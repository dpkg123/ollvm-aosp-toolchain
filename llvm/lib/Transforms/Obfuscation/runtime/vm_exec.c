// vm_exec.c — the missing runtime half of the IR virtualizer.
//
//   uint64_t vm_exec(const uint8_t *code, uint32_t size,
//                    void **args, uint64_t num);
//
// Interprets the bytecode emitted by Obfuscation/utils/VMCodeGen.h (FORMAT v2)
// for functions rewritten by FuncRedirector.hpp. The compiler side links a
// WEAK empty stub when no definition exists; providing this file to the link
// (compile it alongside your sources) overrides that stub with a real,
// strong-symbol interpreter.
//
// Design rules that make the whole thing sound (and that v1 of the format
// could not express -- see VMCodeGen.h's FORMAT v2 note):
//   * every slot is an 8-byte-aligned, 8-byte-multiple word;
//   * every write to a slot stores a ZERO-EXTENDED 64-bit value (narrow
//     results are computed at their width, then zero-extended);
//   * OP_LOAD/OP_STORE carry an explicit access width;
//   * OP_CAST carries src/dst bit widths; OP_CMP carries the operand width;
//     OP_GEP carries sizeof(source element);
//   * floating point values live in slots as IEEE bit patterns (f32 patterns
//     zero-extended to 64 bits).
//
// The interpreter keeps no global state: one invocation = one data frame +
// one alloca arena, so recursion and threads are safe by construction.
// handle_call(id, args, num) is the generated dispatch (HandleCallTool.h):
// args[i] points at the i-th dynamic argument's slot, exactly like here.
//
// This file is deliberately dependency-free C99 (no LLVM headers) so it can
// be compiled into any target directly: clang -c vm_exec.c && clang app.c vm_exec.o

#include "vm_exec.h"
#include "vm_crypt.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// ---------------------------------------------------------------------------
// bytecode opcodes / encodings — canonical values live in vm_crypt.h (single
// source shared with VMCodeGen.h). With per-build opcode permutation the wire
// bytes differ; every fetch goes through the frame's decode LUT f.dec, so the
// switch below only ever sees canonical opcodes.
// ---------------------------------------------------------------------------
#define OP_ALLOCA     VM_OP_ALLOCA
#define OP_LOAD       VM_OP_LOAD
#define OP_STORE      VM_OP_STORE
#define OP_GEP        VM_OP_GEP
#define OP_CMP        VM_OP_CMP
#define OP_CAST       VM_OP_CAST
#define OP_BR         VM_OP_BR
#define OP_CALL       VM_OP_CALL
#define OP_RET        VM_OP_RET
#define OP_ARITH      VM_OP_ARITH
#define OP_PARAMMAP   VM_OP_PARAMMAP
#define OP_SELECT     VM_OP_SELECT /* reserved: IR select virtualization */

#define VT_CONST      0
#define VT_SLOT       1
#define CK_INT        0
#define CK_PTR        1
#define CK_F32        2
#define CK_F64        3

/* arithmetic sub-ops */
#define AR_ADD        0
#define AR_SUB        1
#define AR_MUL        2
#define AR_UDIV       3
#define AR_SDIV       4
#define AR_UREM       5
#define AR_SREM       6
#define AR_SHL        7
#define AR_LSHR       8
#define AR_ASHR       9
#define AR_AND        10
#define AR_OR         11
#define AR_XOR        12
#define AR_FADD       13
#define AR_FSUB       14
#define AR_FMUL       15
#define AR_FDIV       16
#define AR_FREM       17

/* LLVM CmpInst predicates (stable ABI of the IR enums) */
#define FCMP_FALSE    0
#define FCMP_OEQ      1
#define FCMP_OGT      2
#define FCMP_OGE      3
#define FCMP_OLT      4
#define FCMP_OLE      5
#define FCMP_ONE      6
#define FCMP_ORD      7
#define FCMP_UNO      8
#define FCMP_UEQ      9
#define FCMP_UGT      10
#define FCMP_UGE      11
#define FCMP_ULT      12
#define FCMP_ULE      13
#define FCMP_UNE      14
#define FCMP_TRUE     15
#define ICMP_EQ       32
#define ICMP_NE       33
#define ICMP_UGT      34
#define ICMP_UGE      35
#define ICMP_ULT      36
#define ICMP_ULE      37
#define ICMP_SGT      38
#define ICMP_SGE      39
#define ICMP_SLT      40
#define ICMP_SLE      41

/* Cast kinds: STABLE CC_ enum shared with VMCodeGen.h (v3). LLVM renumbers
 * its CastOps across versions (FPExt 17 -> 47 in this tree), so the bytecode
 * never carries raw LLVM opcode numbers. */
#define CC_TRUNC      1
#define CC_ZEXT       2
#define CC_SEXT       3
#define CC_FPTOUI     4
#define CC_FPTOSI     5
#define CC_UITOFP     6
#define CC_SITOFP     7
#define CC_FPTRUNC    8
#define CC_FPEXT      9
#define CC_PTRTOINT   10
#define CC_INTTOPTR   11
#define CC_BITCAST    12
#define CAST_TRUNC    CC_TRUNC
#define CAST_ZEXT     CC_ZEXT
#define CAST_SEXT     CC_SEXT
#define CAST_FPTOUI   CC_FPTOUI
#define CAST_FPTOSI   CC_FPTOSI
#define CAST_UITOFP   CC_UITOFP
#define CAST_SITOFP   CC_SITOFP
#define CAST_FPTRUNC  CC_FPTRUNC
#define CAST_FPEXT    CC_FPEXT
#define CAST_PTRTOINT CC_PTRTOINT
#define CAST_INTTOPTR CC_INTTOPTR
#define CAST_BITCAST  CC_BITCAST

extern uint64_t handle_call(uint64_t id, void **args, uint64_t num);

// ---------------------------------------------------------------------------
// frame: slot space + alloca arena
// ---------------------------------------------------------------------------
typedef struct arena_node {
    struct arena_node *next;
    uint32_t size;
} arena_node;

typedef struct {
    const uint8_t *code;
    uint32_t size;
    uint8_t *slots;        // zeroed slot space
    uint32_t slots_bytes;
    arena_node *arena;
    uint64_t steps;
} vm_frame;

#define VM_MAX_DYN_ARGS 256

static int vm_trace_enabled(void) {              // absorbed from VMP.h: VMP_TRACE=1
    static int cached = -1;
    if (cached < 0) cached = getenv("VMP_TRACE") ? 1 : 0;
    return cached;
}
#define VTRACE(...) do { if (vm_trace_enabled()) { \
    fprintf(stderr, "[vm] step=%lu pc=%u ", (unsigned long)f->steps, (unsigned)*pc); \
    fprintf(stderr, __VA_ARGS__); } } while (0)

static void vm_fatal(const vm_frame *f, uint32_t pc, const char *why) {
    fprintf(stderr, "[vm_exec] FATAL at pc=%u step=%lu: %s\n",
            pc, (unsigned long)f->steps, why);
}

// bounds-checked readers ------------------------------------------------------
static int need(vm_frame *f, uint32_t pc, uint32_t n) {
    return (uint64_t)pc + n <= f->size;
}
static uint8_t rd8(vm_frame *f, uint32_t *pc) {
    uint8_t v = f->code[*pc]; *pc += 1; return v;
}
static uint32_t rd32(vm_frame *f, uint32_t *pc) {
    uint32_t v = (uint32_t)f->code[*pc]
               | ((uint32_t)f->code[*pc + 1] << 8)
               | ((uint32_t)f->code[*pc + 2] << 16)
               | ((uint32_t)f->code[*pc + 3] << 24);
    *pc += 4; return v;
}
static uint64_t rd64(vm_frame *f, uint32_t *pc) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; i--) v = (v << 8) | f->code[*pc + i];
    *pc += 8; return v;
}

static int slot_ok(vm_frame *f, uint32_t off, uint32_t width) {
    return (uint64_t)off + width <= f->slots_bytes;
}
static uint64_t slot_read(vm_frame *f, uint32_t off) {
    uint64_t v;
    memcpy(&v, f->slots + off, 8);   // slots are 8-byte words (zero-extended)
    return v;
}
static void slot_write(vm_frame *f, uint32_t off, uint64_t v) {
    memcpy(f->slots + off, &v, 8);   // full-word store keeps zero-extension
}

// read one encoded operand; returns 0 on malformed input -----------------------
static int read_val(vm_frame *f, uint32_t *pc, uint64_t *out) {
    if (!need(f, *pc, 1)) return 0;
    uint8_t tag = rd8(f, pc);
    if (tag == VT_SLOT) {
        if (!need(f, *pc, 4)) return 0;
        uint32_t off = rd32(f, pc);
        if (!slot_ok(f, off, 8)) return 0;
        *out = slot_read(f, off);
        return 1;
    }
    if (tag == VT_CONST) {
        if (!need(f, *pc, 1)) return 0;
        uint8_t ck = rd8(f, pc);
        if (!need(f, *pc, 4)) return 0;
        uint32_t sz = rd32(f, pc);
        if (ck == CK_INT) {
            if (sz != 8 || !need(f, *pc, 8)) return 0;
            *out = rd64(f, pc);
            return 1;
        }
        if (ck == CK_PTR) {          // never emitted today; treated as int bits
            if (sz != 8 || !need(f, *pc, 8)) return 0;
            *out = rd64(f, pc);
            return 1;
        }
        if (ck == CK_F32) {
            if (sz != 4 || !need(f, *pc, 4)) return 0;
            *out = (uint64_t)rd32(f, pc);      // bit pattern, zero-extended
            return 1;
        }
        if (ck == CK_F64) {
            if (sz != 8 || !need(f, *pc, 8)) return 0;
            *out = rd64(f, pc);                // bit pattern
            return 1;
        }
        return 0;
    }
    return 0;
}

// fp helpers (operate on bit patterns) ----------------------------------------
static double bits_f64(uint64_t b) { double d; uint64_t v=b; memcpy(&d,&v,8); return d; }
static uint64_t f64_bits(double d) { uint64_t b; memcpy(&b,&d,8); return b; }
static float  bits_f32(uint64_t b) { float f; uint32_t v=(uint32_t)b; memcpy(&f,&v,4); return f; }
static uint64_t f32_bits(float f)  { uint32_t v; memcpy(&v,&f,4); return (uint64_t)v; }

static uint64_t sext_to_64(uint64_t v, uint32_t bits) {
    if (bits == 0 || bits >= 64) return v;
    uint64_t sign = (v >> (bits - 1)) & 1u;
    return sign ? (v | (~0ull << bits)) : v;
}

// 原生评估器：默认 static；测试构建 -DVM_EXEC_EXPOSE_EVAL 暴露给
// test_vm2.c 作为等价性对照的 oracle。
#if defined(VM_EXEC_EXPOSE_EVAL)
#define VM_EVAL_FN
#else
#define VM_EVAL_FN static
#endif

VM_EVAL_FN int cmp_eval(uint8_t pred, uint64_t a, uint64_t b, uint32_t bits) {
    if (pred < 16) {
        // floating compare: bits == 32 -> f32 pattern, 64 -> f64 pattern
        if (bits == 32) {
            float x = bits_f32(a), y = bits_f32(b);
            switch (pred) {
            case FCMP_FALSE: return 0;
            case FCMP_OEQ:   return x == y;
            case FCMP_OGT:   return x >  y;
            case FCMP_OGE:   return x >= y;
            case FCMP_OLT:   return x <  y;
            case FCMP_OLE:   return x <= y;
            case FCMP_ONE:   return x != y;
            case FCMP_ORD:   return x == x && y == y;
            case FCMP_UNO:   return x != x || y != y;
            case FCMP_UEQ:   return x == y || (x != x && y != y);
            case FCMP_UGT:   return x >  y || (x != x && y != y);
            case FCMP_UGE:   return x >= y || (x != x && y != y);
            case FCMP_ULT:   return x <  y || (x != x && y != y);
            case FCMP_ULE:   return x <= y || (x != x && y != y);
            case FCMP_UNE:   return x != y;
            case FCMP_TRUE:  return 1;
            }
            return 0;
        }
        double x = bits_f64(a), y = bits_f64(b);
        switch (pred) {
        case FCMP_FALSE: return 0;
        case FCMP_OEQ:   return x == y;
        case FCMP_OGT:   return x >  y;
        case FCMP_OGE:   return x >= y;
        case FCMP_OLT:   return x <  y;
        case FCMP_OLE:   return x <= y;
        case FCMP_ONE:   return x != y;
        case FCMP_ORD:   return x == x && y == y;
        case FCMP_UNO:   return x != x || y != y;
        case FCMP_UEQ:   return x == y || (x != x && y != y);
        case FCMP_UGT:   return x >  y || (x != x && y != y);
        case FCMP_UGE:   return x >= y || (x != x && y != y);
        case FCMP_ULT:   return x <  y || (x != x && y != y);
        case FCMP_ULE:   return x <= y || (x != x && y != y);
        case FCMP_UNE:   return x != y;
        case FCMP_TRUE:  return 1;
        }
        return 0;
    }
    // integer compare: values are zero-extended; sign matters only for S-preds
    switch (pred) {
    case ICMP_EQ:  return a == b;
    case ICMP_NE:  return a != b;
    case ICMP_UGT: return a >  b;
    case ICMP_UGE: return a >= b;
    case ICMP_ULT: return a <  b;
    case ICMP_ULE: return a <= b;
    case ICMP_SGT: return (int64_t)sext_to_64(a, bits) >  (int64_t)sext_to_64(b, bits);
    case ICMP_SGE: return (int64_t)sext_to_64(a, bits) >= (int64_t)sext_to_64(b, bits);
    case ICMP_SLT: return (int64_t)sext_to_64(a, bits) <  (int64_t)sext_to_64(b, bits);
    case ICMP_SLE: return (int64_t)sext_to_64(a, bits) <= (int64_t)sext_to_64(b, bits);
    }
    return 0;
}

VM_EVAL_FN uint64_t arith_eval(uint8_t sub, uint8_t tk, uint8_t bits,
                           uint64_t a, uint64_t b) {
    if (tk == 1) { // floating
        if (bits == 32) {
            float x = bits_f32(a), y = bits_f32(b), r = 0;
            switch (sub) {
            case AR_FADD: r = x + y; break;
            case AR_FSUB: r = x - y; break;
            case AR_FMUL: r = x * y; break;
            case AR_FDIV: r = x / y; break;
            case AR_FREM: r = (float)fmodf(x, y); break;
            default: r = 0; break;
            }
            return f32_bits(r);
        }
        double x = bits_f64(a), y = bits_f64(b), r = 0;
        switch (sub) {
        case AR_FADD: r = x + y; break;
        case AR_FSUB: r = x - y; break;
        case AR_FMUL: r = x * y; break;
        case AR_FDIV: r = x / y; break;
        case AR_FREM: r = fmod(x, y); break;
        default: r = 0; break;
        }
        return f64_bits(r);
    }
    // integer: compute at the declared width, zero-extend back
    uint64_t mask = (bits >= 64) ? ~0ull : ((1ull << bits) - 1ull);
    uint64_t sa = a & mask, sb = b & mask;
    uint64_t r = 0;
    switch (sub) {
    case AR_ADD:  r = sa + sb; break;
    case AR_SUB:  r = sa - sb; break;
    case AR_MUL:  r = sa * sb; break;
    case AR_UDIV: r = sb ? sa / sb : 0; break;
    case AR_SDIV: {
        if (!sb) { r = 0; break; }
        int64_t x = (int64_t)sext_to_64(sa, bits);
        int64_t y = (int64_t)sext_to_64(sb, bits);
        if (x == INT64_MIN && y == -1) { r = (uint64_t)x; break; } // overflow
        r = (uint64_t)(x / y);
        break;
    }
    case AR_UREM: r = sb ? sa % sb : 0; break;
    case AR_SREM: {
        if (!sb) { r = 0; break; }
        int64_t x = (int64_t)sext_to_64(sa, bits);
        int64_t y = (int64_t)sext_to_64(sb, bits);
        if (x == INT64_MIN && y == -1) { r = 0; break; }
        r = (uint64_t)(x % y);
        break;
    }
    case AR_SHL:  r = (sa << (sb & 63)); break;
    case AR_LSHR: r = (bits >= 64) ? (sa >> (sb & 63)) : ((sa & mask) >> (sb % 64)); break;
    case AR_ASHR: {
        int64_t x = (int64_t)sext_to_64(sa, bits);
        r = (uint64_t)(x >> (sb & 63));
        break;
    }
    case AR_AND:  r = sa & sb; break;
    case AR_OR:   r = sa | sb; break;
    case AR_XOR:  r = sa ^ sb; break;
    default: r = 0; break;
    }
    return r & mask;   // zero-extended by construction (mask, not sign-extend)
}

VM_EVAL_FN uint64_t cast_eval(uint8_t op, uint8_t sbits, uint8_t dbits, uint64_t v) {
    switch (op) {
    case CAST_TRUNC: {
        uint64_t mask = (dbits >= 64) ? ~0ull : ((1ull << dbits) - 1ull);
        return v & mask;
    }
    case CAST_ZEXT:  return v;                        // already zero-extended
    case CAST_SEXT:  return sext_to_64(v, sbits);
    case CAST_FPTOUI: {
        if (sbits == 32) return (uint64_t)bits_f32(v);
        return (uint64_t)bits_f64(v);
    }
    case CAST_FPTOSI: {
        if (sbits == 32) return (uint64_t)(int64_t)bits_f32(v);
        return (uint64_t)(int64_t)bits_f64(v);
    }
    case CAST_UITOFP: {
        if (dbits == 32) return f32_bits((float)(uint64_t)v);
        return f64_bits((double)(uint64_t)v);
    }
    case CAST_SITOFP: {
        if (dbits == 32) return f32_bits((float)(int64_t)v);
        return f64_bits((double)(int64_t)v);
    }
    case CAST_FPTRUNC: return f32_bits(bits_f64(v));  // f64 bits -> f32 bits
    case CAST_FPEXT:   return f64_bits((double)bits_f32(v));
    case CAST_PTRTOINT:
    case CAST_INTTOPTR:
    case CAST_BITCAST:
    default:
        return v;                                     // pointer-width identity
    }
}

// ---------------------------------------------------------------------------
// 嵌套 VM（展望③）钩子：链接 vm2_exec.c 时，强符号接管——L1 的算术/比较/
// 类型转换核心由二级 VM 解释执行；未链接时弱回退到上面的原生评估器，
// 单文件运行时保持可用。语义由 test_vm2.c 穷举等价验证。
// ---------------------------------------------------------------------------
#if defined(__GNUC__)
#define VM2_HOOK __attribute__((weak))
#else
#define VM2_HOOK
#endif

VM2_HOOK uint64_t vm2_arith(uint8_t sub, uint8_t tk, uint8_t bits,
                            uint64_t a, uint64_t b) {
    return arith_eval(sub, tk, bits, a, b);
}
VM2_HOOK int vm2_cmp(uint8_t pred, uint64_t a, uint64_t b, uint8_t obits) {
    return cmp_eval(pred, a, b, obits);
}
VM2_HOOK uint64_t vm2_cast(uint8_t cop, uint8_t sbits, uint8_t dbits, uint64_t v) {
    return cast_eval(cop, sbits, dbits, v);
}

// ---------------------------------------------------------------------------
// opcode handlers (动态分发，展望②)
//
// 每个 opcode 的执行体是一个独立函数；取指后不再走静态 switch，而是查一次
// 调用内动态构建的分发表 lut[wire] -> 槽位 -> htab[槽位] 的函数指针：
//
//   * 构建期置换（-irobf-irvm-dispatch）：发射侧把规范操作码重编码为随机的
//     wire 字节；
//   * 运行期乱序：每次 vm_run 调用都用栈地址/计数器混合的熵对 handler 槽
//     位重新洗牌。
//
// 两层叠加后，op -> 处理函数的映射既随构建变化，也随调用变化，静态分析
// 无法用固定的 opcode-模式匹配到分发结构。
// ---------------------------------------------------------------------------
typedef enum {
    VH_OK = 0,   // 继续执行
    VH_BAD,      // 指令畸形：记日志并以 0 退出
    VH_DONE,     // 正常返回（*retval 已填）
    VH_STOP      // 致命错误已记日志，保留 retval 退出
} vh_r;

typedef vh_r (*vm_handler)(vm_frame *f, uint32_t *pc, uint64_t *retval,
                           void **args, uint64_t num);

static vh_r h_parammap(vm_frame *f, uint32_t *pc, uint64_t *retval,
                        void **args, uint64_t num) {
    (void)retval;
    if (!need(f, *pc, 4)) return VH_BAD;
    uint32_t n = rd32(f, pc);
    for (uint32_t i = 0; i < n; i++) {
        if (!need(f, *pc, 8)) return VH_BAD;
        uint32_t off = rd32(f, pc);
        uint32_t sz  = rd32(f, pc);
        if (i < num && args[i] && slot_ok(f, off, sz))
            memcpy(f->slots + off, args[i], sz);   // rest stays zeroed
    }
    return VH_OK;
}

static vh_r h_alloca(vm_frame *f, uint32_t *pc, uint64_t *retval,
                     void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 8)) return VH_BAD;
    uint32_t res = rd32(f, pc);
    uint32_t area = rd32(f, pc);
    if (!slot_ok(f, res, 8)) return VH_BAD;
    arena_node *node = (arena_node *)malloc(sizeof(arena_node) + area);
    if (!node) return VH_BAD;
    node->next = f->arena;
    node->size = area;
    f->arena = node;
    memset((char *)(node + 1), 0, area);
    slot_write(f, res, (uint64_t)(uintptr_t)(node + 1));
    return VH_OK;
}

static vh_r h_load(vm_frame *f, uint32_t *pc, uint64_t *retval,
                   void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 4)) return VH_BAD;
    uint32_t dst = rd32(f, pc);
    uint64_t ptr;
    if (!read_val(f, pc, &ptr)) return VH_BAD;
    if (!need(f, *pc, 1)) return VH_BAD;
    uint8_t w = rd8(f, pc);
    if (!slot_ok(f, dst, 8) || w == 0 || w > 8) return VH_BAD;
    uint64_t v = 0;
    memcpy(&v, (const void *)(uintptr_t)ptr, w);   // zero-extends
    slot_write(f, dst, v);
    return VH_OK;
}

static vh_r h_store(vm_frame *f, uint32_t *pc, uint64_t *retval,
                    void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    uint64_t v, ptr;
    if (!read_val(f, pc, &v)) return VH_BAD;
    if (!read_val(f, pc, &ptr)) return VH_BAD;
    if (!need(f, *pc, 1)) return VH_BAD;
    uint8_t w = rd8(f, pc);
    if (w == 0 || w > 8) return VH_BAD;
    memcpy((void *)(uintptr_t)ptr, &v, w);
    return VH_OK;
}

static vh_r h_gep(vm_frame *f, uint32_t *pc, uint64_t *retval,
                  void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 4)) return VH_BAD;
    uint32_t dst = rd32(f, pc);
    uint64_t base;
    if (!read_val(f, pc, &base)) return VH_BAD;
    if (!need(f, *pc, 4)) return VH_BAD;
    uint32_t n = rd32(f, pc);
    uint64_t addr = base;
    for (uint32_t i = 0; i < n; i++) {
        uint64_t idx;
        if (!read_val(f, pc, &idx)) return VH_BAD;
        if (!need(f, *pc, 4)) return VH_BAD;
        uint32_t scale = rd32(f, pc);     // byte scale per index (v3)
        // GEP indices are signed; slot values are zero-extended, so a
        // negative index arrives as its two's-complement 64-bit value.
        addr = (uint64_t)((int64_t)addr + (int64_t)idx * (int64_t)scale);
    }
    if (!slot_ok(f, dst, 8)) return VH_BAD;
    slot_write(f, dst, addr);
    return VH_OK;
}

static vh_r h_cmp(vm_frame *f, uint32_t *pc, uint64_t *retval,
                  void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 2)) return VH_BAD;
    uint8_t pred = rd8(f, pc);
    uint8_t obits = rd8(f, pc);
    if (!need(f, *pc, 4)) return VH_BAD;
    uint32_t dst = rd32(f, pc);
    uint64_t a, b;
    if (!read_val(f, pc, &a)) return VH_BAD;
    if (!read_val(f, pc, &b)) return VH_BAD;
    if (!slot_ok(f, dst, 8)) return VH_BAD;
    { uint64_t cr = vm2_cmp(pred, a, b, obits) ? 1ull : 0ull;
      VTRACE("CMP pred=%u bits=%u a=%llx b=%llx -> %llu\n",
             pred, obits, (unsigned long long)a, (unsigned long long)b,
             (unsigned long long)cr);
      slot_write(f, dst, cr); }
    return VH_OK;
}

static vh_r h_cast(vm_frame *f, uint32_t *pc, uint64_t *retval,
                   void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 3)) return VH_BAD;
    uint8_t cop = rd8(f, pc);
    uint8_t sbits = rd8(f, pc);
    uint8_t dbits = rd8(f, pc);
    if (!need(f, *pc, 4)) return VH_BAD;
    uint32_t dst = rd32(f, pc);
    uint64_t v;
    if (!read_val(f, pc, &v)) return VH_BAD;
    if (!slot_ok(f, dst, 8)) return VH_BAD;
    { uint64_t cv = vm2_cast(cop, sbits, dbits, v);
      VTRACE("CAST op=%u sb=%u db=%u v=%llx -> %llx\n",
             cop, sbits, dbits, (unsigned long long)v, (unsigned long long)cv);
      slot_write(f, dst, cv); }
    return VH_OK;
}

static vh_r h_br(vm_frame *f, uint32_t *pc, uint64_t *retval,
                 void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 1)) return VH_BAD;
    uint8_t kind = rd8(f, pc);
    if (kind == 0) {
        if (!need(f, *pc, 4)) return VH_BAD;
        *pc = rd32(f, pc);
    } else {
        uint64_t cond;
        if (!read_val(f, pc, &cond)) return VH_BAD;
        if (!need(f, *pc, 8)) return VH_BAD;
        uint32_t t = rd32(f, pc);
        uint32_t fl = rd32(f, pc);
        *pc = cond ? t : fl;
    }
    if (*pc >= f->size) {
        vm_fatal(f, *pc, "branch target out of range");
        return VH_STOP;
    }
    return VH_OK;
}

static vh_r h_call(vm_frame *f, uint32_t *pc, uint64_t *retval,
                   void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 8)) return VH_BAD;
    uint64_t id = rd64(f, pc);
    if (!need(f, *pc, 8)) return VH_BAD;
    uint32_t dst = rd32(f, pc);
    uint32_t dynN = rd32(f, pc);
    if (dynN > VM_MAX_DYN_ARGS) return VH_BAD;
    void *cargs[VM_MAX_DYN_ARGS];
    for (uint32_t i = 0; i < dynN; i++) {
        if (!need(f, *pc, 4)) return VH_BAD;
        uint32_t off = rd32(f, pc);
        if (!slot_ok(f, off, 8)) return VH_BAD;
        cargs[i] = f->slots + off;
    }
    uint64_t ret = handle_call(id, cargs, dynN);
    if (dst != 0xFFFFFFFFu && slot_ok(f, dst, 8))
        slot_write(f, dst, ret);
    return VH_OK;
}

static vh_r h_ret(vm_frame *f, uint32_t *pc, uint64_t *retval,
                  void **args, uint64_t num) {
    (void)args; (void)num;
    uint64_t v;
    if (!read_val(f, pc, &v)) return VH_BAD;
    VTRACE("RET %llx\n", (unsigned long long)v);
    *retval = v;
    return VH_DONE;
}

static vh_r h_arith(vm_frame *f, uint32_t *pc, uint64_t *retval,
                    void **args, uint64_t num) {
    (void)retval; (void)args; (void)num;
    if (!need(f, *pc, 3)) return VH_BAD;
    uint8_t sub = rd8(f, pc);
    uint8_t tk = rd8(f, pc);
    uint8_t bits = rd8(f, pc);
    if (!need(f, *pc, 4)) return VH_BAD;
    uint32_t dst = rd32(f, pc);
    uint64_t a, b;
    if (!read_val(f, pc, &a)) return VH_BAD;
    if (!read_val(f, pc, &b)) return VH_BAD;
    if (!slot_ok(f, dst, 8)) return VH_BAD;
    { uint64_t ar = vm2_arith(sub, tk, bits, a, b);
      VTRACE("ARITH sub=%u tk=%u bits=%u a=%llx b=%llx -> %llx\n",
             sub, tk, bits, (unsigned long long)a, (unsigned long long)b,
             (unsigned long long)ar);
      slot_write(f, dst, ar); }
    return VH_OK;
}

/* 预留槽位：SELECT（阶段五实现），当前命中即拒 */
static vh_r h_select_stub(vm_frame *f, uint32_t *pc, uint64_t *retval,
                          void **args, uint64_t num) {
    (void)pc; (void)retval; (void)args; (void)num;
    vm_fatal(f, 0, "opcode reserved (select)");
    return VH_STOP;
}

/* 规范序 handler 表（与 VM_OP_CANON 同序）：
   ALLOCA LOAD STORE GEP CMP CAST BR CALL RET ARITH PARAMMAP SELECT */
static const vm_handler VM_CanonHandlers[VM_OP_N] = {
    h_alloca, h_load, h_store, h_gep, h_cmp, h_cast,
    h_br, h_call, h_ret, h_arith, h_parammap, h_select_stub
};

/* 每次调用重建分发表：
   lut[wire字节] = 槽位；  htab[槽位] = handler 函数指针。
   槽位序 π_run 来自栈地址与调用计数的混合熵（Fisher–Yates 洗牌），
   wire 字节序来自构建期置换 perm。 */
static volatile uint64_t g_vm_calls = 0;   /* 仅作熵源，竞争无害 */

static void build_dispatch(const uint8_t perm[VM_OP_N],
                           vm_handler htab[VM_OP_N], uint8_t lut[256]) {
    const uint8_t *p = perm ? perm : VM_OP_CANON;
    uint8_t slot[VM_OP_N];
    uint64_t st;
    int i, j;

    for (i = 0; i < VM_OP_N; i++) slot[i] = (uint8_t)i;

    st = (uint64_t)(uintptr_t)&htab[0] ^ (uint64_t)(uintptr_t)&lut[0] ^
         (uint64_t)(uintptr_t)&st ^ ++g_vm_calls ^ 0x9E3779B97F4A7C15ull;
    for (i = VM_OP_N - 1; i > 0; i--) {         // 运行期槽位洗牌 π_run
        uint64_t r = vm_sm64_next(&st);
        j = (int)(r % (uint64_t)(i + 1));
        uint8_t t = slot[i]; slot[i] = slot[j]; slot[j] = t;
    }

    for (i = 0; i < VM_OP_N; i++)               // 规范 handler -> 洗牌后槽位
        htab[slot[i]] = VM_CanonHandlers[i];

    memset(lut, 0xFF, 256);                     // 0xFF = 非法
    for (i = 0; i < VM_OP_N; i++)               // wire 字节 -> 槽位
        lut[p[i]] = slot[i];
}

// ---------------------------------------------------------------------------
// interpreter core: runs FORMAT v2 bytecode in [code, code+size) against a
// freshly allocated frame. perm is the build-time opcode permutation the
// blob was encoded with (identity for legacy blobs); dispatch goes through
// the per-invocation table built by build_dispatch().
// ---------------------------------------------------------------------------
static uint64_t vm_run(const uint8_t *code, uint32_t size,
                        const uint8_t perm[VM_OP_N],
                        void **args, uint64_t num) {
    if (!code || size == 0) return 0;

    vm_frame f;
    f.code = code;
    f.size = size;
    f.arena = NULL;
    f.steps = 0;

    // 动态分发表（每次调用重建：构建期置换 + 运行期槽位洗牌）
    vm_handler htab[VM_OP_N];
    uint8_t lut[256];
    build_dispatch(perm, htab, lut);

    // Conservative slot-space bound: every slot is one 8-byte word and slots
    // are never more numerous than bytecode bytes; PARAMMAP aggregates may
    // reserve more than 8 bytes per slot, so pad generously. (A two-pass
    // exact scan is a drop-in optimization if this ever matters.)
    f.slots_bytes = (uint32_t)(((uint64_t)size * 24) + 4096);
    f.slots = (uint8_t *)calloc(f.slots_bytes, 1);
    if (!f.slots) return 0;

    uint64_t retval = 0;
    uint32_t pc = 0;

    for (;;) {
        if (++f.steps > 100000000ull) {              // runaway-loop guard
            vm_fatal(&f, pc, "step budget exhausted");
            retval = 0;
            break;
        }
        if (!need(&f, pc, 1)) {
            vm_fatal(&f, pc, "pc out of range");
            break;
        }
        uint8_t wire = rd8(&f, &pc);             // wire 字节（可能已置换）
        uint8_t slot = lut[wire];                // 动态表：wire -> 槽位
        if (slot >= VM_OP_N) {
            vm_fatal(&f, pc - 1, "unknown opcode");
            break;
        }
        vh_r r = htab[slot](&f, &pc, &retval, args, num);
        if (r == VH_BAD) {
            vm_fatal(&f, pc, "malformed instruction");
            retval = 0;
            break;
        }
        if (r != VH_OK) break;                   // VH_DONE / VH_STOP
    }

    while (f.arena) {
        arena_node *n = f.arena->next;
        free(f.arena);
        f.arena = n;
    }
    free(f.slots);
    return retval;
}

// ---------------------------------------------------------------------------
// public entries
// ---------------------------------------------------------------------------
/* vm_exec_sealed — the hardening-aware entry the IRVM stubs call when the
 * module was built with -mllvm -irobf-irvm-enc / -irobf-irvm-dispatch.
 *
 *   code : sealed blob  = [8-byte IRVS header][payload]
 *          (or a legacy plaintext blob — detected via the header magic)
 *   key16: 16-byte keystream key global (required for encrypted payloads;
 *          ignored otherwise)
 *   perm : VM_OP_N-byte opcode permutation global (NULL = canonical)
 *
 * "Code 加密" semantics implemented here:
 *   * .rodata keeps the ciphertext forever (const pages are never written);
 *   * each invocation mallocs a private working copy, decrypts it, interprets
 *     from it, then RE-ENCRYPTS the copy before free — so the heap never
 *     retains plaintext bytecode beyond an active call, and freed-memory /
 *     post-mortem dumps see ciphertext.
 */
uint64_t vm_exec_sealed(const uint8_t *code, uint32_t size,
                         const uint8_t *key16, const uint8_t *perm,
                         void **args, uint64_t num) {
    if (!code || size == 0) return 0;

    unsigned flags = 0;
    size_t payload_off = 0;
    int sealed = vm_seal_parse(code, (size_t)size, &flags, &payload_off);

    const uint8_t *wcode = code;
    uint32_t wsize = size;
    uint8_t *work = NULL;

    if (sealed) {
        wcode = code + payload_off;
        wsize = size - (uint32_t)payload_off;
        if (flags & VM_SEAL_F_ENCRYPTED) {
            if (!key16) {
                fprintf(stderr,
                        "[vm_exec] FATAL: encrypted blob without a key\n");
                return 0;
            }
            work = (uint8_t *)malloc(wsize ? wsize : 1);
            if (!work) return 0;
            memcpy(work, wcode, wsize);
            vm_keystream(work, wsize, key16);        // decrypt working copy
            wcode = work;
        }
        if ((flags & VM_SEAL_F_PERMUTED) && !perm) {
            fprintf(stderr,
                    "[vm_exec] FATAL: permuted blob without a perm table\n");
            free(work);
            return 0;
        }
    }

    uint64_t r = vm_run(wcode, wsize,
                        (sealed && (flags & VM_SEAL_F_PERMUTED)) ? perm : NULL,
                        args, num);

    if (work) {
        vm_keystream(work, wsize, key16);            // re-encrypt before free
        free(work);
    }
    return r;
}

/* legacy entry — behaves exactly as before for unsealed blobs; sealed blobs
 * are detected via their header (perm/key default to canonical/none). */
uint64_t vm_exec(const uint8_t *code, uint32_t size, void **args, uint64_t num) {
    return vm_exec_sealed(code, size, NULL, NULL, args, num);
}
