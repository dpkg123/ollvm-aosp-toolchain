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

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <math.h>

// ---------------------------------------------------------------------------
// bytecode opcodes / encodings (must match VMCodeGen.h exactly)
// ---------------------------------------------------------------------------
#define OP_ALLOCA     0x01
#define OP_LOAD       0x02
#define OP_STORE      0x03
#define OP_GEP        0x05
#define OP_CMP        0x06
#define OP_CAST       0x07
#define OP_BR         0x08
#define OP_CALL       0x09
#define OP_RET        0x0A
#define OP_ARITH      0x10
#define OP_PARAMMAP   0x11

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
    fprintf(stderr, "[vm] step=%lu pc=%u ", (unsigned long)f.steps, pc); \
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

static int cmp_eval(uint8_t pred, uint64_t a, uint64_t b, uint32_t bits) {
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

static uint64_t arith_eval(uint8_t sub, uint8_t tk, uint8_t bits,
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

static uint64_t cast_eval(uint8_t op, uint8_t sbits, uint8_t dbits, uint64_t v) {
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
// entry
// ---------------------------------------------------------------------------
uint64_t vm_exec(const uint8_t *code, uint32_t size, void **args, uint64_t num) {
    if (!code || size == 0) return 0;

    vm_frame f;
    f.code = code;
    f.size = size;
    f.arena = NULL;
    f.steps = 0;

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
        uint8_t op = rd8(&f, &pc);

        switch (op) {
        case OP_PARAMMAP: {
            if (!need(&f, pc, 4)) goto bad;
            uint32_t n = rd32(&f, &pc);
            for (uint32_t i = 0; i < n; i++) {
                if (!need(&f, pc, 8)) goto bad;
                uint32_t off = rd32(&f, &pc);
                uint32_t sz  = rd32(&f, &pc);
                if (i < num && args[i] && slot_ok(&f, off, sz)) {
                    memcpy(f.slots + off, args[i], sz);   // rest stays zeroed
                }
            }
            break;
        }
        case OP_ALLOCA: {
            if (!need(&f, pc, 8)) goto bad;
            uint32_t res = rd32(&f, &pc);
            uint32_t area = rd32(&f, &pc);
            if (!slot_ok(&f, res, 8)) goto bad;
            arena_node *node = (arena_node *)malloc(sizeof(arena_node) + area);
            if (!node) goto bad;
            node->next = f.arena;
            node->size = area;
            f.arena = node;
            memset((char *)(node + 1), 0, area);
            slot_write(&f, res, (uint64_t)(uintptr_t)(node + 1));
            break;
        }
        case OP_LOAD: {
            if (!need(&f, pc, 4)) goto bad;
            uint32_t dst = rd32(&f, &pc);
            uint64_t ptr;
            if (!read_val(&f, &pc, &ptr)) goto bad;
            if (!need(&f, pc, 1)) goto bad;
            uint8_t w = rd8(&f, &pc);
            if (!slot_ok(&f, dst, 8) || w == 0 || w > 8) goto bad;
            uint64_t v = 0;
            memcpy(&v, (const void *)(uintptr_t)ptr, w);   // zero-extends
            slot_write(&f, dst, v);
            break;
        }
        case OP_STORE: {
            uint64_t v, ptr;
            if (!read_val(&f, &pc, &v)) goto bad;
            if (!read_val(&f, &pc, &ptr)) goto bad;
            if (!need(&f, pc, 1)) goto bad;
            uint8_t w = rd8(&f, &pc);
            if (w == 0 || w > 8) goto bad;
            memcpy((void *)(uintptr_t)ptr, &v, w);
            break;
        }
        case OP_GEP: {
            if (!need(&f, pc, 4)) goto bad;
            uint32_t dst = rd32(&f, &pc);
            uint64_t base;
            if (!read_val(&f, &pc, &base)) goto bad;
            if (!need(&f, pc, 4)) goto bad;
            uint32_t n = rd32(&f, &pc);
            uint64_t addr = base;
            for (uint32_t i = 0; i < n; i++) {
                uint64_t idx;
                if (!read_val(&f, &pc, &idx)) goto bad;
                if (!need(&f, pc, 4)) goto bad;
                uint32_t scale = rd32(&f, &pc);     // byte scale per index (v3)
                // GEP indices are signed; slot values are zero-extended, so a
                // negative index arrives as its two's-complement 64-bit value.
                addr = (uint64_t)((int64_t)addr + (int64_t)idx * (int64_t)scale);
            }
            if (!slot_ok(&f, dst, 8)) goto bad;
            slot_write(&f, dst, addr);
            break;
        }
        case OP_CMP: {
            if (!need(&f, pc, 2)) goto bad;
            uint8_t pred = rd8(&f, &pc);
            uint8_t obits = rd8(&f, &pc);
            if (!need(&f, pc, 4)) goto bad;
            uint32_t dst = rd32(&f, &pc);
            uint64_t a, b;
            if (!read_val(&f, &pc, &a)) goto bad;
            if (!read_val(&f, &pc, &b)) goto bad;
            if (!slot_ok(&f, dst, 8)) goto bad;
            { uint64_t cr = cmp_eval(pred, a, b, obits) ? 1ull : 0ull;
              VTRACE("CMP pred=%u bits=%u a=%llx b=%llx -> %llu\n",
                     pred, obits, (unsigned long long)a, (unsigned long long)b,
                     (unsigned long long)cr);
              slot_write(&f, dst, cr); }
            break;
        }
        case OP_CAST: {
            if (!need(&f, pc, 3)) goto bad;
            uint8_t cop = rd8(&f, &pc);
            uint8_t sbits = rd8(&f, &pc);
            uint8_t dbits = rd8(&f, &pc);
            if (!need(&f, pc, 4)) goto bad;
            uint32_t dst = rd32(&f, &pc);
            uint64_t v;
            if (!read_val(&f, &pc, &v)) goto bad;
            if (!slot_ok(&f, dst, 8)) goto bad;
            { uint64_t cv = cast_eval(cop, sbits, dbits, v);
              VTRACE("CAST op=%u sb=%u db=%u v=%llx -> %llx\n",
                     cop, sbits, dbits, (unsigned long long)v, (unsigned long long)cv);
              slot_write(&f, dst, cv); }
            break;
        }
        case OP_BR: {
            if (!need(&f, pc, 1)) goto bad;
            uint8_t kind = rd8(&f, &pc);
            if (kind == 0) {
                if (!need(&f, pc, 4)) goto bad;
                pc = rd32(&f, &pc);
            } else {
                uint64_t cond;
                if (!read_val(&f, &pc, &cond)) goto bad;
                if (!need(&f, pc, 8)) goto bad;
                uint32_t t = rd32(&f, &pc);
                uint32_t fl = rd32(&f, &pc);
                pc = cond ? t : fl;
            }
            if (pc >= f.size) { vm_fatal(&f, pc, "branch target out of range"); goto done; }
            break;
        }
        case OP_CALL: {
            if (!need(&f, pc, 8)) goto bad;
            uint64_t id = rd64(&f, &pc);
            if (!need(&f, pc, 8)) goto bad;
            uint32_t dst = rd32(&f, &pc);
            uint32_t dynN = rd32(&f, &pc);
            if (dynN > VM_MAX_DYN_ARGS) goto bad;
            void *cargs[VM_MAX_DYN_ARGS];
            for (uint32_t i = 0; i < dynN; i++) {
                if (!need(&f, pc, 4)) goto bad;
                uint32_t off = rd32(&f, &pc);
                if (!slot_ok(&f, off, 8)) goto bad;
                cargs[i] = f.slots + off;
            }
            uint64_t ret = handle_call(id, cargs, dynN);
            if (dst != 0xFFFFFFFFu && slot_ok(&f, dst, 8))
                slot_write(&f, dst, ret);
            break;
        }
        case OP_RET: {
            uint64_t v;
            if (!read_val(&f, &pc, &v)) goto bad;
            VTRACE("RET %llx\n", (unsigned long long)v);
            retval = v;
            goto done;
        }
        case OP_ARITH: {
            if (!need(&f, pc, 3)) goto bad;
            uint8_t sub = rd8(&f, &pc);
            uint8_t tk = rd8(&f, &pc);
            uint8_t bits = rd8(&f, &pc);
            if (!need(&f, pc, 4)) goto bad;
            uint32_t dst = rd32(&f, &pc);
            uint64_t a, b;
            if (!read_val(&f, &pc, &a)) goto bad;
            if (!read_val(&f, &pc, &b)) goto bad;
            if (!slot_ok(&f, dst, 8)) goto bad;
            { uint64_t ar = arith_eval(sub, tk, bits, a, b);
              VTRACE("ARITH sub=%u tk=%u bits=%u a=%llx b=%llx -> %llx\n",
                     sub, tk, bits, (unsigned long long)a, (unsigned long long)b,
                     (unsigned long long)ar);
              slot_write(&f, dst, ar); }
            break;
        }
        default:
            vm_fatal(&f, pc - 1, "unknown opcode");
            goto done;
        }
        continue;
    bad:
        vm_fatal(&f, pc, "malformed instruction");
        retval = 0;
        break;
    }
done:
    while (f.arena) {
        arena_node *n = f.arena->next;
        free(f.arena);
        f.arena = n;
    }
    free(f.slots);
    return retval;
}
