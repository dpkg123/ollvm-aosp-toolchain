// test_vm_exec.c — host unit tests for the vm_exec interpreter, against
// hand-packed FORMAT v2 bytecode. Each case builds the bytecode with the same
// packing helpers VMCodeGen.h uses (p8/p32/p64, little-endian), runs vm_exec,
// and asserts the result. This is the interpreter's ground truth: it must
// pass on the host before the compiler side ever emits a byte.
#define VMP_NO_WEAK_HANDLE_CALL   /* this test defines its own bridge */
#include "VMP.h"                  /* header-only runtime: nothing else to link */
#include <assert.h>

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

static uint8_t buf[4096];
static uint32_t len;
static void reset(void) { len = 0; }
static void p8_(uint8_t v)  { buf[len++] = v; }
static void p32_(uint32_t v){ for (int i=0;i<4;i++) buf[len++]=(uint8_t)(v>>(i*8)); }
static void p64_(uint64_t v){ for (int i=0;i<8;i++) buf[len++]=(uint8_t)(v>>(i*8)); }
static void vconst_i(uint64_t v){ p8_(0); p8_(0); p32_(8); p64_(v); }       // VT_CONST CK_INT
static void vconst_f32(float f){ uint32_t b; memcpy(&b,&f,4); p8_(0); p8_(2); p32_(4); p32_(b); }
static void vconst_f64(double d){ uint64_t b; memcpy(&b,&d,8); p8_(0); p8_(3); p32_(8); p64_(b); }
static void vslot(uint32_t off){ p8_(1); p32_(off); }                       // VT_SLOT
static void op_arith(uint8_t sub,uint8_t tk,uint8_t bits,uint32_t dst,uint64_t a,int aconst,uint32_t aslot,uint64_t b,int bconst,uint32_t bslot){
    p8_(0x10); p8_(sub); p8_(tk); p8_(bits); p32_(dst);
    if(aconst) vconst_i(a); else vslot(aslot);
    if(bconst) vconst_i(b); else vslot(bslot);
}

static int tests_run = 0;
#define CHECK(cond, name) do { tests_run++; \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", name); exit(1); } } while (0)

static uint64_t run(void **args, uint64_t n) {
    return vm_exec(buf, len, args, n);
}

// a toy handle_call: id=7 -> returns args[0] + args[1]; id=9 -> returns 0x1234
uint64_t handle_call(uint64_t id, void **args, uint64_t num) {
    if (id == 7) {
        uint64_t a, b; memcpy(&a, args[0], 8); memcpy(&b, args[1], 8);
        return a + b;
    }
    if (id == 9) return 0x1234;
    (void)num;
    return 0;
}

/* sealed-blob helpers (file scope: clang rejects GNU nested functions) */
static uint8_t sbuf[4096 + VM_SEAL_HDR_SIZE];
static const uint8_t KEY[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static uint8_t BADKEY[16];
static uint8_t PERM[VM_OP_N];

static uint32_t seal(unsigned flags, const uint8_t *key) {
    vm_seal_write_header(sbuf, flags);
    memcpy(sbuf + VM_SEAL_HDR_SIZE, buf, len);
    if (flags & VM_SEAL_F_ENCRYPTED)
        vm_keystream(sbuf + VM_SEAL_HDR_SIZE, len, key);
    return VM_SEAL_HDR_SIZE + len;
}
static uint8_t op_(uint8_t canon) { uint8_t w = vm_op_encode(canon, PERM); p8_(w); return w; }

int main(void) {
    // 1. PARAMMAP + ARITH add on param slots + RET
    {
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);            // PARAMMAP: args[0] -> slot0(8B)
        op_arith(0 /*ADD*/, 0 /*INT*/, 32, 8, 0,0,0, 0,0,0); // slot8 = slot0 + slot0
        p8_(0x0A); vslot(8);                             // RET slot8
        uint64_t arg = 21; void *args[1] = { &arg };
        uint64_t r = run(args, 1);
        CHECK(r == 42, "parammap+add32");
    }
    // 2. signed arithmetic: SREM(-7, 3) @16 bits == -1 (zero-extended 0xFFFF)
    {
        reset();
        op_arith(6 /*SREM*/, 0, 16, 0, (uint64_t)(uint16_t)(int16_t)-7,1,0, 3,1,0);
        p8_(0x0A); vslot(0);
        uint64_t r = run(NULL, 0);
        CHECK(r == 0xFFFF, "srem16 sign");
    }
    // 3. ASHR at 8 bits: (-128 >> 4) = -8 -> 0xF8
    {
        reset();
        op_arith(9 /*ASHR*/, 0, 8, 0, 0x80,1,0, 4,1,0);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == 0xF8, "ashr8");
    }
    // 4. ICMP_SLT @8: 0xFF (=-1 as i8) < 0 -> 1
    {
        reset();
        p8_(0x06); p8_(40 /*SLT*/); p8_(8); p32_(16); vconst_i(0xFF); vconst_i(0);
        p8_(0x0A); vslot(16);
        CHECK(run(NULL,0) == 1, "icmp_slt8 signed");
    }
    // 5. ICMP_UGT @8: 0xFF > 0 -> 1 (unsigned)
    {
        reset();
        p8_(0x06); p8_(34 /*UGT*/); p8_(8); p32_(16); vconst_i(0xFF); vconst_i(0);
        p8_(0x0A); vslot(16);
        CHECK(run(NULL,0) == 1, "icmp_ugt8");
    }
    // 6. float arith f32: 1.5 + 2.25 == 3.75 (bit patterns)
    {
        reset();
        p8_(0x10); p8_(13 /*FADD*/); p8_(1 /*FP*/); p8_(32); p32_(0);
        vconst_f32(1.5f); vconst_f32(2.25f);
        p8_(0x0A); vslot(0);
        uint64_t r = run(NULL,0);
        float got; uint32_t b32 = (uint32_t)r; memcpy(&got,&b32,4);
        CHECK(got == 3.75f, "fadd32");
    }
    // 7. FCMP_OEQ f64
    {
        reset();
        p8_(0x06); p8_(1 /*OEQ*/); p8_(64); p32_(8); vconst_f64(0.5); vconst_f64(0.5);
        p8_(0x0A); vslot(8);
        CHECK(run(NULL,0) == 1, "fcmp_oeq64");
    }
    // 8. LOAD/STORE with width: store 1 byte, load 1 byte from an arena cell
    {
        reset();
        p8_(0x03 /*STORE*/); vconst_i(0xAB); vconst_i((uint64_t)(uintptr_t)&buf[2048]); p8_(1);
        p8_(0x02 /*LOAD*/);  p32_(0); vconst_i((uint64_t)(uintptr_t)&buf[2048]); p8_(1);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == 0xAB, "store1/load1");
    }
    // 9. ALLOCA + STORE through the alloca pointer + LOAD back
    {
        reset();
        p8_(0x01 /*ALLOCA*/); p32_(0); p32_(16);         // slot0 = ptr to 16B zeroed
        p8_(0x03 /*STORE*/); vconst_i(77); vslot(0); p8_(8);   // *(slot0) = 77
        p8_(0x02 /*LOAD*/);  p32_(8); vslot(0); p8_(8);        // slot8 = *(slot0)
        p8_(0x0A); vslot(8);
        CHECK(run(NULL,0) == 77, "alloca+store+load");
    }
    // 10. GEP: base + 2 * 4
    {
        uint64_t base = (uint64_t)(uintptr_t)&buf[2048];
        reset();
        p8_(0x05); p32_(0); vconst_i(base); p32_(1); vconst_i(2); p32_(4);  // dst,base,n=1,(idx=2,scale=4)
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == base + 8, "gep+2*4");
    }
    // 11. GEP negative index: base + (-1) * 8
    {
        uint64_t base = (uint64_t)(uintptr_t)&buf[2048];
        reset();
        p8_(0x05); p32_(0); vconst_i(base); p32_(1); vconst_i((uint64_t)-1); p32_(8);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == base - 8, "gep-1*8");
    }
    // 11b. multi-index: gep(p, 0, 3) over [10 x i32]: scale0=40, scale1=4
    {
        uint64_t base = (uint64_t)(uintptr_t)&buf[2048];
        reset();
        p8_(0x05); p32_(0); vconst_i(base); p32_(2);
        vconst_i(0); p32_(40); vconst_i(3); p32_(4);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == base + 12, "gep(0,3) nested scales");
    }
    // 12. CAST SExt i8->i64: 0x80 -> 0xFF..FF80
    {
        reset();
        p8_(0x07); p8_(3 /*CC_SEXT*/); p8_(8); p8_(64); p32_(0); vconst_i(0x80);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == 0xFFFFFFFFFFFFFF80ull, "sext8to64");
    }
    // 13. CAST Trunc i64->i16 then SExt back
    {
        reset();
        p8_(0x07); p8_(1 /*CC_TRUNC*/); p8_(64); p8_(16); p32_(0); vconst_i(0x1234ABCD);
        p8_(0x07); p8_(3 /*CC_SEXT*/); p8_(16); p8_(64); p32_(8); vslot(0);
        p8_(0x0A); vslot(8);
        CHECK(run(NULL,0) == 0xFFFFFFFFFFFFABCDull, "trunc+sext");
    }
    // 14. CAST SIToFP i32->f64
    {
        reset();
        p8_(0x07); p8_(7 /*CC_SITOFP*/); p8_(32); p8_(64); p32_(0); vconst_i(3);
        p8_(0x0A); vslot(0);
        double d; uint64_t b = run(NULL,0); memcpy(&d,&b,8);
        CHECK(d == 3.0, "sitofp");
    }
    // 15. conditional BR: take true when slot0 != 0
    {
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);            // slot0 = arg0
        // pc layout: [1 PARAMMAP][.. 13 bytes] BR at 13: p8(1) cond=slot0 t=.. f=..
        // true path @ T: ARITH slot8 = 5+6; RET slot8
        // false path @ F: RET const 0
        uint32_t here = len;
        p8_(0x08); p8_(1); vslot(0); p32_(0); p32_(0);   // patched below
        uint32_t t_pos = len; (void)t_pos;
        uint32_t T = len;
        op_arith(0,0,32,8, 5,1,0, 6,1,0); p8_(0x0A); vslot(8);
        uint32_t F = len;
        p8_(0x0A); vconst_i(0);
        // patch branch targets
        buf[here+1+1+1+4+0] = (uint8_t)T; buf[here+1+1+1+4+1]=(uint8_t)(T>>8);
        buf[here+1+1+1+4+2] = (uint8_t)(T>>16); buf[here+1+1+1+4+3]=(uint8_t)(T>>24);
        buf[here+1+1+1+4+4] = (uint8_t)F; buf[here+1+1+1+4+5]=(uint8_t)(F>>8);
        buf[here+1+1+1+4+6] = (uint8_t)(F>>16); buf[here+1+1+1+4+7]=(uint8_t)(F>>24);
        uint64_t a1 = 1; void *args1[1] = { &a1 };
        CHECK(run(args1,1) == 11, "br taken");
        uint64_t a0 = 0; void *args0[1] = { &a0 };
        CHECK(run(args0,1) == 0, "br not taken");
    }
    // 16. CALL id=7 with two dyn slots (5,6) -> 11; void dst for id=9 path
    {
        reset();
        op_arith(0,0,64,0, 5,1,0, 0,1,0);                // slot0 = 5 + 0
        op_arith(0,0,64,8, 6,1,0, 0,1,0);                // slot8 = 6 + 0
        p8_(0x09); p64_(7); p32_(16); p32_(2); p32_(0); p32_(8);  // dst16 = call7(slot0, slot8)
        p8_(0x0A); vslot(16);
        CHECK(run(NULL,0) == 11, "call dyn args");
    }
    // 17. RET of a const (void-function shape)
    {
        reset();
        p8_(0x0A); vconst_i(0);
        CHECK(run(NULL,0) == 0, "ret const 0");
    }
    // 18. narrow load zero-extends: write 0xCD byte, load word around it
    {
        buf[2100] = 0; buf[2101] = 0;                    // neighbours clean
        reset();
        p8_(0x03); vconst_i(0xCD); vconst_i((uint64_t)(uintptr_t)&buf[2100]); p8_(1);
        p8_(0x02); p32_(0); vconst_i((uint64_t)(uintptr_t)&buf[2100]); p8_(1);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == 0xCD, "narrow load zero-extends");
    }
    // 19. UDIV by zero does not crash (returns 0), UDIV normal works
    {
        reset();
        op_arith(3 /*UDIV*/, 0, 32, 0, 10,1,0, 0,1,0);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == 0, "udiv by zero");
        reset();
        op_arith(3, 0, 32, 0, 10,1,0, 3,1,0);
        p8_(0x0A); vslot(0);
        CHECK(run(NULL,0) == 3, "udiv");
    }
    // 20. f64 arith: 1.25 * 4.0 == 5.0
    {
        reset();
        p8_(0x10); p8_(15 /*FMUL*/); p8_(1); p8_(64); p32_(0);
        vconst_f64(1.25); vconst_f64(4.0);
        p8_(0x0A); vslot(0);
        double d; uint64_t b = run(NULL,0); memcpy(&d,&b,8);
        CHECK(d == 5.0, "fmul64");
    }

    // ===== sealed-blob path (-irobf-irvm-enc) ==============================
    // S1. encrypted blob: decrypt-execute-reencrypt yields the same result
    //     as the plaintext run of the same stream (test-1 stream)
    {
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);
        op_arith(0, 0, 32, 8, 0,0,0, 0,0,0);
        p8_(0x0A); vslot(8);
        uint64_t arg = 21; void *args[1] = { &arg };
        uint64_t plain = run(args, 1);
        uint32_t total = seal(VM_SEAL_F_ENCRYPTED, KEY);
        CHECK(vm_exec_sealed(sbuf, total, KEY, NULL, args, 1) == plain,
              "sealed enc == plaintext run");
        // the .rodata-style original must still be ciphertext (unmodified)
        CHECK(sbuf[VM_SEAL_HDR_SIZE] != 0x11, "rodata original stays sealed");
    }
    // S2. encrypted blob with control flow + args (test-15 stream)
    {
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);
        uint32_t here = len;
        p8_(0x08); p8_(1); vslot(0); p32_(0); p32_(0);
        uint32_t T = len;
        op_arith(0,0,32,8, 5,1,0, 6,1,0); p8_(0x0A); vslot(8);
        uint32_t F = len;
        p8_(0x0A); vconst_i(0);
        buf[here+1+1+1+4+0]=(uint8_t)T; buf[here+8]=(uint8_t)(T>>8);
        buf[here+9]=(uint8_t)(T>>16); buf[here+10]=(uint8_t)(T>>24);
        buf[here+11]=(uint8_t)F; buf[here+12]=(uint8_t)(F>>8);
        buf[here+13]=(uint8_t)(F>>16); buf[here+14]=(uint8_t)(F>>24);
        uint64_t a1 = 1; void *args1[1] = { &a1 };
        uint64_t plain = run(args1, 1);
        uint32_t total = seal(VM_SEAL_F_ENCRYPTED, KEY);
        CHECK(vm_exec_sealed(sbuf, total, KEY, NULL, args1, 1) == plain,
              "sealed enc condbr == plaintext");
    }
    // S3. wrong key never yields the correct answer (deterministic stream)
    {
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);
        op_arith(0, 0, 32, 8, 0,0,0, 0,0,0);
        p8_(0x0A); vslot(8);
        uint64_t arg = 21; void *args[1] = { &arg };
        uint32_t total = seal(VM_SEAL_F_ENCRYPTED, KEY);
        uint64_t r_bad = vm_exec_sealed(sbuf, total, BADKEY, NULL, args, 1);
        CHECK(r_bad != 42, "wrong key gives wrong answer");
    }
    // S4. encrypted blob without a key: graceful 0, no crash
    {
        reset();
        p8_(0x0A); vconst_i(7);
        uint32_t total = seal(VM_SEAL_F_ENCRYPTED, KEY);
        CHECK(vm_exec_sealed(sbuf, total, NULL, NULL, NULL, 0) == 0,
              "enc blob without key -> 0");
        // legacy entry on an encrypted blob (no key argument available):
        // detected via header, also refuses gracefully
        CHECK(vm_exec(sbuf, total, NULL, 0) == 0,
              "legacy entry refuses enc blob");
    }
    // S5. legacy (unsealed) blob through vm_exec_sealed: perm is ignored
    {
        reset();
        p8_(0x0A); vconst_i(0x55);
        uint8_t junk[VM_OP_N]; vm_perm_from_seed(123, junk);
        CHECK(vm_exec_sealed(buf, len, NULL, junk, NULL, 0) == 0x55,
              "legacy blob ignores perm");
    }
    // S6. sealed but unencrypted, unpermuted: header skipped, runs directly
    {
        reset();
        p8_(0x0A); vconst_i(0x77);
        uint32_t total = seal(0, NULL);
        CHECK(vm_exec_sealed(sbuf, total, KEY, NULL, NULL, 0) == 0x77,
              "sealed plaintext runs");
    }

    // ===== permuted-dispatch path (-irobf-irvm-dispatch) ===================
    vm_perm_from_seed(0xC0FFEE123456789ull, PERM);
    // 同一流用明文规范码与置换码各跑一遍，结果必须一致（P1：enc+perm）
    {
        // 明文基准
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);
        op_arith(0, 0, 32, 8, 0,0,0, 0,0,0);
        p8_(0x0A); vslot(8);
        uint64_t arg = 6; void *args[1] = { &arg };
        uint64_t plain = run(args, 1);
        CHECK(plain == 12, "perm baseline plaintext");

        // 置换码：PARAMMAP/ARITH/RET 的 opcode 字节重编码
        reset();
        op_(0x11); p32_(1); p32_(0); p32_(8);
        p8_(vm_op_encode(0x10, PERM)); p8_(0); p8_(0); p8_(32); p32_(8);
        vslot(0); vslot(0);
        op_(0x0A); vslot(8);
        uint32_t total = seal(VM_SEAL_F_ENCRYPTED | VM_SEAL_F_PERMUTED, KEY);
        CHECK(vm_exec_sealed(sbuf, total, KEY, PERM, args, 1) == plain,
              "perm+enc == plaintext");
        // 置换确实发生了（至少一个操作码被重编码）
        CHECK(vm_op_encode(0x11, PERM) != 0x11 || vm_op_encode(0x0A, PERM) != 0x0A,
              "perm actually permutes");
    }
    // P2: perm only (no encryption)
    {
        reset();
        op_(0x0A); vconst_i(0x99);
        uint32_t total = seal(VM_SEAL_F_PERMUTED, NULL);
        CHECK(vm_exec_sealed(sbuf, total, NULL, PERM, NULL, 0) == 0x99,
              "perm-only runs");
    }
    // P3: wrong perm gives a different (wrong) answer — deterministic stream
    {
        reset();
        op_(0x0A); vconst_i(0x42);
        uint32_t total = seal(VM_SEAL_F_PERMUTED, NULL);
        uint8_t bad[VM_OP_N]; vm_perm_from_seed(777, bad);
        uint64_t r = vm_exec_sealed(sbuf, total, NULL, bad, NULL, 0);
        CHECK(r != 0x42, "wrong perm gives wrong answer");
    }
    // P4: permuted blob without perm table -> graceful 0
    {
        reset();
        op_(0x0A); vconst_i(1);
        uint32_t total = seal(VM_SEAL_F_PERMUTED, NULL);
        CHECK(vm_exec_sealed(sbuf, total, NULL, NULL, NULL, 0) == 0,
              "permuted blob without perm -> 0");
    }
    // P5: full stack — enc + perm + args + conditional branch
    {
        // 明文基准
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);
        uint32_t here = len;
        p8_(0x08); p8_(1); vslot(0); p32_(0); p32_(0);
        uint32_t T = len;
        op_arith(0,0,32,8, 21,1,0, 21,1,0); p8_(0x0A); vslot(8);
        uint32_t F = len;
        p8_(0x0A); vconst_i(0);
        buf[here+7]=(uint8_t)T; buf[here+8]=(uint8_t)(T>>8);
        buf[here+9]=(uint8_t)(T>>16); buf[here+10]=(uint8_t)(T>>24);
        buf[here+11]=(uint8_t)F; buf[here+12]=(uint8_t)(F>>8);
        buf[here+13]=(uint8_t)(F>>16); buf[here+14]=(uint8_t)(F>>24);
        uint64_t a1 = 1; void *args1[1] = { &a1 };
        uint64_t plain = run(args1, 1);
        CHECK(plain == 42, "full-stack baseline");

        // 置换码版本（手工重打包：PARAMMAP BR ARITH RET + 内部 RET const）
        reset();
        op_(0x11); p32_(1); p32_(0); p32_(8);
        uint32_t here2 = len;
        op_(0x08); p8_(1); vslot(0); p32_(0); p32_(0);
        uint32_t T2 = len;
        p8_(vm_op_encode(0x10, PERM)); p8_(0); p8_(0); p8_(32); p32_(8);
        vconst_i(21); vconst_i(21);
        op_(0x0A); vslot(8);
        uint32_t F2 = len;
        op_(0x0A); vconst_i(0);
        buf[here2+7]=(uint8_t)T2; buf[here2+8]=(uint8_t)(T2>>8);
        buf[here2+9]=(uint8_t)(T2>>16); buf[here2+10]=(uint8_t)(T2>>24);
        buf[here2+11]=(uint8_t)F2; buf[here2+12]=(uint8_t)(F2>>8);
        buf[here2+13]=(uint8_t)(F2>>16); buf[here2+14]=(uint8_t)(F2>>24);
        uint32_t total = seal(VM_SEAL_F_ENCRYPTED | VM_SEAL_F_PERMUTED, KEY);
        CHECK(vm_exec_sealed(sbuf, total, KEY, PERM, args1, 1) == plain,
              "enc+perm+args+br == plaintext");
    }

    // 21. SELECT: cond from param slot picks between two constants
    {
        reset();
        p8_(0x11); p32_(1); p32_(0); p32_(8);            // slot0 = arg0
        p8_(0x0C /*SELECT*/); p32_(16); vslot(0); vconst_i(0xAA); vconst_i(0xBB);
        p8_(0x0A); vslot(16);
        uint64_t a1 = 1; void *args1[1] = { &a1 };
        uint64_t a0 = 0; void *args0[1] = { &a0 };
        CHECK(run(args1,1) == 0xAA, "select true");
        CHECK(run(args0,1) == 0xBB, "select false");
    }
    // 22. SELECT sealed+encrypted+permuted full stack
    {
        uint64_t a1 = 1; void *args1[1] = { &a1 };
        uint64_t a0 = 0; void *args0[1] = { &a0 };
        reset();
        op_(0x11); p32_(1); p32_(0); p32_(8);
        op_(0x0C); p32_(16); vslot(0); vconst_i(0x1234); vconst_i(0x5678);
        op_(0x0A); vslot(16);
        uint32_t total = seal(VM_SEAL_F_ENCRYPTED | VM_SEAL_F_PERMUTED, KEY);
        CHECK(vm_exec_sealed(sbuf, total, KEY, PERM, args1, 1) == 0x1234,
              "select sealed+enc+perm true");
        CHECK(vm_exec_sealed(sbuf, total, KEY, PERM, args0, 1) == 0x5678,
              "select sealed+enc+perm false");
    }

    printf("vm_exec interpreter: %d checks passed\n", tests_run);
    return 0;
}
