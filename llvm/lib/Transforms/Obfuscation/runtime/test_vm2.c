// test_vm2.c — exhaustive equivalence between the L2 virtualized cores
// (vm2_arith / vm2_cmp / vm2_cast in vm2_exec.c) and the native evaluators
// (arith_eval / cmp_eval / cast_eval in vm_exec.c, exposed via
// -DVM_EXEC_EXPOSE_EVAL). The L2 programs are transliterations; this test is
// the ground truth that keeps them honest.
//
// Build & run:
//   cc -DVM_EXEC_EXPOSE_EVAL test_vm2.c vm_exec.c vm2_exec.c -lm -o t && ./t
#include "vm_exec.h"
#include "vm2_exec.h"
#include "vm_crypt.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* native evaluators (oracle), exposed by -DVM_EXEC_EXPOSE_EVAL */
uint64_t arith_eval(uint8_t sub, uint8_t tk, uint8_t bits, uint64_t a, uint64_t b);
int      cmp_eval(uint8_t pred, uint64_t a, uint64_t b, uint32_t bits);
uint64_t cast_eval(uint8_t op, uint8_t sbits, uint8_t dbits, uint64_t v);

static long tests_run = 0;
#define CHECK(cond, name) do { tests_run++; \
    if (!(cond)) { fprintf(stderr, "FAIL: %s (case %ld)\n", name, tests_run); exit(1); } } while (0)

/* vm_exec.c references this; the L2 equivalence tests never execute OP_CALL */
uint64_t handle_call(uint64_t id, void **args, uint64_t num) {
    (void)id; (void)args; (void)num; return 0;
}

static const uint64_t IV[] = {
    0, 1, 2, 3, 5, 7, 63, 64, 65, 100, 255, 256,
    0x7Full, 0x80ull, 0xFFull, 0x100ull,
    0x7FFFull, 0x8000ull, 0xFFFFull,
    0x7FFFFFFFull, 0x80000000ull, 0xFFFFFFFFull,
    0x7FFFFFFFFFFFFFFFull, 0x8000000000000000ull, 0xFFFFFFFFFFFFFFFFull,
    0x5555555555555555ull, 0xAAAAAAAAAAAAAAAAull, 0x0123456789ABCDEFull,
};
#define NIV (sizeof IV / sizeof IV[0])

static const uint8_t TK_INT = 0, TK_FP = 1;
enum { AR_ADD=0, AR_SUB, AR_MUL, AR_UDIV, AR_SDIV, AR_UREM, AR_SREM,
       AR_SHL, AR_LSHR, AR_ASHR, AR_AND, AR_OR, AR_XOR,
       AR_FADD, AR_FSUB, AR_FMUL, AR_FDIV, AR_FREM };

static void chk_arith_int(void) {
    static const uint8_t bitsv[4] = {8, 16, 32, 64};
    for (int s = 0; s <= 12; s++)
      for (int bi = 0; bi < 4; bi++)
        for (size_t i = 0; i < NIV; i++)
          for (size_t j = 0; j < NIV; j++) {
            uint8_t bits = bitsv[bi];
            uint64_t a = IV[i], b = IV[j];
            uint64_t want = arith_eval((uint8_t)s, TK_INT, bits, a, b);
            uint64_t got  = vm2_arith((uint8_t)s, TK_INT, bits, a, b);
            if (want != got) {
                fprintf(stderr,
                        "arith INT sub=%d bits=%u a=0x%llx b=0x%llx: "
                        "native=0x%llx l2=0x%llx\n",
                        s, bits, (unsigned long long)a, (unsigned long long)b,
                        (unsigned long long)want, (unsigned long long)got);
                exit(1);
            }
            tests_run++;
          }
}

static double f64v[] = {0.0, -0.0, 1.0, -1.5, 3.75, 1e300, 1e-300, 0.1};
static float  f32v[] = {0.0f, -0.0f, 1.0f, -1.5f, 3.75f, 1e30f, 1e-30f, 0.1f};
static uint64_t bits64(double d) { uint64_t b; memcpy(&b, &d, 8); return b; }
static uint64_t bits32(float f)  { uint32_t b; memcpy(&b, &f, 4); return b; }
static uint64_t f32nan = 0x7FC00000ull;        /* quiet NaN pattern */
static uint64_t f64nan = 0x7FF8000000000000ull;

static void chk_arith_fp(void) {
    int nf = (int)(sizeof f64v / sizeof f64v[0]);
    int nf32 = (int)(sizeof f32v / sizeof f32v[0]);
    for (int s = 13; s <= 17; s++)
      for (int i = -1; i < nf; i++)            /* -1 = NaN */
        for (int j = -1; j < nf; j++) {
            uint64_t a = i < 0 ? f64nan : bits64(f64v[i]);
            uint64_t b = j < 0 ? f64nan : bits64(f64v[j]);
            uint64_t want = arith_eval((uint8_t)s, TK_FP, 64, a, b);
            uint64_t got  = vm2_arith((uint8_t)s, TK_FP, 64, a, b);
            if (want != got) {
                fprintf(stderr, "arith FP64 sub=%d i=%d j=%d: native=%llx l2=%llx\n",
                        s, i, j, (unsigned long long)want, (unsigned long long)got);
                exit(1);
            }
            tests_run++;
            /* 32-bit side */
            a = i < 0 ? f32nan : (i < nf32 ? bits32(f32v[i]) : bits32(1.0f));
            b = j < 0 ? f32nan : (j < nf32 ? bits32(f32v[j]) : bits32(1.0f));
            want = arith_eval((uint8_t)s, TK_FP, 32, a, b);
            got  = vm2_arith((uint8_t)s, TK_FP, 32, a, b);
            if (want != got) {
                fprintf(stderr, "arith FP32 sub=%d i=%d j=%d: native=%llx l2=%llx\n",
                        s, i, j, (unsigned long long)want, (unsigned long long)got);
                exit(1);
            }
            tests_run++;
        }
}

static void chk_cmp(void) {
    /* fp preds 0..15 both widths (NaNs included) */
    for (int p = 0; p < 16; p++)
      for (int i = -1; i < (int)(sizeof f64v / sizeof f64v[0]); i++)
        for (int j = -1; j < (int)(sizeof f64v / sizeof f64v[0]); j++) {
            uint64_t a = i < 0 ? f64nan : bits64(f64v[i]);
            uint64_t b = j < 0 ? f64nan : bits64(f64v[j]);
            int want = cmp_eval((uint8_t)p, a, b, 64);
            int got  = vm2_cmp((uint8_t)p, a, b, 64);
            if (want != got) {
                fprintf(stderr, "cmp FP64 pred=%d i=%d j=%d: %d vs %d\n", p, i, j, want, got);
                exit(1);
            }
            tests_run++;
        }
    for (int p = 0; p < 16; p++)
      for (int i = -1; i < (int)(sizeof f32v / sizeof f32v[0]); i++)
        for (int j = -1; j < (int)(sizeof f32v / sizeof f32v[0]); j++) {
            uint64_t a = i < 0 ? f32nan : bits32(f32v[i]);
            uint64_t b = j < 0 ? f32nan : bits32(f32v[j]);
            int want = cmp_eval((uint8_t)p, a, b, 32);
            int got  = vm2_cmp((uint8_t)p, a, b, 32);
            if (want != got) {
                fprintf(stderr, "cmp FP32 pred=%d i=%d j=%d: %d vs %d\n", p, i, j, want, got);
                exit(1);
            }
            tests_run++;
        }
    /* int preds 32..41 across widths (sext-sensitive) */
    for (int p = 32; p <= 41; p++)
      for (int bi = 0; bi < 4; bi++) {
        uint8_t bits = (uint8_t)((const uint8_t[4]){8,16,32,64})[bi];
        for (size_t i = 0; i < NIV; i++)
          for (size_t j = 0; j < NIV; j++) {
            int want = cmp_eval((uint8_t)p, IV[i], IV[j], bits);
            int got  = vm2_cmp((uint8_t)p, IV[i], IV[j], bits);
            if (want != got) {
                fprintf(stderr, "cmp INT pred=%d bits=%u a=%llx b=%llx: %d vs %d\n",
                        p, bits, (unsigned long long)IV[i], (unsigned long long)IV[j],
                        want, got);
                exit(1);
            }
            tests_run++;
          }
      }
}

static void chk_cast(void) {
    static const uint8_t w[5] = {8, 16, 32, 64, 1};
    /* int-involving casts over all sbits/dbits combos */
    for (int op = 1; op <= 12; op++)
      for (int si = 0; si < 5; si++)
        for (int di = 0; di < 5; di++) {
          uint8_t sb = w[si], db = w[di];
          for (size_t i = 0; i < NIV; i++) {
            uint64_t v = IV[i];
            uint64_t want = cast_eval((uint8_t)op, sb, db, v);
            uint64_t got  = vm2_cast((uint8_t)op, sb, db, v);
            if (want != got) {
                fprintf(stderr, "cast op=%d sb=%u db=%u v=%llx: native=%llx l2=%llx\n",
                        op, sb, db, (unsigned long long)v,
                        (unsigned long long)want, (unsigned long long)got);
                exit(1);
            }
            tests_run++;
          }
        }
    /* fp casts with the actual float inputs (incl NaN) */
    for (int op = 4; op <= 9; op++)
      for (int i = -1; i < (int)(sizeof f64v / sizeof f64v[0]); i++) {
        uint64_t v = i < 0 ? f64nan : bits64(f64v[i]);
        static const uint8_t w2[2] = {32, 64};
        for (int si = 0; si < 2; si++)
          for (int di = 0; di < 2; di++) {
            uint64_t want = cast_eval((uint8_t)op, w2[si], w2[di], v);
            uint64_t got  = vm2_cast((uint8_t)op, w2[si], w2[di], v);
            if (want != got) {
                fprintf(stderr, "castfp op=%d v=%llx sb=%u db=%u: %llx vs %llx\n",
                        op, (unsigned long long)v, w2[si], w2[di],
                        (unsigned long long)want, (unsigned long long)got);
                exit(1);
            }
            tests_run++;
          }
      }
}

int main(void) {
    chk_arith_int();
    chk_arith_fp();
    chk_cmp();
    chk_cast();
    printf("test_vm2 (L2 equivalence): all %ld cases passed\n", tests_run);
    return 0;
}
