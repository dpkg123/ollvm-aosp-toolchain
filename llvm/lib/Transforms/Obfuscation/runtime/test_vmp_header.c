// test_vmp_header.c — header-only runtime smoke test (TU 1 of 3).
//
// Proves the VMP.h single-include story end to end on the host:
//   * this TU includes VMP.h, defines a strong handle_call, runs a sealed +
//     permuted + encrypted blob through the full stack (L1 dispatch + L2
//     cores + seal decrypt/re-encrypt);
//   * test_vmp_header_tu2.c includes VMP.h and uses nothing (weak-def
//     coexistence, -Wall clean);
//   * test_vmp_header.cpp is a C++ TU calling vm_exec.
//
// Build & run:
//   cc -std=c99 -Wall -Wextra -Werror -I. test_vmp_header.c
//      test_vmp_header_tu2.c -lm -o t && ./t
//   (plus: g++ -c test_vmp_header.cpp && link the .o in)
#include "vm_crypt.h"

#define VMP_NO_WEAK_HANDLE_CALL   /* this TU defines the strong bridge */
#include "VMP.h"

#include <stdio.h>
#include <string.h>

uint64_t handle_call(uint64_t id, void **args, uint64_t num) {
    if (id == 7 && num >= 2) {
        uint64_t a, b;
        memcpy(&a, args[0], 8);
        memcpy(&b, args[1], 8);
        return a + b;
    }
    return 0;
}

static int checks = 0;
#define CHECK(c, n) do { checks++; \
    if (!(c)) { fprintf(stderr, "FAIL: %s\n", n); return 1; } } while (0)

int main(void) {
    /* plaintext stream: slot0=arg0; slot8=arg0+arg0; RET slot8  (=2*arg0) */
    uint8_t pt[64];
    uint32_t n = 0;
#define P8(v)  (pt[n++] = (uint8_t)(v))
#define P32(v) do { uint32_t x_ = (uint32_t)(v); \
    P8(x_); P8(x_ >> 8); P8(x_ >> 16); P8(x_ >> 24); } while (0)
    P8(0x11); P32(1); P32(0); P32(8);            /* PARAMMAP arg0 -> slot0(8B) */
    P8(0x10); P8(0); P8(0); P8(32); P32(8);      /* ARITH ADD i32, dst=8 */
    P8(1); P32(0);                               /* a = VT_SLOT 0 */
    P8(1); P32(0);                               /* b = VT_SLOT 0 */
    P8(0x0A); P8(1); P32(8);                     /* RET slot8 */

    uint64_t arg = 21;
    void *args[1] = { &arg };

    /* 1. plaintext via legacy entry */
    CHECK(vm_exec(pt, n, args, 1) == 42, "plaintext 2*21");

    /* 2. sealed + encrypted (key derives deterministically) */
    uint8_t key[16];
    vm_derive_key16(key, 424242);
    uint8_t blob[64 + VM_SEAL_HDR_SIZE];
    vm_seal_write_header(blob, VM_SEAL_F_ENCRYPTED);
    memcpy(blob + VM_SEAL_HDR_SIZE, pt, n);
    vm_keystream(blob + VM_SEAL_HDR_SIZE, n, key);
    CHECK(vm_exec_sealed(blob, VM_SEAL_HDR_SIZE + n, key, NULL, args, 1) == 42,
          "sealed+enc 2*21");
    CHECK(blob[VM_SEAL_HDR_SIZE] != 0x11, "rodata stays ciphertext");

    /* 3. level-2 cores are live: SREM(-7,3)@16 -> 0xFFFF through OP_ARITH */
    uint8_t pt2[64];
    uint32_t m = 0;
#undef P8
#undef P32
#define P8(v)  (pt2[m++] = (uint8_t)(v))
#define P32(v) do { uint32_t x_ = (uint32_t)(v); \
    P8(x_); P8(x_ >> 8); P8(x_ >> 16); P8(x_ >> 24); } while (0)
    P8(0x10); P8(6 /*SREM*/); P8(0); P8(16); P32(0);   /* dst 0 */
    P8(0); P8(0); P32(8);                            /* VT_CONST CK_INT sz8 */
    { uint64_t sv = (uint64_t)(int64_t)-7; int i;
      for (i = 0; i < 8; i++) P8(sv >> (i * 8)); }
    P8(0); P8(0); P32(8);
    { uint64_t sv = 3; int i;
      for (i = 0; i < 8; i++) P8(sv >> (i * 8)); }
    P8(0x0A); P8(1); P32(0);                           /* RET slot0 */
    CHECK(vm_exec(pt2, m, NULL, 0) == 0xFFFF, "L2 srem sign");

    printf("test_vmp_header: all %d checks passed\n", checks);
    return 0;
}
