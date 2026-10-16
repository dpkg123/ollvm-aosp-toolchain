// test_vm_crypt.c — host unit tests for the shared seal/keystream/permutation
// core (vm_crypt.h). This file pins the cross-side contract: the compiler
// (C++) and the interpreter (C) both include the header, and these
// known-answer vectors make any accidental change to the seal format loud.
//
// Build & run:  clang test_vm_crypt.c -o t && ./t   (or any C99 compiler)
#include "vm_crypt.h"
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int tests_run = 0;
#define CHECK(cond, name) do { tests_run++; \
    if (!(cond)) { fprintf(stderr, "FAIL: %s\n", name); exit(1); } } while (0)

/* KAT vectors (generated once from the reference implementation; changing
 * these means changing the sealed-blob ABI — bump VM_SEAL_VER and update
 * both sides + docs). */
static const uint8_t KAT_KEY[16] = {0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15};
static const uint64_t KAT_WORD0 = 0x9917d89494931393ull;
static const uint64_t KAT_WORD1 = 0x8d0bd2afca7eb0afull;
static const uint8_t KAT_PT[24] = {1,8,15,22,29,36,43,50,57,64,71,78,
                                   85,92,99,106,113,120,127,134,141,148,155,162};
static const uint8_t KAT_CT[24] = {0x92,0x1b,0x9c,0x82,0x89,0xfc,0x3c,0xab,
                                   0x96,0xf0,0x39,0x84,0xfa,0x8e,0x68,0xe7,
                                   0xee,0x51,0x8e,0x8a,0xb9,0xa2,0xca,0xf2};
static const uint8_t KAT_PERM[VM_OP_N] =
    {0x09,0x07,0x0c,0x06,0x0a,0x03,0x02,0x01,0x05,0x08,0x10,0x11};
static const uint8_t KAT_KEY42[16] = {0x95,0x6e,0xeb,0x2f,0x26,0x32,0xd7,0xbd,
                                      0x03,0xf1,0x66,0xb2,0x33,0xe3,0xef,0x28};

int main(void) {
  /* --- 1. keystream KAT: exact words + exact ciphertext ------------------- */
  {
    vm_ks ks;
    vm_ks_init(&ks, KAT_KEY);
    CHECK(ks.s0 == 0x0706050403020100ull, "ks init lo");
    CHECK(ks.s1 == 0x0f0e0d0c0b0a0908ull, "ks init hi");
    CHECK(vm_ks_next(&ks) == KAT_WORD0, "ks word0 KAT");
    CHECK(vm_ks_next(&ks) == KAT_WORD1, "ks word1 KAT");
    uint8_t buf[24];
    memcpy(buf, KAT_PT, 24);
    vm_keystream(buf, 24, KAT_KEY);
    CHECK(memcmp(buf, KAT_CT, 24) == 0, "keystream KAT ct");
    /* length not a multiple of 8: only the first n bytes change, the tail
     * bytes of the last keystream word are simply unused */
    uint8_t b5[5]; memcpy(b5, KAT_PT, 5);
    vm_keystream(b5, 5, KAT_KEY);
    CHECK(memcmp(b5, KAT_CT, 5) == 0, "keystream prefix n%8!=0");
  }
  /* --- 2. self-inverse: seal -> unseal -> re-seal restores ciphertext ----- */
  {
    uint8_t a[100], orig[100], ct[100];
    for (int i = 0; i < 100; i++) a[i] = orig[i] = (uint8_t)(i * 31 + 5);
    vm_keystream(a, 100, KAT_KEY);
    memcpy(ct, a, 100);
    CHECK(memcmp(a, orig, 100) != 0, "ciphertext differs from plaintext");
    vm_keystream(a, 100, KAT_KEY);
    CHECK(memcmp(a, orig, 100) == 0, "decrypt restores plaintext");
    vm_keystream(a, 100, KAT_KEY);
    CHECK(memcmp(a, ct, 100) == 0, "re-encrypt restores ciphertext");
  }
  /* --- 3. key sensitivity -------------------------------------------------- */
  {
    uint8_t k2[16]; memcpy(k2, KAT_KEY, 16); k2[0] ^= 1;
    uint8_t a[32], b[32];
    memset(a, 0x5A, 32); memset(b, 0x5A, 32);
    vm_keystream(a, 32, KAT_KEY);
    vm_keystream(b, 32, k2);
    CHECK(memcmp(a, b, 32) != 0, "one-bit key change alters stream");
    /* all-zero key must not degenerate (golden-ratio fallback) */
    uint8_t zk[16]; memset(zk, 0, 16);
    vm_ks k; vm_ks_init(&k, zk);
    uint64_t w1 = vm_ks_next(&k), w2 = vm_ks_next(&k);
    CHECK(w1 != 0 && w2 != 0 && w1 != w2, "zero-key fallback non-degenerate");
  }
  /* --- 4. seal header: roundtrip + strictness ------------------------------ */
  {
    uint8_t blob[VM_SEAL_HDR_SIZE + 16];
    unsigned flags; size_t off;
    CHECK(vm_seal_parse(blob, 0, &flags, &off) == 0, "empty blob unsealed");
    CHECK(vm_seal_parse(blob, 3, &flags, &off) == 0, "short blob unsealed");
    vm_seal_write_header(blob, VM_SEAL_F_ENCRYPTED | VM_SEAL_F_PERMUTED);
    CHECK(vm_seal_parse(blob, sizeof blob, &flags, &off) == 1, "sealed parse ok");
    CHECK(flags == (VM_SEAL_F_ENCRYPTED | VM_SEAL_F_PERMUTED), "flags roundtrip");
    CHECK(off == VM_SEAL_HDR_SIZE, "payload offset");
    blob[5] |= 0x80u; /* unknown bit */
    CHECK(vm_seal_parse(blob, sizeof blob, &flags, &off) == 0, "unknown flag rejected");
    vm_seal_write_header(blob, 0);
    blob[4] = 99; /* bad version */
    CHECK(vm_seal_parse(blob, sizeof blob, &flags, &off) == 0, "bad version rejected");
    /* legacy bytecode can never collide with the magic: valid first opcodes
     * are 0x01..0x11, magic starts with 'I' = 0x49 */
    uint8_t legacy[8] = {0x11, 0, 0, 0, 1, 0, 0, 0};
    CHECK(vm_seal_parse(legacy, sizeof legacy, &flags, &off) == 0,
          "legacy PARAMMAP blob stays unsealed");
  }
  /* --- 5. permutation: determinism, validity, encode/decode roundtrip ------ */
  {
    uint8_t p1[VM_OP_N], p2[VM_OP_N], ident[VM_OP_N];
    vm_perm_identity(ident);
    CHECK(vm_perm_valid(ident), "identity perm valid");
    vm_perm_from_seed(0xDEADBEEFCAFE1234ull, p1);
    vm_perm_from_seed(0xDEADBEEFCAFE1234ull, p2);
    CHECK(memcmp(p1, p2, VM_OP_N) == 0, "perm deterministic");
    CHECK(memcmp(p1, KAT_PERM, VM_OP_N) == 0, "perm KAT");
    CHECK(vm_perm_valid(p1), "seeded perm valid (injective, no zero)");
    /* encode(canonical) -> decode LUT -> canonical, for all 12 ops */
    uint8_t dec[256];
    vm_perm_build_dec(p1, dec);
    for (int i = 0; i < VM_OP_N; i++) {
      uint8_t canon = VM_OP_CANON[i];
      uint8_t wire = vm_op_encode(canon, p1);
      CHECK(wire == p1[i], "encode table order");
      CHECK(dec[wire] == canon, "lut decode roundtrip");
    }
    /* every unmapped byte decodes to 0 (invalid) */
    memset(dec, 0xAA, sizeof dec);
    vm_perm_identity(ident);
    vm_perm_build_dec(ident, dec);
    CHECK(dec[0] == 0 && dec[0x04] == 0 && dec[0xFF] == 0, "unmapped -> invalid");
    /* degenerate perms rejected */
    uint8_t bad[VM_OP_N]; vm_perm_identity(bad); bad[3] = bad[0];
    CHECK(!vm_perm_valid(bad), "duplicate rejected");
    bad[3] = 0;
    CHECK(!vm_perm_valid(bad), "zero rejected");
  }
  /* --- 6. distribution smoke: most seeds move the table ------------------- */
  {
    int nonident = 0;
    uint8_t ident[VM_OP_N], p[VM_OP_N];
    vm_perm_identity(ident);
    for (uint64_t s = 0; s < 200; s++) {
      vm_perm_from_seed(s, p);
      CHECK(vm_perm_valid(p), "seeded perm stays valid");
      if (memcmp(p, ident, VM_OP_N) != 0) nonident++;
    }
    CHECK(nonident >= 190, "most seeds produce a non-identity perm");
    (void)nonident;
  }
  /* --- 7. key derivation KAT ---------------------------------------------- */
  {
    uint8_t k[16]; vm_derive_key16(k, 42);
    CHECK(memcmp(k, KAT_KEY42, 16) == 0, "derive_key16 KAT");
    uint8_t k2[16]; vm_derive_key16(k2, 43);
    CHECK(memcmp(k, k2, 16) != 0, "adjacent seeds differ");
  }

  printf("test_vm_crypt: all %d checks passed\n", tests_run);
  return 0;
}
