// vm_crypt.h — shared seal / keystream / opcode-permutation core (FORMAT v2 sealed blobs).
//
// Single source of truth included by BOTH sides, so the two can never drift:
//   - compiler side: Obfuscation/utils/VMCodeGen.h, Obfuscation/IRVMModuleTool.h (C++)
//   - runtime side:  Obfuscation/runtime/vm_exec.c (C99)
//
// Deliberately pure and dependency-free (only <stdint.h>, <stddef.h>, <string.h>):
// the runtime must stay free of LLVM headers, and the test suite must be able
// to exercise every function on the host with a plain system compiler.
//
// What lives here (SmallVMP hardening, items 1+2 of the roadmap):
//   * vm_keystream()      — xorshift128+ keystream XOR, self-inverse. Seals the
//                           bytecode at compile time; decrypts the heap working
//                           copy before interpretation and re-encrypts it after
//                           ("code 加密": 密文落盘、执行前解密、执行后再加密回去).
//   * vm_seal_*()         — 8-byte plaintext blob header {magic "IRVS", ver, flags}.
//   * vm_perm_*()/vm_op_* — per-build opcode permutation: canonical opcode bytes
//                           are remapped through a seeded Fisher–Yates shuffle
//                           ("动态分发": the opcode<->handler mapping is built at
//                           runtime from this table, never a fixed switch).
//
// Threat model, stated honestly: the key/permutation ship next to the ciphertext
// in the same binary. This defeats static pattern matching on plaintext bytecode
// (strings / opcode-sequence signatures / naive lifters) and forces an analyst to
// recover the seal layout first; it is not resistant to a determined reversible
// analysis. The .rodata original always stays encrypted — the runtime decrypts a
// private heap copy only (const pages are not writable), interprets from it, and
// re-encrypts that copy before free, so no plaintext bytecode lingers in memory
// beyond an active invocation and freed-memory dumps see ciphertext.

#ifndef OBFUSCATION_IRVM_VM_CRYPT_H
#define OBFUSCATION_IRVM_VM_CRYPT_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#ifdef __cplusplus
extern "C" {
#endif

// ---------------------------------------------------------------------------
// sealed-blob header: blob = header(8) || payload
// payload = FORMAT v2/v3 bytecode (opcode bytes possibly permuted, then all
// bytes XORed with the keystream when VM_SEAL_F_ENCRYPTED is set).
// A legacy (unsealed) blob starts with a valid opcode (0x01..0x11); 0x49 'I'
// can never be a first byte, so the magic is collision-free against every
// blob the old pass ever emitted.
// ---------------------------------------------------------------------------
#define VM_SEAL_HDR_SIZE 8
#define VM_SEAL_VER      1
#define VM_SEAL_F_ENCRYPTED 0x01u
#define VM_SEAL_F_PERMUTED  0x02u
#define VM_SEAL_F_KNOWN_MASK (VM_SEAL_F_ENCRYPTED | VM_SEAL_F_PERMUTED)

static const uint8_t VM_SEAL_MAGIC[4] = { 0x49, 0x52, 0x56, 0x53 }; /* "IRVS" */

static inline void vm_seal_write_header(uint8_t out[VM_SEAL_HDR_SIZE],
                                        unsigned flags) {
  memset(out, 0, VM_SEAL_HDR_SIZE);
  memcpy(out, VM_SEAL_MAGIC, 4);
  out[4] = (uint8_t)VM_SEAL_VER;
  out[5] = (uint8_t)(flags & 0xFFu);
}

/* Returns 1 and fills *flags / *payload_off when the blob carries a valid
 * header (known version, known flag bits). Returns 0 for legacy unsealed
 * blobs. */
static inline int vm_seal_parse(const uint8_t *blob, size_t size,
                                unsigned *flags, size_t *payload_off) {
  unsigned f;
  if (size < VM_SEAL_HDR_SIZE) return 0;
  if (memcmp(blob, VM_SEAL_MAGIC, 4) != 0) return 0;
  if (blob[4] != VM_SEAL_VER) return 0;
  f = blob[5];
  if (f & ~VM_SEAL_F_KNOWN_MASK) return 0; /* refuse unknown bits */
  if (flags) *flags = f;
  if (payload_off) *payload_off = VM_SEAL_HDR_SIZE;
  return 1;
}

// ---------------------------------------------------------------------------
// keystream: xorshift128+ over a 16-byte key. Symmetric (self-inverse XOR), no
// tables, constant-time per byte, trivially implemented identically in C and
// C++. init() folds the degenerate all-zero state onto golden-ratio seeds.
// ---------------------------------------------------------------------------
typedef struct { uint64_t s0, s1; } vm_ks;

static inline uint64_t vm_rd64le(const uint8_t *p) {
  uint64_t v = 0;
  int i;
  for (i = 7; i >= 0; i--) v = (v << 8) | p[i];
  return v;
}

static inline void vm_ks_init(vm_ks *ks, const uint8_t key[16]) {
  ks->s0 = vm_rd64le(key);
  ks->s1 = vm_rd64le(key + 8);
  if (ks->s0 == 0 && ks->s1 == 0) {
    ks->s0 = 0x9E3779B97F4A7C15ull;
    ks->s1 = 0xBF58476D1CE4E5B9ull;
  }
}

static inline uint64_t vm_ks_next(vm_ks *ks) {
  uint64_t x = ks->s0, y = ks->s1;
  ks->s0 = y;
  x ^= x << 23;
  ks->s1 = x ^ y ^ (x >> 17) ^ (y >> 26);
  return ks->s1 + y;
}

/* XOR buf[0..n) with the keystream. Sealing (compile time), decryption and
 * re-encryption (runtime working copy) are all this one call. Restarting the
 * stream from the same key reproduces the same bytes — that is what makes
 * "decrypt, execute, re-encrypt" restore the exact ciphertext. */
static inline void vm_keystream(uint8_t *buf, size_t n, const uint8_t key[16]) {
  vm_ks ks;
  size_t i;
  vm_ks_init(&ks, key);
  for (i = 0; i < n; i += 8) {
    uint64_t w = vm_ks_next(&ks);
    uint8_t kb[8];
    int j;
    for (j = 0; j < 8; j++) kb[j] = (uint8_t)(w >> (j * 8));
    for (j = 0; j < 8 && i + (size_t)j < n; j++) buf[i + j] ^= kb[j];
  }
}

/* derive a 16-byte key from a 64-bit seed (splitmix64; used by tests and by
 * the pass when a fixed -irobf-irvm-seed pins reproducible builds) */
static inline uint64_t vm_sm64_next(uint64_t *state) {
  uint64_t z = (*state += 0x9E3779B97F4A7C15ull);
  z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
  z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
  return z ^ (z >> 31);
}
static inline void vm_derive_key16(uint8_t key[16], uint64_t seed) {
  uint64_t st = seed;
  uint64_t a = vm_sm64_next(&st), b = vm_sm64_next(&st);
  int i;
  for (i = 0; i < 8; i++) key[i] = (uint8_t)(a >> (i * 8));
  for (i = 0; i < 8; i++) key[8 + i] = (uint8_t)(b >> (i * 8));
}

// ---------------------------------------------------------------------------
// opcode permutation (动态分发的编译侧一半): canonical opcode bytes below are
// the FORMAT v2/v3 wire contract; when VM_SEAL_F_PERMUTED is set the emitter
// writes perm[i] instead of VM_OP_CANON[i], and the interpreter fetches
// opcodes through a 256-entry decode LUT built at vm_exec entry from the
// permutation global — the mapping is data, decided per build, resolved per
// invocation, never a static switch.
// ---------------------------------------------------------------------------
#define VM_OP_N 12

static const uint8_t VM_OP_CANON[VM_OP_N] = {
  0x01, /* ALLOCA    */
  0x02, /* LOAD      */
  0x03, /* STORE     */
  0x05, /* GEP       */
  0x06, /* CMP       */
  0x07, /* CAST      */
  0x08, /* BR        */
  0x09, /* CALL      */
  0x0A, /* RET       */
  0x10, /* ARITH     */
  0x11, /* PARAMMAP  */
  0x0C, /* SELECT (reserved: IR select virtualization) */
};

static inline void vm_perm_identity(uint8_t perm[VM_OP_N]) {
  memcpy(perm, VM_OP_CANON, VM_OP_N);
}

/* a usable permutation must map every canonical opcode to a distinct
 * non-zero byte (0 marks "unknown opcode" in the decode LUT) */
static inline int vm_perm_valid(const uint8_t perm[VM_OP_N]) {
  int i, j;
  for (i = 0; i < VM_OP_N; i++) {
    if (perm[i] == 0) return 0;
    for (j = i + 1; j < VM_OP_N; j++)
      if (perm[i] == perm[j]) return 0;
  }
  return 1;
}

/* canonical opcode byte -> wire byte (identity when perm is identity) */
static inline uint8_t vm_op_encode(uint8_t canon, const uint8_t perm[VM_OP_N]) {
  int i;
  for (i = 0; i < VM_OP_N; i++)
    if (VM_OP_CANON[i] == canon) return perm[i];
  return canon; /* not a virtualized opcode: pass through */
}

/* build dec[256]: wire byte -> canonical opcode (0 = unknown/invalid) */
static inline void vm_perm_build_dec(const uint8_t perm[VM_OP_N],
                                     uint8_t dec[256]) {
  int i;
  memset(dec, 0, 256);
  for (i = 0; i < VM_OP_N; i++) dec[perm[i]] = VM_OP_CANON[i];
}

/* seeded Fisher–Yates over the canonical table — the pass derives a per-module
 * permutation from its RNG seed; tests re-derive it to cross-check emission */
static inline void vm_perm_from_seed(uint64_t seed, uint8_t perm[VM_OP_N]) {
  uint64_t st = seed ^ 0xD1B54A32D192ED03ull;
  int i;
  vm_perm_identity(perm);
  for (i = VM_OP_N - 1; i > 0; i--) {
    uint64_t r = vm_sm64_next(&st);
    int j = (int)(r % (uint64_t)(i + 1));
    uint8_t t = perm[i];
    perm[i] = perm[j];
    perm[j] = t;
  }
}

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* OBFUSCATION_IRVM_VM_CRYPT_H */
