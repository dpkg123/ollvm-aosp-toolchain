// vm_exec.h — public surface of the IR-virtualizer runtime.
//
// The compiler side (FuncRedirector.hpp) declares vm_exec with ExternalLinkage
// and emits a WEAK empty stub when no definition is present. Compiling
// vm_exec.c into the target provides a strong definition that overrides it.
//
//   code : bytecode emitted by Obfuscation/utils/VMCodeGen.h (FORMAT v2);
//          with -irobf-irvm-enc/-irobf-irvm-dispatch this is a SEALED blob:
//          [8-byte IRVS header][payload] where the payload is keystream-
//          encrypted and/or carries permuted opcode bytes (see vm_crypt.h)
//   size : blob length in bytes (header included when sealed)
//   args : one pointer per function argument; args[i] points at the boxed
//          value (see FuncRedirector's argument boxing), read by OP_PARAMMAP
//   num  : number of arguments
//
// Returns the function's return value as a u64: integers zero/sign-extended
// to width, pointers as addresses, f32/f64 as IEEE bit patterns.

#ifndef OBFUSCATION_IRVM_VM_EXEC_H
#define OBFUSCATION_IRVM_VM_EXEC_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Legacy entry (also auto-detects sealed blobs via their header). */
uint64_t vm_exec(const uint8_t *code, uint32_t size, void **args, uint64_t num);

/* Hardening entry used by stubs built with -irobf-irvm-enc / -dispatch:
 *   key16 : 16-byte keystream key (NULL only if the blob is not encrypted)
 *   perm  : VM_OP_N-byte opcode permutation table (NULL if not permuted) */
uint64_t vm_exec_sealed(const uint8_t *code, uint32_t size,
                        const uint8_t *key16, const uint8_t *perm,
                        void **args, uint64_t num);

#ifdef __cplusplus
}
#endif

#endif
