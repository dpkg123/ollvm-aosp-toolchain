// vm_exec.h — public surface of the IR-virtualizer runtime.
//
// The compiler side (FuncRedirector.hpp) declares vm_exec with ExternalLinkage
// and emits a WEAK empty stub when no definition is present. Compiling
// vm_exec.c into the target provides a strong definition that overrides it.
//
//   code : bytecode emitted by Obfuscation/utils/VMCodeGen.h (FORMAT v2)
//   size : bytecode length in bytes
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

uint64_t vm_exec(const uint8_t *code, uint32_t size, void **args, uint64_t num);

#ifdef __cplusplus
}
#endif

#endif
