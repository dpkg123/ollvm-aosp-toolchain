/*
 * VMP.h — IRVM user-side header (runtime half shipped with the toolchain).
 *
 * Usage:
 *   #include "VMP.h"
 *
 *   IRVM_SECTION
 *   int my_secret(int a, int b) { return a * b + 1; }
 *
 * Build (link the interpreter; without it the pass's weak empty stub runs):
 *   clang -mllvm -irobf-irvm app.c \
 *       llvm/lib/Transforms/Obfuscation/runtime/vm_exec.c -lm -o app
 *
 * IRVM_SECTION places the function in section ".irvm"; the IRVM pass
 * (enabled by -mllvm -irobf-irvm) translates it to bytecode and rewrites the
 * body to call vm_exec(code, size, args, num).
 *
 * Debugging: set VMP_TRACE=1 in the environment to get a per-step interpreter
 * trace (opcode, operands, results) on stderr.
 *
 * Read stderr at build time: every "[irvm] skip ..." line names a function
 * that stayed NATIVE (e.g. `select` is not virtualized yet) — know which
 * functions you actually protected before trusting coverage.
 */
#ifndef IRVM_VMP_H
#define IRVM_VMP_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Mark a function for IR-level virtualization. */
#define IRVM_SECTION __attribute__((section(".irvm")))

/* The VM entry the rewritten stubs call (strong definition in vm_exec.c). */
uint64_t vm_exec(const uint8_t *code, uint32_t size, void **args, uint64_t num);

/* Bridge dispatch: the IRVM pass generates a strong definition; this weak
 * fallback keeps -O0 test builds linkable when the pass produced none. */
__attribute__((weak))
uint64_t handle_call(uint64_t id, void **args, uint64_t num) {
  (void)id; (void)args; (void)num;
  return 0;
}

#ifdef __cplusplus
}
#endif

#endif
