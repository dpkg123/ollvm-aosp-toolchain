# IRVM runtime — the missing half

The IR virtualizer (`.irvm` section + `-mllvm -irobf-irvm`, see
`../utils/IRVMModuleTool.h`) rewrites marked functions into calls to
`vm_exec(code, size, args, num)`. `FuncRedirector.hpp` links a **weak empty
stub** when no definition is present — a build without this runtime compiles
and links, then falls into that stub at runtime. **Always link this file into
anything built with `-irobf-irvm`:**

    clang -mllvm -irobf-irvm app.c \
        llvm/lib/Transforms/Obfuscation/runtime/vm_exec.c -lm -o app

## What is here

| file | role |
|---|---|
| `vm_exec.h` | public surface: `uint64_t vm_exec(const uint8_t*, uint32_t, void**, uint64_t)` |
| `vm_exec.c` | the interpreter: FORMAT v2 bytecode, slot machine, alloca arena, `handle_call` bridge |
| `test_vm_exec.c` | host unit tests: hand-packed bytecode exercising every opcode (22 checks). Build & run: `clang test_vm_exec.c vm_exec.c -lm && ./a.out` |

## FORMAT v2 (generator + interpreter contract)

Slot space: every slot is 8-byte aligned, 8-byte multiple, values stored
zero-extended (`OP_PARAMMAP` copies only the payload bytes into a zeroed
slot). Instruction extensions over the original v1 encoding — v1 emitted none
of the width fields and no standalone interpreter could implement it:

| opcode | v2 fields appended |
|---|---|
| `OP_LOAD` / `OP_STORE` | access width in bytes (1/2/4/8) |
| `OP_CAST` | src bits, dst bits |
| `OP_CMP` | operand width (integer bit width; 32/64 marks fp via the predicate range) |
| `OP_GEP` | `sizeof(source element)` after the indices |

Return convention: integers zero/sign-extended to width, pointers as
addresses, f32/f64 as IEEE bit patterns (matches `FuncRedirector`'s unboxing).

## Limits (deliberate)

- Static allocas only, no EH/atomics/vectors (the pass skips such functions
  with an `[irvm] skip` line — read stderr).
- One `vm_exec` invocation per call: own slot frame + alloca arena, freed on
  return; recursion- and thread-safe by construction.
- Runaway guard: 100M interpreter steps per invocation.
- Division by zero yields 0 with no crash (matches "educational runtime"
  intent; tighten if used adversarially).
