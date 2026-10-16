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
| `vm_exec.h` | public surface: `vm_exec` + `vm_exec_sealed` |
| `vm_crypt.h` | **shared seal core** — keystream cipher, IRVS header, opcode permutation; single source of truth for the pass (C++) and the runtime (C99) |
| `vm_exec.c` | the L1 interpreter: FORMAT v2 slot machine, sealed-blob handling, dynamic dispatch table |
| `vm2_exec.h/.c` | the **level-2 VM** (optional link): interprets the L1 interpreter's arith/cmp/cast cores |
| `vm2_prog.h` | sealed L2 programs (generated — do not edit) |
| `vm2gen.c` | dev-time generator for `vm2_prog.h` (not shipped in builds) |
| `VMP.h` | user-side header (`IRVM_SECTION`, weak `handle_call` fallback) |
| `test_vm_crypt.c` | seal/keystream/permutation KAT + property tests |
| `test_vm_exec.c` | L1 interpreter tests: hand-packed bytecode, sealed + permuted paths |
| `test_vm2.c` | exhaustive L2-vs-native equivalence (84k cases) |

## FORMAT v2 (generator + interpreter contract)

Slot space: every slot is 8-byte aligned, 8-byte multiple, values stored
zero-extended (`OP_PARAMMAP` copies only the payload bytes into a zeroed
slot). Instruction extensions over v1:

| opcode | v2 fields appended |
|---|---|
| `OP_LOAD` / `OP_STORE` | access width in bytes (1/2/4/8) |
| `OP_CAST` | src bits, dst bits |
| `OP_CMP` | operand width (32/64 mark fp via the predicate range) |
| `OP_GEP` | `sizeof(source element)` after the indices |
| `OP_SELECT` | `dst`, then cond/true/false as encoded values |

Return convention: integers zero/sign-extended to width, pointers as
addresses, f32/f64 as IEEE bit patterns (matches `FuncRedirector`'s unboxing).

## Hardening features (SmallVMP roadmap items 1–3 + select)

All opt-in, combinable, and backward compatible — a blob without the seal
header runs exactly as before.

### ① Code 加密 (`-mllvm -irobf-irvm-enc`)

The `<fn>_code` global is stored as ciphertext: `[8-byte IRVS header
{magic, ver, flags}][xorshift128+ keystream payload]`. A 16-byte per-function
key ships as `<fn>_k`. At runtime `vm_exec_sealed` mallocs a **private heap
copy**, decrypts it, interprets from it, then **re-encrypts the copy before
free** — the `.rodata` original stays ciphertext for the process lifetime and
freed-memory dumps see ciphertext, never plaintext bytecode.

### ② 动态分发 (`-mllvm -irobf-irvm-dispatch`)

Two layers, no static switch anywhere:

* **build-time**: every opcode byte in the blob is remapped through a
  per-module random permutation (Fisher–Yates over the 12 canonical opcodes,
  table shipped as `__irvm_op_perm`);
* **run-time**: `build_dispatch()` rebuilds the `wire byte -> slot ->
  function pointer` table on **every** `vm_run` invocation, shuffling handler
  slots with stack-address + call-counter entropy.

The opcode↔handler mapping differs per build *and* per call.

### ③ 嵌套 VM (link `vm2_exec.c`)

`OP_ARITH` / `OP_CMP` / `OP_CAST` delegate to `vm2_arith` / `vm2_cmp` /
`vm2_cast`: the L1 interpreter's semantic cores execute as **L2 bytecode** on
a second, deliberately disjoint stack machine (different ISA, rel32 branches,
sealed programs decrypted once per process, re-encrypted at exit). Lifting
the target now requires lifting two unrelated VMs. Linking is optional —
without `vm2_exec.c`, weak hooks fall back to the native evaluators and the
runtime behaves exactly like the single-file version.

### `select` 虚拟化

`select` is now translated (`OP_SELECT`) instead of skipped; only vector
selects remain rejected. (Constant `select c, 1, 0` forms are still folded to
`zext` earlier by `PhiSimplifyTool` — that's an optimization, not a
limitation.)

### Build matrix

    # base virtualization
    clang -mllvm -irobf-irvm app.c vm_exec.c -lm -o app
    # + ① encryption (compile side: -irobf-irvm-enc)
    clang -mllvm -irobf-irvm -mllvm -irobf-irvm-enc app.c vm_exec.c -lm -o app
    # + ② dynamic dispatch (-irobf-irvm-dispatch)
    clang -mllvm -irobf-irvm -mllvm -irobf-irvm-enc \
          -mllvm -irobf-irvm-dispatch app.c vm_exec.c -lm -o app
    # + ③ nested VM: link vm2_exec.c
    clang -mllvm -irobf-irvm -mllvm -irobf-irvm-enc \
          -mllvm -irobf-irvm-dispatch app.c vm_exec.c vm2_exec.c -lm -o app

Reproducible builds: `-mllvm -irobf-irvm-seed=N` pins the RNG (keys +
permutation).

## Tests

    cd llvm/lib/Transforms/Obfuscation/runtime
    cc test_vm_crypt.c -o t1 && ./t1                                            # 253 checks
    cc vm_exec.c test_vm_exec.c -o t2 -lm && ./t2                               # 43 checks (native cores)
    cc vm_exec.c vm2_exec.c test_vm_exec.c -o t3 -lm && ./t3                     # 43 checks (L2 cores)
    cc -DVM_EXEC_EXPOSE_EVAL test_vm2.c vm_exec.c vm2_exec.c -o t4 -lm && ./t4  # 84k L2 equivalence

Regenerating the L2 programs after touching `vm2_exec.h`/`vm2gen.c`:

    cc vm2gen.c -o vm2gen && ./vm2gen > vm2_prog.h   # then re-run t4!

## Limits (deliberate)

- Static allocas only, no EH/atomics/vectors (the pass skips such functions
  with an `[irvm] skip` line — read stderr).
- One `vm_exec` invocation per call: own slot frame + alloca arena, freed on
  return; recursion- and thread-safe by construction.
- Runaway guard: 100M interpreter steps (L1) / 1M steps (L2) per invocation.
- Division by zero yields 0 with no crash ("educational runtime" intent).
- **Threat model, stated honestly**: keys/permutations ship inside the
  binary. The seal defeats static pattern matching on plaintext bytecode and
  forces recovery of the layout first; it is not resistant to a determined
  reversible-engineering effort. The `handle_call` bridge and the L2 programs
  themselves are sealed but their keys are fixed per build (rotate by
  re-running `vm2gen`).
- L2 lazy-decrypt is once-per-process (race is benign); the working copies
  are re-encrypted at exit via `atexit`.
