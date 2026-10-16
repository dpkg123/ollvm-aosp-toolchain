# IRVM runtime — the missing half

The IR virtualizer (`.irvm` section + `-mllvm -irobf-irvm`, see
`../utils/IRVMModuleTool.h`) rewrites marked functions into calls to
`vm_exec(code, size, args, num)`. Since the header-only rework the runtime
ships entirely inside `VMP.h` — **include it and you are done**, no .c files
to pick between:

    #include "VMP.h"
    IRVM_SECTION int my_secret(int a, int b) { return a * b + 1; }

    clang -mllvm -irobf-irvm -mllvm -irobf-irvm-enc \
          -mllvm -irobf-irvm-dispatch app.c -lm -o app

Without the include (and without linking anything) the pass emits a WEAK
empty `vm_exec` stub instead — such builds still link, then fall into the
stub at runtime.

## What is here

| file | role |
|---|---|
| `VMP.h` | **the runtime** (header-only): L1 interpreter + seal handling + level-2 VM, `static inline` internals + weak exports |
| `vm_crypt.h` | shared seal core — keystream cipher, IRVS header, opcode permutation; single source of truth for the pass (C++) and the runtime (C99) |
| `vm2_exec.h` | L2 ISA (included by VMP.h; prototypes only for the deprecated standalone build) |
| `vm2_prog.h` | sealed L2 programs (generated — do not edit) |
| `vm2gen.c` | dev-time generator for `vm2_prog.h` (not shipped in builds) |
| `vm_exec.h` | plain prototypes for reference |
| `vm_exec.c`, `vm2_exec.c` | DEPRECATED one-line shims (`#include "VMP.h"`) — old link commands keep working |
| `test_vm_crypt.c` | seal/keystream/permutation KAT + property tests |
| `test_vm_exec.c` | L1 interpreter tests: hand-packed bytecode, sealed + permuted paths |
| `test_vm2.c` | exhaustive L2-vs-native equivalence (84k cases) |
| `test_vmp_header{,_tu2.c,.cpp}` | header-only smoke: 3 TUs (C/C++), strong-`handle_call` coexistence |

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

### ③ 嵌套 VM (on by default in VMP.h)

`OP_ARITH` / `OP_CMP` / `OP_CAST` delegate to the L2 cores: the L1
interpreter's semantic cores execute as **L2 bytecode** on a second,
deliberately disjoint stack machine (different ISA, rel32 branches, sealed
programs decrypted once per process, re-encrypted at exit). Lifting the target
now requires lifting two unrelated VMs. Slim it out with `#define VMP_L2 0`
before including `VMP.h` (falls back to the native evaluators).

### `select` 虚拟化

`select` is now translated (`OP_SELECT`) instead of skipped; only vector
selects remain rejected. (Constant `select c, 1, 0` forms are still folded to
`zext` earlier by `PhiSimplifyTool` — that's an optimization, not a
limitation.)

### Build matrix

Everything below assumes `app.c` starts with `#include "VMP.h"`:

    # base virtualization
    clang -mllvm -irobf-irvm app.c -lm -o app
    # + ① encryption (compile side: -irobf-irvm-enc)
    clang -mllvm -irobf-irvm -mllvm -irobf-irvm-enc app.c -lm -o app
    # + ② dynamic dispatch (-irobf-irvm-dispatch)
    clang -mllvm -irobf-irvm -mllvm -irobf-irvm-enc \
          -mllvm -irobf-irvm-dispatch app.c -lm -o app
    # + ③ nested VM: already on; `#define VMP_L2 0` in app.c to disable

Header knobs (define before `#include "VMP.h"`):

| knob | effect |
|---|---|
| `VMP_L2 0` | native evaluators instead of the level-2 VM (smaller code) |
| `VMP_NO_WEAK_HANDLE_CALL` | suppress the weak `handle_call` fallback (define your own) |
| `VMP_EXPOSE_EVAL` | keep native evaluators compiled (test oracle) |

Reproducible builds: `-mllvm -irobf-irvm-seed=N` pins the RNG (keys +
permutation).

## Tests

    cd llvm/lib/Transforms/Obfuscation/runtime
    cc test_vm_crypt.c -o t1 && ./t1                                            # 253 checks
    cc -I. test_vm_exec.c -o t2 -lm && ./t2                                     # 43 checks (L2 cores)
    cc -I. -DVMP_L2=0 test_vm_exec.c -o t2n -lm && ./t2n                        # 43 checks (native cores)
    cc -I. test_vm2.c -o t4 -lm && ./t4                                         # 84k L2 equivalence
    cc -I. -c test_vmp_header.c test_vmp_header_tu2.c && \
       c++ -I. -c test_vmp_header.cpp && \
       cc test_vmp_header*.o -o t5 -lm && ./t5                                  # header smoke (C+C++)

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
- Header-only mode inlines the runtime into every TU that includes `VMP.h`
  (~12 KB object growth per TU at -O0; unused internals strip out under
  optimization). `VMP_L2 0` halves that; the deprecated shims exist for old
  link commands.
