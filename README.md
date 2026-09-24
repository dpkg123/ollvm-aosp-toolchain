# The LLVM Compiler Infrastructure (OLLVM AOSP Toolchain)

## Disclaimer

**IMPORTANT NOTICE:**
This repository is an **independent, personal research project** and is **NOT** affiliated with, endorsed by, or an official release of Google, the Android Open Source Project (AOSP), or the upstream LLVM Project.

Due to the highly complex nature of integrating diverse upstream codebases (including AOSP toolchain branches, upstream LLVM, and third-party obfuscation implementations), **THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED OR IMPLIED.** 

The maintainer **DOES NOT** provide any form of technical support, issue resolution, bug fixes, or stability guarantees for compilation failures, runtime crashes, kernel panics, or regressions. Users must use, modify, and build this repository entirely at their own discretion and risk.

---

## Introduction

Obfuscator-LLVM (OLLVM) is an open-source extension based on the LLVM compiler framework, primarily designed for program code obfuscation and intellectual property protection.

OLLVM operates at the LLVM IR optimization stage via custom Pass mechanisms, introducing transformations (such as control flow flattening, bogus control flow, and instruction substitution) to substantially raise the bar for reverse engineering binary executables.

The primary objective of this repository is to integrate modern obfuscation passes into toolchains that closely align with the [AOSP Prebuilt C/C++ Toolchain](https://android.googlesource.com/platform/prebuilts/clang/host/linux-x86).

---

## Upstream & Code Sources

- [AOSP llvm-project](https://android.googlesource.com/toolchain/llvm-project/)
- [Upstream llvm-project](https://github.com/llvm/llvm-project)
- [AOSP llvm_android](https://android.googlesource.com/toolchain/llvm_android)
- [Arkari](https://github.com/KomiMoe/Arkari) (Obfuscation pass for Clang 21+)
- [ollvm-adaplite-clang](https://github.com/ollvm-adaplite/ollvm-clang) (Obfuscation pass for Clang 21)

---

## Current Status

- [x] Build with GCC (`clang` + `lld`)
- [x] Self-hosted toolchain bootstrap
- [x] Build Rust toolchain (refer to [Rust Support](#rust-support))
- [x] Build and execute standard userland binaries
- [x] Build and run Rust binaries compiled with this toolchain (tested samples with Arkari)
- [ ] Build Android Linux kernel and verify runtime stability (*Untested*)
- [ ] Run complete LLVM test suite (*Untested*)

---

## Branches and Build Targets

Please select the corresponding branch according to your targeted AOSP revision and LLVM/Clang version:

| Branch Family | Target LLVM/Clang Version | Description |
| :--- | :--- | :--- |
| `ollvm-r614150-clang23*` | Clang 23 | Based on AOSP `r614150` toolchain baseline (includes standard, rebase, and `+omp` variants). |
| `ollvm-r596125-clang22*` | Clang 22 | Based on AOSP `r596125` toolchain baseline (includes standard, rebase, and `+omp` variants). |
| `ollvm-r574158-clang21*` | Clang 21 | Based on AOSP `r574158` toolchain baseline (includes standard and rebase variants). |
| `ollvm-r450784-clang14` | Clang 14 | Legacy baseline branch for earlier Android toolchain compatibility. |

> **Note:**
> - Branches designated with `+omp` include additional OpenMP runtime / compiler support.
> - The `main` branch serves primarily as a landing and meta-branch; checkout the specific `ollvm-*` branch matching your requirements prior to compilation.

---

## Rust Support

Bootstrapping `rustc` stage1 compiler artifacts with `ollvm-adaplite-clang` is known to abort under Hikari pass execution:

```text
Building stage1 compiler artifacts (stage0 -> stage1, x86_64-unknown-linux-gnu)
...
Compiling unwind v0.0.0 (/workspace/llvm/llvm/out/src/rust/library/unwind)
std::mt19937_64 seeded with current timestamp: 1772943110852
Initializing Hikari Core with Revision ID:e8b3b881f0e5103a11ddb6eb0a3ea7b9e78fa657
Running Hikari On memchr.3c5f4c5b136ccbdf-cgu.0
Doing Post-Run Cleanup
Hikari Out
Spend Time: 0.0005970s
rustc exited with signal: 6 (SIGABRT) (core dumped)
```

### Workaround / Requirement:

When bootstrapping Rust using Arkari, it is required to drop i386 target detection in compiler-rt.

​## License

​This project adheres to the upstream licenses of the underlying LLVM / AOSP projects (Apache 2.0 License with LLVM Exceptions). Individual obfuscation extensions retain the licensing terms of their respective upstream repositories.
