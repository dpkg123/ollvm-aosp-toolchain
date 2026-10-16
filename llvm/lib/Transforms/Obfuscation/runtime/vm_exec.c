// vm_exec.c — DEPRECATED shim: the L1 interpreter now lives in VMP.h
// (header-only runtime). This file remains so old build commands keep
// working:
//
//     clang -mllvm -irobf-irvm app.c vm_exec.c -lm -o app      (old, still OK)
//     clang -mllvm -irobf-irvm app.c -lm -o app                (new: nothing
//                                                              extra to link,
//                                                              just include
//                                                              VMP.h in app.c)
#include "VMP.h"
