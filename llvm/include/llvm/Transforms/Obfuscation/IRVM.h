#ifndef OBFUSCATION_IRVM_H
#define OBFUSCATION_IRVM_H

#include "llvm/IR/PassManager.h"
#include "llvm/Passes/PassBuilder.h"

namespace llvm {

// IR-level virtualization pass: rewrites functions in section ".irvm" into
// vm_exec(code, size, args, num) stubs (see Obfuscation/utils/IRVMModuleTool.h
// and runtime/vm_exec.c). Enabled with -mllvm -irobf-irvm.
class IRVMPass : public PassInfoMixin<IRVMPass> {
public:
  PreservedAnalyses run(Module &M, ModuleAnalysisManager &AM);

  static llvm::StringRef name() { return "IRVMPass"; }
};

} // namespace llvm

#endif
