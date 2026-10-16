#include "llvm/Transforms/Obfuscation/IRVM.h"
#include "llvm/IR/Module.h"
#include "llvm/Support/CommandLine.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Obfuscation/IRVMModuleTool.h"

using namespace llvm;

#define DEBUG_TYPE "irvm"

static cl::opt<bool>
    EnableIRVM("irobf-irvm", cl::init(false), cl::NotHidden,
               cl::desc("Enable IR-level virtualization (section .irvm)."));

PreservedAnalyses IRVMPass::run(Module &M, ModuleAnalysisManager &AM) {
  if (!EnableIRVM) {
    return PreservedAnalyses::all();
  }

  vmp::IRVMModuleTool Tool;
  bool Changed = Tool.run(M);

  const auto &S = Tool.getStats();
  errs() << "[irvm] summary candidates=" << S.NumCandidates
         << " emitted=" << S.NumEmitted << " rewritten=" << S.NumRewritten
         << " skipped(pre)=" << S.NumSkippedPre
         << " skipped(post)=" << S.NumSkippedPostSimplify
         << " skipped(codegen)=" << S.NumSkippedCodegen << "\n";

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
