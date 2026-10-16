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

// ---- 硬化开关（SmallVMP 展望 ①②③）------------------------------------
// ① Code 加密：字节码以密文落盘（IRVS 头 + xorshift128+ 密钥流），
//    vm_exec_sealed 解密堆副本执行后再加密回去。
static cl::opt<bool>
    EnableIRVMEnc("irobf-irvm-enc", cl::init(false), cl::NotHidden,
                  cl::desc("IRVM: seal bytecode (encrypt at rest, "
                           "decrypt/re-encrypt at runtime)."));
// ② 动态分发：每模块随机操作码置换，opcode 字节在构建时重编码，
//    运行时由置换表构建 handler 映射，不再固定。
static cl::opt<bool>
    EnableIRVMDispatch("irobf-irvm-dispatch", cl::init(false), cl::NotHidden,
                       cl::desc("IRVM: per-build opcode permutation "
                                "(dynamic handler dispatch)."));
// ③ 嵌套 VM：解释器算术/比较/类型转换核心由二级 VM 解释执行
//    （runtime/vm2_exec.c）。
static cl::opt<bool>
    EnableIRVML2("irobf-irvm-l2", cl::init(false), cl::NotHidden,
                 cl::desc("IRVM: run interpreter cores on the level-2 VM."));
// 固定种子（可重现构建/测试）；0 = 每次随机。
static cl::opt<unsigned long long>
    IRVMSeed("irobf-irvm-seed", cl::init(0), cl::NotHidden,
             cl::desc("IRVM: pin the RNG seed for enc keys / opcode "
                      "permutation (0 = random)."));

PreservedAnalyses IRVMPass::run(Module &M, ModuleAnalysisManager &AM) {
  if (!EnableIRVM) {
    return PreservedAnalyses::all();
  }

  vmp::IRVMModuleTool::Options Opt;
  Opt.Encrypt = EnableIRVMEnc;
  Opt.Dispatch = EnableIRVMDispatch;
  Opt.L2 = EnableIRVML2;
  Opt.Seed = (uint64_t)IRVMSeed;

  vmp::IRVMModuleTool Tool(Opt);
  bool Changed = Tool.run(M);

  const auto &S = Tool.getStats();
  errs() << "[irvm] summary candidates=" << S.NumCandidates
         << " emitted=" << S.NumEmitted << " rewritten=" << S.NumRewritten
         << " sealed=" << S.NumSealed
         << " skipped(pre)=" << S.NumSkippedPre
         << " skipped(post)=" << S.NumSkippedPostSimplify
         << " skipped(codegen)=" << S.NumSkippedCodegen << "\n";

  return Changed ? PreservedAnalyses::none() : PreservedAnalyses::all();
}
