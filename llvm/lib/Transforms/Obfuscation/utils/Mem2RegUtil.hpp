// utils/Mem2RegUtil.hpp — LLVM 15.0.7
#pragma once
#include "llvm/IR/Function.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Dominators.h"
#include "llvm/Analysis/AssumptionCache.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Support/raw_ostream.h"
#include "llvm/Transforms/Utils/PromoteMemToReg.h" // PromoteMemToReg, isAllocaPromotable

namespace m2r {

    using namespace llvm;

    // 收集函数入口块里“可晋升”的 allocas（mem2reg 规则）
    inline void collectPromotableAllocas(Function &F, SmallVectorImpl<AllocaInst*> &Out) {
        Out.clear();
        if (F.isDeclaration()) return;
        BasicBlock &Entry = F.getEntryBlock();
        for (Instruction &I : Entry) {
            auto *AI = dyn_cast<AllocaInst>(&I);
            if (!AI) break; // 入口块里，alloca 一般都在最前面；遇到非 allocas 可提前结束
            if (!AI->isStaticAlloca()) continue;
            if (isAllocaPromotable(AI)) Out.push_back(AI);
        }
    }

    // 对单个函数执行 mem2reg。返回“被尝试晋升的 alloca 数”（为 0 代表无事可做）
    inline unsigned promoteFunction(Function &F, bool verbose = false) {
        SmallVector<AllocaInst*, 32> Allocas;
        collectPromotableAllocas(F, Allocas);
        if (Allocas.empty()) return 0;

        DominatorTree DT(F);
        AssumptionCache AC(F);
        if (verbose) {
            errs() << "[mem2reg] promoting " << Allocas.size()
                   << " allocas in @" << F.getName() << "\n";
        }
        PromoteMemToReg(Allocas, DT, &AC);
        return (unsigned)Allocas.size();
    }

    // 对整个模块执行 mem2reg（逐函数）。返回总计晋升的 alloca 数
    inline unsigned promoteModule(Module &M, bool verbose = false) {
        unsigned total = 0;
        for (Function &F : M) {
            total += promoteFunction(F, verbose);
        }
        if (verbose)
            errs() << "[mem2reg] total promoted allocas: " << total << "\n";
        return total;
    }

} // namespace m2r
