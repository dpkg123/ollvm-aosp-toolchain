// PhiEliminateTool.hpp — header-only, LLVM 15.0.7
#pragma once
#include <map>
#include <utility>

#include "llvm/IR/Function.h"
#include "llvm/IR/BasicBlock.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/CFG.h"
#include "llvm/IR/Constants.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/Transforms/Utils/BasicBlockUtils.h" // SplitEdge

namespace vmp {

class PhiEliminateTool {
public:
  struct Stats {
    unsigned NumPhiEliminated = 0;
    unsigned NumEdgesSplit    = 0;
    unsigned NumSelect01      = 0;
  };

  /// simplifySelect01: 先把 `select i1 %c, i32 1, i32 0` → `zext i1 %c to i32`
  explicit PhiEliminateTool(bool simplifySelect01 = true)
      : SimplifySelect01(simplifySelect01) {}

  /// 对单个函数执行：先可选 select(0/1) 归约，再消除所有 PHI
  /// 返回是否修改 IR
  bool run(llvm::Function &F) {
    bool Changed = false;
    if (SimplifySelect01)
      Changed |= foldSimpleSelect01(F);
    Changed |= eliminateAllPhi(F);
    return Changed;
  }

  const Stats& getStats() const { return S; }

private:
  bool SimplifySelect01;
  Stats S;

  // --- pass 1: 把常见的 select 0/1 变成 zext/sext，避免 VM 不支持 select ---
  bool foldSimpleSelect01(llvm::Function &F) {
    bool Changed = false;
    llvm::SmallVector<llvm::SelectInst*, 16> Work;
    for (llvm::BasicBlock &BB : F)
      for (llvm::Instruction &I : BB)
        if (auto *SI = llvm::dyn_cast<llvm::SelectInst>(&I))
          Work.push_back(SI);

    for (auto *SI : Work) {
      llvm::Value *Cond = SI->getCondition();
      llvm::Type  *Ty   = SI->getType();
      auto *CTrue  = llvm::dyn_cast<llvm::ConstantInt>(SI->getTrueValue());
      auto *CFalse = llvm::dyn_cast<llvm::ConstantInt>(SI->getFalseValue());
      if (!CTrue || !CFalse) continue;
      if (!Cond->getType()->isIntegerTy(1)) continue;
      // 形如 select i1 %c, iN 1, iN 0 或 select i1 %c, iN 0, iN 1
      if (CTrue->isOne() && CFalse->isZero() && Ty->isIntegerTy()) {
        // %res = zext i1 %c to iN
        llvm::IRBuilder<> B(SI);
        llvm::Value *Z = B.CreateZExt(Cond, Ty, SI->getName());
        SI->replaceAllUsesWith(Z);
        SI->eraseFromParent();
        ++S.NumSelect01;
        Changed = true;
      } else if (CTrue->isZero() && CFalse->isOne() && Ty->isIntegerTy()) {
        // %res = zext (not %c) to iN  == 或 1 - zext(%c)
        llvm::IRBuilder<> B(SI);
        llvm::Value *NotC = B.CreateNot(Cond, "notc");
        llvm::Value *Z = B.CreateZExt(NotC, Ty, SI->getName());
        SI->replaceAllUsesWith(Z);
        SI->eraseFromParent();
        ++S.NumSelect01;
        Changed = true;
      }
      // 其他复杂 select 不动（避免改变 FP NaN/异常语义）
    }
    return Changed;
  }

  // --- pass 2: 消除 PHI（Demote to stack），自动拆分关键边 ---
  bool eliminateAllPhi(llvm::Function &F) {
    bool Changed = false;

    // 为避免在遍历中修改迭代器：先收集所有 PHI
    llvm::SmallVector<llvm::PHINode*, 32> AllPhis;
    for (llvm::BasicBlock &BB : F) {
      for (llvm::Instruction &I : BB) {
        if (auto *PN = llvm::dyn_cast<llvm::PHINode>(&I))
          AllPhis.push_back(PN);
        else
          break; // PHI 只会在块首连续出现
      }
    }

    if (AllPhis.empty()) return false;

    // 维护边分裂缓存：<Pred, Succ> → 新块；避免重复 SplitEdge
    std::map<std::pair<llvm::BasicBlock*, llvm::BasicBlock*>, llvm::BasicBlock*> EdgeSplitCache;

    // 入口块：在此放 alloca
    llvm::BasicBlock &Entry = F.getEntryBlock();
    llvm::Instruction *AllocaIP = &*Entry.getFirstInsertionPt();

    for (llvm::PHINode *PN : AllPhis) {
      if (!PN || PN->use_empty()) { // 无 uses 直接删
        if (PN) { PN->eraseFromParent(); ++S.NumPhiEliminated; Changed = true; }
        continue;
      }

      // 1) 为该 PHI 创建栈槽
      auto *AI = new llvm::AllocaInst(PN->getType(), 0, PN->getName() + ".phi.spill", AllocaIP);

      // 2) 对每条 incoming 边：在边上插入 store
      llvm::BasicBlock *DestBB = PN->getParent();
      const unsigned N = PN->getNumIncomingValues();

      for (unsigned i = 0; i < N; ++i) {
        llvm::Value      *V    = PN->getIncomingValue(i);
        llvm::BasicBlock *Pred = PN->getIncomingBlock(i);

        llvm::BasicBlock *InsertBB = Pred;

        // 判断是否关键边：Pred 的后继多于 1，且其中之一是 DestBB
        auto *TI = Pred->getTerminator();
        const unsigned Succs = TI->getNumSuccessors();
        if (Succs > 1) {
          auto Key = std::make_pair(Pred, DestBB);
          auto It = EdgeSplitCache.find(Key);
          if (It != EdgeSplitCache.end()) {
            InsertBB = It->second;
          } else {
            // 拆分 Pred->DestBB 这条边
            llvm::BasicBlock *NewEdgeBB = llvm::SplitEdge(Pred, DestBB);
            InsertBB = NewEdgeBB;
            EdgeSplitCache.emplace(Key, NewEdgeBB);
            ++S.NumEdgesSplit;
          }
        } else {
          // 单后继：直接在 Pred 末尾前插入
          // （无需拆边）
        }

        // 插入 store（在 InsertBB 的终结指令前）
        llvm::IRBuilder<> B(InsertBB->getTerminator());
        // V 可能是 poison/undef，直接 store 也保持语义
        B.CreateStore(V, AI);
      }

      // 3) 在目标块插入 load，并替换 PHI uses
      llvm::Instruction *IP = DestBB->getFirstNonPHI();
      llvm::IRBuilder<> BL(IP);
      llvm::LoadInst *Ld = BL.CreateLoad(PN->getType(), AI, PN->getName() + ".ld");
      PN->replaceAllUsesWith(Ld);

      // 4) 删除原 PHI
      PN->eraseFromParent();
      ++S.NumPhiEliminated;
      Changed = true;
    }

    return Changed;
  }
};

} // namespace vmp
