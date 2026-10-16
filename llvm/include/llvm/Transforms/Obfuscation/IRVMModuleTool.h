// utils/IRVMModuleTool.h
// LLVM 15 兼容（opaque pointers）
// 作用：对模块中 section=".irvm" 的函数进行：
//   (1) 规范化(PHI消解/ switch→if) + 句柄收集
//   (2) 字节码生成 + 全局落地 + 重写为 vm_exec 桩
// 失败/不支持时会打印原因并跳过，不影响其它函数。
//
// 硬化选项（SmallVMP 展望 ①②③，对应 cl::opt 见 IRVM.cpp）：
//   Encrypt  —— 密封字节码（IRVS 头 + xorshift128+ 密钥流），运行时
//               解密堆副本执行后再加密回去（Code 加密）
//   Dispatch —— 每模块随机操作码置换，opcode↔handler 映射不再固定
//               （动态分发的编译侧一半）
//   L2       —— 预留：解释器核心二级 VM（见 runtime/vm2_exec.c）

#pragma once
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/Support/raw_ostream.h"

#include <random>
#include <string>
#include <vector>
#include <cctype>

#include "utils/FuncRedirector.hpp"  // frx::rewriteToVMExec / VMExecOptions
#include "utils/GlobalInit.hpp"      // ginit::ensureDefinableGV / setBytes
#include "utils/IRVMTool.hpp"        // vmp::HandleCallTool
#include "utils/VMCodeGen.h"         // vmp::VMCodeGen
#include "utils/PhiSimplifyTool.h"   // vmp::PhiEliminateTool
#include "utils/SwitchToIf.h"        // vmp::SwitchToIfTool
#include "runtime/vm_crypt.h"        // seal/keystream/perm（与运行时共享）

namespace vmp {

class IRVMModuleTool {
public:
  struct Options {
    bool Encrypt = false;   // -mllvm -irobf-irvm-enc
    bool Dispatch = false;  // -mllvm -irobf-irvm-dispatch
    bool L2 = false;        // -mllvm -irobf-irvm-l2 (预留)
    uint64_t Seed = 0;      // -mllvm -irobf-irvm-seed=N（0 = 随机）
  };

  struct Stats {
    unsigned NumCandidates = 0;
    unsigned NumSkippedPre = 0;
    unsigned NumSkippedPostSimplify = 0;
    unsigned NumSkippedCodegen = 0;
    unsigned NumEmitted = 0;      // 成功生成 code 全局
    unsigned NumRewritten = 0;    // 成功改写为 vm_exec
    unsigned NumSealed = 0;       // 密封（加密）输出的函数数
    unsigned NumExceptions = 0;   // 捕获的异常次数
  };

  IRVMModuleTool() = default;
  explicit IRVMModuleTool(const Options &O) : Opt(O) {}

  /// 主入口：对 M 中所有 .irvm 函数执行转换。
  /// 发生错误会打印并跳过，不抛异常；返回是否有任何函数被成功改写。
  bool run(llvm::Module &M) {
    using namespace llvm;
    TheDL = &M.getDataLayout();

    initRNG(M);

    // 动态分发（展望②）：每模块生成一张随机操作码置换表并落盘为全局，
    // 发射侧 emitOp 按它重编码，运行侧 build_dispatch 据它查表。
    uint8_t OpPerm[VM_OP_N];
    llvm::GlobalVariable *PermGV = nullptr;
    if (Opt.Dispatch) {
      vm_perm_from_seed(NextKeySeed(), OpPerm);
      auto *PermArrTy = llvm::ArrayType::get(
          llvm::Type::getInt8Ty(M.getContext()), VM_OP_N);
      PermGV = ginit::ensureDefinableGV(M, "__irvm_op_perm", PermArrTy,
                                        llvm::Align(1));
      PermGV->setLinkage(llvm::GlobalValue::ExternalLinkage);
      PermGV->setConstant(true);
      PermGV->setSection(".rodata.irvm");
      if (!ginit::setBytes(PermGV,
                           llvm::ArrayRef<uint8_t>(OpPerm, VM_OP_N))) {
        llvm::errs() << "[irvm] ! FAILED to emit opcode perm table; "
                        "falling back to canonical opcodes\n";
        PermGV = nullptr;
      } else {
        llvm::errs() << "[irvm] opcode permutation table emitted\n";
      }
    }

    vmp::HandleCallTool handleTool;
    handleTool.bindModule(M);

    vmp::SwitchToIfTool switchTool;

    // 第一轮：规范化 + 收集
    for (Function &F : M) {
      if (!isCandidate(F)) continue;
      S.NumCandidates++;

      // 预检查：判断 VM 覆盖能力
      {
        std::string why;
        if (!isVMFriendly(F, *TheDL, why)) {
          llvm::errs() << "[irvm] skip (pre) " << F.getName() << " : " << why << "\n";
          S.NumSkippedPre++;
          continue;
        }
      }

      // try {
        // PHI 消解（含 select(0/1) 简化）
        vmp::PhiEliminateTool phiTool(/*simplifySelect01=*/true);
        (void)phiTool.run(F);
        auto st = phiTool.getStats();
        llvm::errs() << "[irvm] phi eliminated=" << st.NumPhiEliminated
                     << ", edges split=" << st.NumEdgesSplit
                     << ", select01=" << st.NumSelect01 << " @ " << F.getName() << "\n";

        // switch → if
        (void)switchTool.transform(F);

        // 二次检查：残留 PHI/SWITCH 或其它不支持 IR
        bool hasPhi = false, hasSwitch = false;
        for (Instruction &I : instructions(F)) {
          hasPhi    |= llvm::isa<llvm::PHINode>(I);
          hasSwitch |= llvm::isa<llvm::SwitchInst>(I);
          if (hasPhi || hasSwitch) break;
        }
        if (hasPhi || hasSwitch) {
          llvm::errs() << "[irvm] skip (post-simplify) " << F.getName()
                       << " : still has " << (hasPhi ? "PHI " : "")
                       << (hasSwitch ? "SWITCH " : "") << "\n";
          S.NumSkippedPostSimplify++;
          continue;
        }

        std::string why2;
        if (!isVMFriendly(F, *TheDL, why2)) {
          llvm::errs() << "[irvm] skip (post) " << F.getName() << " : " << why2 << "\n";
          S.NumSkippedPostSimplify++;
          continue;
        }

        // 收集调用/常量地址等句柄
        handleTool.collectFromFunction(F);

      // } catch (const std::exception &e) {
      //   llvm::errs() << "[irvm] exception in normalize/collect of " << F.getName()
      //                << " : " << e.what() << "\n";
      //   S.NumExceptions++;
      //   continue;
      // } catch (...) {
      //   llvm::errs() << "[irvm] unknown exception in normalize/collect of "
      //                << F.getName() << "\n";
      //   S.NumExceptions++;
      //   continue;
      // }
    }

    // 第二轮：生成字节码 + 落地 + 改写
    for (llvm::Function &F : M) {
      if (!isCandidate(F)) continue;

      // 再做一次防御性检查
      {
        std::string why;
        if (!isVMFriendly(F, *TheDL, why)) {
          llvm::errs() << "[irvm] skip (codegen) " << F.getName() << " : " << why << "\n";
          S.NumSkippedCodegen++;
          continue;
        }
      }

      // try {
        vmp::VMCodeGen gen(F, handleTool);
        gen.setOpPerm(Opt.Dispatch && PermGV ? OpPerm : nullptr);
        gen.run();
        const auto &bytes = gen.code();   // 可能已按置换重编码

        // -------- 密封（展望①②）: blob = IRVS 头 + [密文]载荷 --------
        std::vector<uint8_t> blob(bytes.begin(), bytes.end());
        unsigned sealFlags = 0;
        if (Opt.Encrypt)  sealFlags |= VM_SEAL_F_ENCRYPTED;
        if (Opt.Dispatch) sealFlags |= VM_SEAL_F_PERMUTED;
        const bool sealed = (sealFlags != 0);

        llvm::GlobalVariable *KeyGV = nullptr;
        if (sealed) {
          uint8_t key[16];
          if (Opt.Encrypt) {
            vm_derive_key16(key, NextKeySeed());

            std::string keyName = sanitizeName(F.getName()) + "_k";
            auto *KeyArrTy =
                llvm::ArrayType::get(llvm::Type::getInt8Ty(M.getContext()), 16);
            KeyGV = ginit::ensureDefinableGV(M, keyName.c_str(), KeyArrTy,
                                             llvm::Align(1));
            KeyGV->setLinkage(llvm::GlobalValue::ExternalLinkage);
            KeyGV->setConstant(true);
            KeyGV->setSection(".rodata.irvm");
            if (!ginit::setBytes(KeyGV, llvm::ArrayRef<uint8_t>(key, 16))) {
              llvm::errs() << "[irvm]   ! FAILED to initialize key for "
                           << F.getName() << "\n";
              S.NumSkippedCodegen++;
              continue;
            }
          }

          // blob = 头(明文 flags) + 载荷（已置换；加密则再叠加密钥流）
          blob.insert(blob.begin(), VM_SEAL_HDR_SIZE, 0);
          vm_seal_write_header(blob.data(), sealFlags);
          if (Opt.Encrypt) {
            vm_keystream(blob.data() + VM_SEAL_HDR_SIZE, bytes.size(), key);
            S.NumSealed++;
            llvm::errs() << "[irvm]   + sealed (encrypted + permuted)\n";
          } else {
            llvm::errs() << "[irvm]   + sealed (permuted opcodes)\n";
          }
        }

        auto *ArrTy = llvm::ArrayType::get(llvm::Type::getInt8Ty(M.getContext()),
                                           blob.size());
        std::string codeName = sanitizeName(F.getName()) + "_code";
        llvm::errs() << "[irvm] emit code global: " << codeName
                     << " (" << blob.size() << " bytes)\n";

        llvm::GlobalVariable *GV =
            ginit::ensureDefinableGV(M, codeName.c_str(), ArrTy, llvm::Align(1));
        GV->setLinkage(llvm::GlobalValue::ExternalLinkage);
        GV->setConstant(true);
        GV->setSection(".rodata.irvm");

        if (!ginit::setBytes(GV, blob)) {
          llvm::errs() << "[irvm]   ! FAILED to initialize bytes for "
                       << F.getName() << "\n";
          S.NumSkippedCodegen++;
          continue;
        } else {
          llvm::errs() << "[irvm]   + bytes initialized\n";
          S.NumEmitted++;
        }

        frx::VMExecOptions opt{};
        if (sealed) {
          opt.Sealed = true;      // 桩改调 vm_exec_sealed(code,size,key,perm,...)
          opt.KeyGV = KeyGV;      // 仅加密时非空
          opt.PermGV = (Opt.Dispatch && PermGV) ? PermGV : nullptr;
        }
        frx::rewriteToVMExec(F, GV, blob.size(), opt);
        llvm::errs() << "[irvm]   + rewritten to "
                     << (opt.Sealed ? "vm_exec_sealed" : "vm_exec")
                     << " stub: " << F.getName() << "\n";
        F.setSection("");   // idempotency: never re-virtualize the stub
        F.removeFnAttr(llvm::Attribute::OptimizeNone);
        S.NumRewritten++;

      // } catch (const std::exception &e) {
      //   llvm::errs() << "[irvm] exception in codegen/rewrite of " << F.getName()
      //                << " : " << e.what() << "\n";
      //   S.NumExceptions++;
      //   continue;
      // } catch (...) {
      //   llvm::errs() << "[irvm] unknown exception in codegen/rewrite of "
      //                << F.getName() << "\n";
      //   S.NumExceptions++;
      //   continue;
      // }
    }

    // 统一物化 handle
    // try {
      (void)handleTool.materializeHandle(M);
    // } catch (const std::exception &e) {
    //   llvm::errs() << "[irvm] exception in materializeHandle : " << e.what() << "\n";
    //   S.NumExceptions++;
    // } catch (...) {
    //   llvm::errs() << "[irvm] unknown exception in materializeHandle\n";
    //   S.NumExceptions++;
    // }

    return (S.NumRewritten > 0);
  }

  const Stats& getStats() const { return S; }

private:
  const llvm::DataLayout *TheDL = nullptr;
  Stats S{};
  Options Opt{};
  std::mt19937_64 RNG;

  // 种子：显式 -irobf-irvm-seed 优先（可重现构建）；否则 random_device 叉上
  // 模块标识 —— 不同模块不同密钥，同一模块每次构建也不同。（手写 FNV-1a
  // 哈希，兼容 getModuleIdentifier() 返回 StringRef / std::string 的树）
  void initRNG(llvm::Module &M) {
    uint64_t seed = Opt.Seed;
    if (seed == 0) {
      std::random_device rd;
      uint64_t midHash = 0xcbf29ce484222325ull;
      for (char c : M.getModuleIdentifier())
        midHash = (midHash ^ (uint64_t)(unsigned char)c) * 0x100000001b3ull;
      seed = ((uint64_t)rd() << 32) ^ rd() ^ midHash;
    }
    RNG.seed(seed);
  }
  uint64_t NextKeySeed() { return RNG(); }

  static bool isCandidate(const llvm::Function &F) {
    return !F.isDeclaration() && F.hasSection() && F.getSection() == ".irvm";
  }

  static std::string sanitizeName(llvm::StringRef S) {
    std::string R; R.reserve(S.size());
    for (char c : S) R.push_back(std::isalnum(static_cast<unsigned char>(c)) ? c : '_');
    return R;
  }

  /// 保守 VM 覆盖能力检查：不支持的 IR 直接拒绝
  static bool isVMFriendly(llvm::Function &F, const llvm::DataLayout &DL, std::string &Why) {
    using namespace llvm;
    if (F.isDeclaration() || !F.hasSection() || F.getSection() != ".irvm") {
      Why = "not in .irvm or declaration";
      return false;
    }

    for (Instruction &I : instructions(F)) {
      Type *Ty = I.getType();
      if (!Ty->isVoidTy() &&
          !(Ty->isIntegerTy() || Ty->isPointerTy() || Ty->isFloatTy() || Ty->isDoubleTy())) {
        if (Ty->isVectorTy() || Ty->isArrayTy() || Ty->isStructTy()) {
          Why = "aggregate or vector result not supported";
          return false;
        }
      }

      switch (I.getOpcode()) {
        case Instruction::Alloca: {
          auto &AI = cast<AllocaInst>(I);
          if (!AI.isStaticAlloca()) { Why = "variable-sized alloca not supported"; return false; }
          break;
        }
        case Instruction::Load: {
          auto &LI = cast<LoadInst>(I);
          if (LI.isAtomic()) { Why = "atomic load not supported"; return false; }
          if (LI.getType()->isVectorTy()) { Why = "vector load not supported"; return false; }
          break;
        }
        case Instruction::Store: {
          auto &SI = cast<StoreInst>(I);
          if (SI.isAtomic()) { Why = "atomic store not supported"; return false; }
          if (SI.getValueOperand()->getType()->isVectorTy()) { Why = "vector store not supported"; return false; }
          break;
        }

        // 白名单：VMCodeGen 已覆盖
        case Instruction::GetElementPtr:
        case Instruction::Trunc:
        case Instruction::ZExt:
        case Instruction::SExt:
        case Instruction::FPToUI:
        case Instruction::FPToSI:
        case Instruction::UIToFP:
        case Instruction::SIToFP:
        case Instruction::FPExt:
        case Instruction::FPTrunc:
        case Instruction::PtrToInt:
        case Instruction::IntToPtr:
        case Instruction::BitCast:
        case Instruction::Add:
        case Instruction::Sub:
        case Instruction::Mul:
        case Instruction::UDiv:
        case Instruction::SDiv:
        case Instruction::URem:
        case Instruction::SRem:
        case Instruction::Shl:
        case Instruction::LShr:
        case Instruction::AShr:
        case Instruction::And:
        case Instruction::Or:
        case Instruction::Xor:
        case Instruction::FAdd:
        case Instruction::FSub:
        case Instruction::FMul:
        case Instruction::FDiv:
        case Instruction::FRem:
        case Instruction::ICmp:
        case Instruction::FCmp:
        case Instruction::Br:   // this tree still has unified Br (=2)
        case Instruction::Switch:
        case Instruction::Ret:
        case Instruction::PHI:
          break;

        case Instruction::Call:
        case Instruction::CallBr: {
          auto &CB = cast<CallBase>(I);
          if (CB.isInlineAsm()) { Why = "inline asm not supported"; return false; }
          if (CB.isMustTailCall()) { Why = "musttail call not supported"; return false; }
          for (unsigned i = 0; i < CB.arg_size(); ++i) {
            Type *AT = CB.getArgOperand(i)->getType();
            if (AT->isVectorTy()) { Why = "vector arg not supported"; return false; }
          }
          break;
        }

        // 主动拒绝：EH / 原子 / 复杂控制流
        case Instruction::Invoke:
        case Instruction::LandingPad:
        case Instruction::Resume:
        case Instruction::CleanupRet:
        case Instruction::CatchRet:
        case Instruction::CatchPad:
        case Instruction::CleanupPad:
        case Instruction::CatchSwitch:
        case Instruction::IndirectBr:
        case Instruction::Fence:
        case Instruction::AtomicCmpXchg:
        case Instruction::AtomicRMW:
        case Instruction::VAArg:
        case Instruction::Freeze:
          Why = "advanced/eh/atomic/control-flow not supported";
          return false;

        default:
          Why = "unsupported opcode: " + std::string(I.getOpcodeName());
          return false;
      }
    }
    return true;
  }
};

} // namespace vmp

/* 使用示例（在你的 pass 或任何调用点）：
   vmp::IRVMModuleTool tool;
   bool changed = tool.run(M);
   auto st = tool.getStats();
   llvm::errs() << "changed=" << changed
                << " candidates=" << st.NumCandidates
                << " emitted=" << st.NumEmitted
                << " rewritten=" << st.NumRewritten
                << " skipped(pre)=" << st.NumSkippedPre
                << " skipped(post)=" << st.NumSkippedPostSimplify
                << " skipped(codegen)=" << st.NumSkippedCodegen
                << " exceptions=" << st.NumExceptions << "\n";
*/
