// VMCodeGen.h/cc — 基于 HandleCallTool 的按 Function 级字节码生成器
// LLVM 15 兼容（opaque pointers）
//
// 常量指针/常量 GEP 等：在首次用到时发出 OP_CALL(id=const-kid, dynN=0) 物化到 slot，避免 VM 端理解复杂常量。
// 只对“指针类型 & 可折叠为常量地址”的值启用；整型/浮点常量仍内嵌编码即可。

#include "HandleCallTool.h"              // 你的工具类（命名空间 vmp）
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/ADT/Optional.h"
#include "llvm/ADT/SmallPtrSet.h"
#include "llvm/Support/raw_ostream.h"

#include <vector>
#include <map>
#include <cassert>
#include <cstdint>

namespace vmp {

// ===== 字节码定义（与 VM 端对齐） =====
enum : uint8_t {
  OP_ALLOCA = 0x01,
  OP_LOAD   = 0x02,
  OP_STORE  = 0x03,
  OP_GEP    = 0x05,
  OP_CMP    = 0x06,
  OP_CAST   = 0x07,
  OP_BR     = 0x08,
  OP_CALL   = 0x09,
  OP_RET    = 0x0A,
  OP_ARITH  = 0x10,   // 统一“基本算术”
  OP_PARAMMAP = 0x11,
};

// 值编码
enum : uint8_t { VT_CONST = 0, VT_SLOT = 1 };
enum : uint8_t { CK_INT=0, CK_PTR=1, CK_F32=2, CK_F64=3 };

// 算术子操作与类型类
enum : uint8_t {
  AR_ADD, AR_SUB, AR_MUL,
  AR_UDIV, AR_SDIV, AR_UREM, AR_SREM,
  AR_SHL, AR_LSHR, AR_ASHR,
  AR_AND, AR_OR, AR_XOR,
  AR_FADD, AR_FSUB, AR_FMUL, AR_FDIV, AR_FREM,
};
enum : uint8_t { TK_INT=0, TK_FP=1 };

// ==== 小端打包 ====
static inline void p8 (std::vector<uint8_t>& out, uint8_t v)  { out.push_back(v); }
static inline void p32(std::vector<uint8_t>& out, uint32_t v) {
  out.push_back(uint8_t(v      )); out.push_back(uint8_t(v>>8));
  out.push_back(uint8_t(v>>16 )); out.push_back(uint8_t(v>>24));
}
static inline void p64(std::vector<uint8_t>& out, uint64_t v) {
  for (int i=0;i<8;i++) out.push_back(uint8_t(v>>(i*8)));
}

// ===== 等价常量判定（保留，用于 CALL 的动态参数过滤） =====
static bool isConstLike(llvm::Value *V) {
  using namespace llvm;
  if (isa<Constant>(V)) return true;
  if (auto *BC = dyn_cast<BitCastInst>(V))    return isConstLike(BC->getOperand(0));
  if (auto *PTI= dyn_cast<PtrToIntInst>(V))   return isConstLike(PTI->getOperand(0));
  if (auto *ITP= dyn_cast<IntToPtrInst>(V))   return isConstLike(ITP->getOperand(0));
  if (auto *GEP= dyn_cast<GetElementPtrInst>(V)) {
    if (!isConstLike(GEP->getPointerOperand())) return false;
    for (auto Idx = GEP->idx_begin(); Idx != GEP->idx_end(); ++Idx)
      if (!isa<Constant>(*Idx)) return false;
    return true;
  }
  return false;
}

// ==== 翻译器 ====
class VMCodeGen {
public:
  VMCodeGen(llvm::Function &F, vmp::HandleCallTool &tool)
  : F(F), M(*F.getParent()), C(M.getContext()), DL(&M),
    Tool(tool), PtrSize(DL.getPointerSize()) {}

  void run() {
    expandConstantExprs();
    enterFunction();      // 分配返回槽 & 形参槽；收集参数映射
    emitParamMap();       // 在函数字节码最前写入参数映射
    for (auto &BB : F) {
      markBB(&BB);
      for (auto &I : BB) translateInst(I);
    }
    patchBranches();
  }

  const std::vector<uint8_t>& code() const { return Code; }
  void dumpHex() const {
    for (auto b: Code) { llvm::errs() << (int)b << " "; } llvm::errs() << "\n";
  }

private:
  // 上下文
  llvm::Function &F;
  llvm::Module &M;
  llvm::LLVMContext &C;
  llvm::DataLayout DL;
  vmp::HandleCallTool &Tool;
  unsigned PtrSize;

  // 状态
  std::vector<uint8_t> Code;
  std::map<const llvm::Value*, uint32_t>       SlotOf;
  std::map<const llvm::BasicBlock*, uint32_t>  AddrOfBB;
  struct Fixup { uint32_t pos; const llvm::BasicBlock* target; };
  std::vector<Fixup> BrFixups;
  uint32_t CurrDataOffset = 0;

  struct ParamDesc { uint32_t off; uint32_t size; };
  std::vector<ParamDesc> ParamMap;

  // 已物化（插过一次 OP_CALL const）的“指针常量值”
  llvm::SmallPtrSet<const llvm::Value*, 16> ConstPtrDone;

  // --------- 常量表达式展开：把 ConstantExpr 换成指令，放到使用点之前 ---------
  void expandConstantExprs() {
    for (auto &BB : F) {
      for (auto II = BB.begin(); II != BB.end(); ++II) {
        llvm::Instruction *I = &*II;
        for (unsigned oi=0; oi<I->getNumOperands(); ++oi) {
          if (auto *CE = llvm::dyn_cast<llvm::ConstantExpr>(I->getOperand(oi))) {
            llvm::Instruction *NewI = CE->getAsInstruction();
            NewI->insertBefore(I);
            I->setOperand(oi, NewI);
          }
        }
      }
    }
  }

  // --------- 函数入口：为返回值/形参分配槽位，并记录 ParamMap ---------
  void enterFunction() {
    if (!F.getReturnType()->isVoidTy())
      allocSlot(&F, F.getReturnType()); // 约定：返回槽放最前

    ParamMap.clear();
    for (auto &A : F.args()) {
      uint32_t off = allocSlot(&A, A.getType());
      uint32_t sz  = (uint32_t)DL.getTypeAllocSize(A.getType());
      ParamMap.push_back({off, sz});
    }
  }

  // --------- OP_PARAMMAP ---------
  void emitParamMap() {
    p8(Code, OP_PARAMMAP);
    p32(Code, (uint32_t)ParamMap.size());
    for (auto &pd : ParamMap) { p32(Code, pd.off); p32(Code, pd.size); }
  }

  // --------- data-slot 分配 ---------
  uint32_t allocSlot(const llvm::Value* V, llvm::Type* Ty) {
    if (auto it = SlotOf.find(V); it!=SlotOf.end()) return it->second;
    uint32_t off = CurrDataOffset;
    uint64_t sz  = DL.getTypeAllocSize(Ty);
    CurrDataOffset += (uint32_t)sz;
    SlotOf[V] = off;
    return off;
  }

  // --------- 指针常量“现场物化”：插入 OP_CALL(id=const) 写到它的 slot ---------
  void materializeConstPtrIfPossible(llvm::Value *V) {
    if (!V->getType()->isPointerTy()) return;
    if (ConstPtrDone.count(V)) return;

    if (llvm::Constant *C8 = Tool.tryMakeConstPtrExpr(V)) {
      uint64_t kid = Tool.ensureConstAddrId(C8);         // ← 为该常量地址拿到 handle_call id
      uint32_t dst = allocSlot(V, V->getType());         //   物化结果写回它自己的 slot

      p8(Code, OP_CALL);
      p64(Code, kid);
      p32(Code, dst);            // dst = slot
      p32(Code, 0);              // dynN = 0

      ConstPtrDone.insert(V);
    }
  }

  // --------- 值编码（常量/槽位）---------
  void encodeValue(llvm::Value* V) {
    using namespace llvm;

    // 指针常量：优先确保已物化到 slot，然后按 slot 编码
    if (V->getType()->isPointerTy()) {
      materializeConstPtrIfPossible(V);
      uint32_t off = allocSlot(V, V->getType());
      p8(Code, VT_SLOT); p32(Code, off);
      return;
    }

    // 纯整型/浮点常量 → 直接内嵌
    if (auto *CI = dyn_cast<ConstantInt>(V)) {
      p8(Code, VT_CONST); p8(Code, CK_INT);
      uint64_t v = CI->getValue().zextOrTrunc(64).getZExtValue();
      p32(Code, 8); p64(Code, v); return;
    }
    if (auto *CF = dyn_cast<ConstantFP>(V)) {
      if (CF->getType()->isDoubleTy()) {
        p8(Code, VT_CONST); p8(Code, CK_F64); p32(Code, 8);
        uint64_t bits = CF->getValueAPF().bitcastToAPInt().getZExtValue();
        p64(Code, bits); return;
      } else if (CF->getType()->isFloatTy()) {
        p8(Code, VT_CONST); p8(Code, CK_F32); p32(Code, 4);
        uint32_t bits = CF->getValueAPF().bitcastToAPInt().getZExtValue();
        p32(Code, bits); return;
      }
    }

    // 其它常量（非指针）→ 放到 slot（极少出现）
    if (isa<Constant>(V)) {
      uint32_t off = allocSlot(V, V->getType());
      p8(Code, VT_SLOT); p32(Code, off); return;
    }

    // 非常量 → slot
    uint32_t off = allocSlot(V, V->getType());
    p8(Code, VT_SLOT); p32(Code, off);
  }

  // --------- 基本块打点 ---------
  void markBB(const llvm::BasicBlock* BB) { AddrOfBB[BB] = (uint32_t)Code.size(); }

  // --------- 指令分发 ---------
  void translateInst(llvm::Instruction &I) {
    using namespace llvm;
    switch (I.getOpcode()) {
      case Instruction::Alloca:  return t_allo(cast<AllocaInst>(I));
      case Instruction::Load:    return t_load(cast<LoadInst>(I));
      case Instruction::Store:   return t_store(cast<StoreInst>(I));
      case Instruction::Br:      return t_br(cast<BranchInst>(I));
      case Instruction::Ret:     return t_ret(cast<ReturnInst>(I));
      case Instruction::BitCast:
      case Instruction::PtrToInt:
      case Instruction::IntToPtr:
      case Instruction::Trunc:
      case Instruction::ZExt:
      case Instruction::SExt:
      case Instruction::FPToUI:
      case Instruction::FPToSI:
      case Instruction::UIToFP:
      case Instruction::SIToFP:
      case Instruction::FPExt:
      case Instruction::FPTrunc:
        return t_cast(cast<CastInst>(I));
      default: break;
    }
    if (auto *BO = llvm::dyn_cast<llvm::BinaryOperator>(&I)) return t_binop(*BO);
    if (auto *CI = llvm::dyn_cast<llvm::CmpInst>(&I))        return t_cmp(*CI);
    if (auto *G  = llvm::dyn_cast<llvm::GetElementPtrInst>(&I)) return t_gep(*G);
    if (auto *CB = llvm::dyn_cast<llvm::CallBase>(&I))       return t_call(*CB);

    llvm::errs() << "[VMCodeGen] unsupported inst: " << I << "\n";
  }

  void t_allo(llvm::AllocaInst &I) {
    uint32_t res_off = allocSlot(&I, I.getType());
    uint64_t area_sz = DL.getTypeAllocSize(I.getAllocatedType());
    p8(Code, OP_ALLOCA); p32(Code, res_off); p32(Code, (uint32_t)area_sz);
  }

  void t_load(llvm::LoadInst &I) {
    // 先确保指针操作数如果是“常量可折叠地址”，被物化到了它的 slot
    materializeConstPtrIfPossible(I.getPointerOperand());

    uint32_t dst = allocSlot(&I, I.getType());
    p8(Code, OP_LOAD); p32(Code, dst);
    encodeValue(I.getPointerOperand());
  }

  void t_store(llvm::StoreInst &I) {
    // 两个操作数都可能是指针 & 常量地址
    if (I.getValueOperand()->getType()->isPointerTy())
      materializeConstPtrIfPossible(I.getValueOperand());
    materializeConstPtrIfPossible(I.getPointerOperand());

    p8(Code, OP_STORE);
    encodeValue(I.getValueOperand());
    encodeValue(I.getPointerOperand());
  }

  // ===== 基本算术统一为 OP_ARITH =====
  struct ArithEnc { uint8_t sub; uint8_t tk; uint8_t bits; };
  llvm::Optional<ArithEnc> mapLLVMArith(const llvm::Instruction &I) {
    using namespace llvm;
    ArithEnc E{};
    switch (I.getOpcode()) {
      // 整数算术
      case Instruction::Add:  E.sub=AR_ADD;  E.tk=TK_INT; break;
      case Instruction::Sub:  E.sub=AR_SUB;  E.tk=TK_INT; break;
      case Instruction::Mul:  E.sub=AR_MUL;  E.tk=TK_INT; break;
      case Instruction::UDiv: E.sub=AR_UDIV; E.tk=TK_INT; break;
      case Instruction::SDiv: E.sub=AR_SDIV; E.tk=TK_INT; break;
      case Instruction::URem: E.sub=AR_UREM; E.tk=TK_INT; break;
      case Instruction::SRem: E.sub=AR_SREM; E.tk=TK_INT; break;
      // 位移/位运算
      case Instruction::Shl:  E.sub=AR_SHL;  E.tk=TK_INT; break;
      case Instruction::LShr: E.sub=AR_LSHR; E.tk=TK_INT; break;
      case Instruction::AShr: E.sub=AR_ASHR; E.tk=TK_INT; break;
      case Instruction::And:  E.sub=AR_AND;  E.tk=TK_INT; break;
      case Instruction::Or:   E.sub=AR_OR;   E.tk=TK_INT; break;
      case Instruction::Xor:  E.sub=AR_XOR;  E.tk=TK_INT; break;
      // 浮点算术
      case Instruction::FAdd: E.sub=AR_FADD; E.tk=TK_FP;  break;
      case Instruction::FSub: E.sub=AR_FSUB; E.tk=TK_FP;  break;
      case Instruction::FMul: E.sub=AR_FMUL; E.tk=TK_FP;  break;
      case Instruction::FDiv: E.sub=AR_FDIV; E.tk=TK_FP;  break;
      case Instruction::FRem: E.sub=AR_FREM; E.tk=TK_FP;  break;
      default: return llvm::None;
    }
    if (E.tk == TK_INT) {
      if (!I.getType()->isIntegerTy()) return llvm::None;
      unsigned bw = I.getType()->getIntegerBitWidth();
      if (bw==8||bw==16||bw==32||bw==64) E.bits = (uint8_t)bw;
      else return llvm::None;
    } else {
      if      (I.getType()->isFloatTy())  E.bits = 32;
      else if (I.getType()->isDoubleTy()) E.bits = 64;
      else return llvm::None;
    }
    return E;
  }

  void t_binop(llvm::BinaryOperator &I) {
    auto Enc = mapLLVMArith(I);
    if (!Enc) { llvm::errs() << "[VMCodeGen] unsupported binop for ARITH: " << I << "\n"; return; }
    uint32_t dst = allocSlot(&I, I.getType());
    p8(Code, OP_ARITH); p8(Code, Enc->sub); p8(Code, Enc->tk); p8(Code, Enc->bits);
    p32(Code, dst);
    encodeValue(I.getOperand(0));
    encodeValue(I.getOperand(1));
  }

  void t_cmp(llvm::CmpInst &I) {
    uint32_t dst = allocSlot(&I, I.getType());
    p8(Code, OP_CMP);
    p8(Code, (uint8_t)I.getPredicate());
    p32(Code, dst);
    encodeValue(I.getOperand(0));
    encodeValue(I.getOperand(1));
  }

  void t_cast(llvm::CastInst &I) {
    // 若 cast 结果是指针，且能折成常量地址 → 直接物化，不再下发 OP_CAST
    if (I.getType()->isPointerTy()) {
      materializeConstPtrIfPossible(&I);
      if (ConstPtrDone.count(&I)) return;
    }

    uint32_t dst = allocSlot(&I, I.getType());
    p8(Code, OP_CAST);
    p8(Code, (uint8_t)I.getOpcode());
    p32(Code, dst);
    encodeValue(I.getOperand(0));
  }

  void t_gep(llvm::GetElementPtrInst &I) {
    // 若 GEP 全常量，可折叠为常量地址 → 直接物化，不再下发 OP_GEP
    materializeConstPtrIfPossible(&I);
    if (ConstPtrDone.count(&I)) return;

    // 否则正常发 OP_GEP；但先保证 base 若为常量地址已物化
    materializeConstPtrIfPossible(I.getPointerOperand());

    uint32_t dst = allocSlot(&I, I.getType());
    p8(Code, OP_GEP);
    p32(Code, dst);
    encodeValue(I.getPointerOperand());
    unsigned n = I.getNumIndices();
    p32(Code, n);
    for (auto Idx = I.idx_begin(); Idx != I.idx_end(); ++Idx) encodeValue(*Idx);
  }

  void t_br(llvm::BranchInst &I) {
    p8(Code, OP_BR);
    if (I.isUnconditional()) {
      p8(Code, 0);
      uint32_t pos = (uint32_t)Code.size(); p32(Code, 0);
      BrFixups.push_back({pos, I.getSuccessor(0)});
    } else {
      p8(Code, 1);
      encodeValue(I.getCondition());
      uint32_t posT = (uint32_t)Code.size(); p32(Code, 0);
      BrFixups.push_back({posT, I.getSuccessor(0)});
      uint32_t posF = (uint32_t)Code.size(); p32(Code, 0);
      BrFixups.push_back({posF, I.getSuccessor(1)});
    }
  }

  void t_ret(llvm::ReturnInst &I) {
    p8(Code, OP_RET);
    if (I.getNumOperands()==0) {
      p8(Code, VT_CONST); p8(Code, CK_INT); p32(Code, 8); p64(Code, 0);
    } else {
      encodeValue(I.getReturnValue());
    }
  }

  // ===== CALL：只把“非常量参数”的槽位写入字节码 =====
  void t_call(llvm::CallBase &CB) {
    uint64_t id = Tool.ensureCallId(&CB);
    p8(Code, OP_CALL);
    p64(Code, id);

    // 返回槽
    if (!CB.getType()->isVoidTy()) {
      uint32_t dst = allocSlot(&CB, CB.getType());
      p32(Code, dst);
    } else {
      p32(Code, UINT32_C(0xFFFFFFFF));
    }

    // 动态参数列表（仅非常量 & 等价常量过滤）
    std::vector<uint32_t> dynOffs;
    dynOffs.reserve(CB.arg_size());
    for (unsigned i=0;i<CB.arg_size();++i) {
      llvm::Value *A = CB.getArgOperand(i);
      if (isConstLike(A)) continue;  // 常量/等价常量不进入 a2（由 handle_call 分支以常量 IR 传递）
      dynOffs.push_back( allocSlot(A, A->getType()) );
    }

    p32(Code, (uint32_t)dynOffs.size());
    for (uint32_t off : dynOffs) p32(Code, off);
  }

  // --------- 回填分支目标 ---------
  void patchBranches() {
    for (auto &fx : BrFixups) {
      auto it = AddrOfBB.find(fx.target);
      assert(it != AddrOfBB.end() && "target BB not seen?");
      uint32_t addr = it->second;
      Code[fx.pos+0] = uint8_t(addr);
      Code[fx.pos+1] = uint8_t(addr>>8);
      Code[fx.pos+2] = uint8_t(addr>>16);
      Code[fx.pos+3] = uint8_t(addr>>24);
    }
  }
};

} // namespace vmp

// 用法：
// vmp::HandleCallTool tool;
// tool.collectFromFunction(F);
// vmp::VMCodeGen gen(F, tool);
// gen.run();
// const auto &bytes = gen.code();
