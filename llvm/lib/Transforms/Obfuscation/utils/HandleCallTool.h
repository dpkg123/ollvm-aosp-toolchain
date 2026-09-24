// HandleCallTool.h/cc — Function 粒度收集 → 生成/改写 handle_call(...) + 常量获取分发
// LLVM 15.0.7 (opaque pointers)

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/InstIterator.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/ADT/DenseMap.h"
#include "llvm/Support/raw_ostream.h"

#include <unordered_map>
#include <vector>
#include <string>
#include <cassert>

namespace vmp {

// ------------ 辅助：类型压缩成签名 key ------------
static void dumpTypeRec(llvm::Type *T, llvm::raw_ostream &OS) {
  using namespace llvm;
  if (T->isIntegerTy()) { OS << "i" << T->getIntegerBitWidth(); return; }
  if (T->isPointerTy()) { OS << "p"; return; } // opaque: 不追 element
  if (T->isFloatTy())   { OS << "f32"; return; }
  if (T->isDoubleTy())  { OS << "f64"; return; }
  if (T->isVoidTy())    { OS << "v";   return; }
  OS << "t";
}
static inline std::string signatureKey(llvm::FunctionType *FTy) {
  using namespace llvm;
  std::string S; raw_string_ostream OS(S);
  OS << "ret:"; dumpTypeRec(FTy->getReturnType(), OS);
  OS << ";args(";
  for (unsigned i=0;i<FTy->getNumParams();++i){ dumpTypeRec(FTy->getParamType(i), OS); OS<<","; }
  OS << ")vararg=" << (FTy->isVarArg()?1:0);
  OS.flush(); return S;
}

// ================ 工具主体 ================
class HandleCallTool {
public:
  HandleCallTool() = default;
  explicit HandleCallTool(llvm::Module &M) { bindModule(M); }

  void bindModule(llvm::Module &M) {
    Mod = &M;
    Ctx = &M.getContext();
    I64 = llvm::Type::getInt64Ty(*Ctx);
    I8  = llvm::Type::getInt8Ty(*Ctx);
    I8Ptr = llvm::Type::getInt8PtrTy(*Ctx);             // i8*
  }

  void collectFromFunction(llvm::Function &F) {
    if (F.isDeclaration()) return;
    if (!Mod) bindModule(*F.getParent());
    else { assert(Mod == F.getParent() && "All functions must be from the same Module"); }

    for (auto &I : llvm::instructions(F)) {
      if (auto *CB = llvm::dyn_cast<llvm::CallBase>(&I)) ensureCallId(CB);
    }
  }

  // ====== 给 VMCodeGen 用：普通 call 的 ID ======
  uint64_t ensureCallId(llvm::CallBase* CB) {
    if (auto it = CallIdOf.find(CB); it != CallIdOf.end()) return it->second;
    uint64_t id = 0;
    if (readIdFromMD(CB, id)) { CallIdOf[CB] = id; return id; }
    id = registerCallSite(CB);
    return id;
  }
  uint64_t getCallId(const llvm::CallBase* CB) const {
    uint64_t id = 0; bool ok = tryGetCallId(CB, id);
    assert(ok && "CallId not found. Use ensureCallId()/collectFromFunction() first.");
    return id;
  }
  bool tryGetCallId(const llvm::CallBase* CB, uint64_t &out) const {
    if (auto it = CallIdOf.find(CB); it != CallIdOf.end()) { out = it->second; return true; }
    return readIdFromMD(CB, out);
  }

  // ====== 新增：给 VMCodeGen 用的“常量获取” ID ======
  // 1) 将 V（Global/ConstantExpr/常量 GEP 指令）规范化为常量 i8*，用于“取地址”
  llvm::Constant* tryMakeConstPtrExpr(llvm::Value *V) {
    using namespace llvm;
    if (!Ctx) return nullptr;

    if (auto *GV = dyn_cast<GlobalValue>(V)) {
      return ConstantExpr::getBitCast(GV, I8Ptr);
    }
    if (auto *CE = dyn_cast<ConstantExpr>(V)) {
      if (CE->getType()->isPointerTy())
        return ConstantExpr::getBitCast(CE, I8Ptr);
      return nullptr;
    }
    if (auto *GEP = dyn_cast<GetElementPtrInst>(V)) {
      Value *Base = GEP->getPointerOperand();
      if (!isa<Constant>(Base)) return nullptr;
      llvm::SmallVector<llvm::Constant*, 8> Idxs;
      for (auto &Idx : GEP->indices()) {
        if (auto *C = dyn_cast<Constant>(Idx)) Idxs.push_back(C);
        else return nullptr;
      }
      llvm::Type *SrcElemTy = GEP->getSourceElementType(); // LLVM 15 可用
      auto *BaseC = cast<Constant>(Base);
      Constant *CG = ConstantExpr::getGetElementPtr(SrcElemTy, BaseC, Idxs, /*InBounds*/true);
      return ConstantExpr::getBitCast(CG, I8Ptr);
    }
    return nullptr;
  }

  // 2) 为“常量地址”（i8* 常量表达式）分配 ID：handle_call 命中时返回 ptr->i64
  uint64_t ensureConstAddrId(llvm::Constant *I8PtrConst) {
    assert(I8PtrConst && I8PtrConst->getType() == I8Ptr && "need i8* constant");
    if (auto it = ConstIdMap.find(I8PtrConst); it != ConstIdMap.end()) return it->second;
    uint64_t id = NextCallId++;
    ConstEntries.push_back(ConstEntry::AddrOf(id, I8PtrConst));
    ConstIdMap.insert({ I8PtrConst, id });
    return id;
  }

  // 3) 为“整型常量”分配 ID（返回 zero-extended/trunc 到 i64）
  uint64_t ensureConstIntId(llvm::ConstantInt *CI) {
    assert(CI && "need ConstantInt");
    llvm::APInt AP = CI->getValue().zextOrTrunc(64);
    uint64_t bits = AP.getZExtValue();
    // 唯一键：指针直接用 Constant*；整型我们用 (width,bits) 做 key
    ConstIntKey key{CI->getType()->getIntegerBitWidth(), bits};
    if (auto it = ConstIntIdMap.find(key); it != ConstIntIdMap.end()) return it->second;
    uint64_t id = NextCallId++;
    ConstEntries.push_back(ConstEntry::IntBits(id, bits));
    ConstIntIdMap.emplace(key, id);
    return id;
  }

  // 4) 为“浮点常量”分配 ID（返回**位模式**组成的 i64；f32 占低 32 位）
  uint64_t ensureConstFPBitsId(llvm::ConstantFP *CFP) {
    assert(CFP && "need ConstantFP");
    uint64_t bits = 0;
    if (CFP->getType()->isDoubleTy()) {
      bits = CFP->getValueAPF().bitcastToAPInt().getZExtValue(); // 64
    } else if (CFP->getType()->isFloatTy()) {
      uint32_t b32 = CFP->getValueAPF().bitcastToAPInt().getZExtValue();
      bits = (uint64_t)b32; // 低 32 位承载
    } else {
      assert(false && "only f32/f64 supported");
    }
    // 唯一键：类型宽度 + 位模式
    ConstFPKey key{CFP->getType()->isDoubleTy()?64u:32u, bits};
    if (auto it = ConstFPIdMap.find(key); it != ConstFPIdMap.end()) return it->second;
    uint64_t id = NextCallId++;
    ConstEntries.push_back(ConstEntry::FPBits(id, bits));
    ConstFPIdMap.emplace(key, id);
    return id;
  }

  // ====== 生成/改写 handle_call ======
  llvm::Function* materializeHandle(bool forceCreateStubIfEmpty=false) {
    ensureModuleBoundOrDerive();
    if (!Mod) { llvm::errs() << "[HandleCallTool] No Module bound.\n"; return nullptr; }
    return materializeImpl(*Mod, forceCreateStubIfEmpty);
  }
  llvm::Function* materializeHandle(llvm::Module &M, bool forceCreateStubIfEmpty=false) {
    if (!Mod) bindModule(M); else { assert(Mod==&M && "Materializing into a different Module"); }
    return materializeImpl(M, forceCreateStubIfEmpty);
  }

private:
  // ========= 登记一个普通 callsite =========
  uint64_t registerCallSite(llvm::CallBase *CB) {
    using namespace llvm;
    CallEntry E;
    E.callId = NextCallId++;
    E.CC = CB->getCallingConv();
    if (auto *CI = dyn_cast<CallInst>(CB)) {
      E.TCK = CI->getTailCallKind();
      E.Attrs = CI->getAttributes();
      E.DL = CI->getDebugLoc();
    }
    E.FTy = CB->getFunctionType();

    Value *CalleeOp = CB->getCalledOperand();
    Value *Stripped = CalleeOp->stripPointerCasts();
    if (auto *F = dyn_cast<Function>(Stripped)) E.DirectCallee = F;
    else if (isa<Constant>(CalleeOp))           E.ConstCallee  = cast<Constant>(CalleeOp);
    else                                        E.NeedsRuntimeFnPtr = true;

    E.methodId = getOrCreateMethodId(E.FTy,
                     E.DirectCallee ? E.DirectCallee->getName()
                                    : (E.ConstCallee ? E.ConstCallee->getName() : "<indirect>"));

    unsigned nextIdx = E.NeedsRuntimeFnPtr ? 1 : 0;
    for (unsigned i=0;i<CB->arg_size();++i) {
      Value *Op = CB->getArgOperand(i);
      ArgSpec A; A.Ty = Op->getType();
      if (isa<Constant>(Op)) { A.isConst=true; A.C=cast<Constant>(Op); }
      else { A.isConst=false; A.runtimeIndex=nextIdx++; }
      E.Args.push_back(A);
    }
    E.RetTy = CB->getType();

    Entries.push_back(std::move(E));
    CallIdOf[CB] = Entries.back().callId;
    writeIdMD(CB, Entries.back().callId);
    return Entries.back().callId;
  }

  // ========= MD 存取 =========
  static constexpr const char* kCallIdMD = "vmp.call.id";
  bool readIdFromMD(const llvm::CallBase* CB, uint64_t &out) const {
    if (auto *N = CB->getMetadata(kCallIdMD)) {
      if (auto *CM = llvm::dyn_cast<llvm::ConstantAsMetadata>(N->getOperand(0))) {
        if (auto *CI = llvm::dyn_cast<llvm::ConstantInt>(CM->getValue())) {
          out = CI->getZExtValue(); return true;
        }
      }
    }
    return false;
  }
  void writeIdMD(llvm::CallBase* CB, uint64_t id) {
    auto &C = CB->getContext();
    auto *I64Local = llvm::Type::getInt64Ty(C);
    auto *CI = llvm::ConstantInt::get(I64Local, id);
    auto *MD = llvm::MDNode::get(C, { llvm::ConstantAsMetadata::get(CI) });
    CB->setMetadata(kCallIdMD, MD);
  }

  // ========= methodId：签名+名称 =========
  uint64_t getOrCreateMethodId(llvm::FunctionType *FTy, llvm::StringRef key) {
    std::string k = signatureKey(FTy) + "|" + key.str();
    auto it = MethodIdMap.find(k);
    if (it != MethodIdMap.end()) return it->second;
    uint64_t id = NextMethodId++;
    MethodIdMap.emplace(std::move(k), id);
    return id;
  }

  // ========= 类型/Module 保障 =========
  void ensureModuleBoundOrDerive() {
    if (Mod) return;
    for (const auto &E : Entries) {
      if (E.DirectCallee) { bindModule(*E.DirectCallee->getParent()); return; }
      if (E.ConstCallee) {
        if (auto *F = llvm::dyn_cast<llvm::Function>(E.ConstCallee->stripPointerCasts())) {
          bindModule(*F->getParent()); return;
        }
      }
    }
    for (const auto &K : ConstEntries) {
      if (K.Kind == ConstEntry::K_Addr && K.AddrConst) {
        if (auto *GV = llvm::dyn_cast<llvm::GlobalValue>(K.AddrConst->stripPointerCasts())) {
          bindModule(*GV->getParent()); return;
        }
      }
    }
  }

  // ========= 任意返回值转 i64 =========
  llvm::Value* toU64(llvm::IRBuilder<> &B, llvm::Value *V, llvm::Type *RTy) {
    using namespace llvm;
    if (RTy->isVoidTy()) return ConstantInt::get(I64, 0);
    if (RTy->isIntegerTy()) {
      unsigned bw = cast<IntegerType>(RTy)->getBitWidth();
      if (bw < 64) return B.CreateZExt(V, I64);
      if (bw > 64) return B.CreateTrunc(V, I64);
      return V;
    }
    if (RTy->isPointerTy()) return B.CreatePtrToInt(V, I64);
    if (RTy->isFloatTy() || RTy->isDoubleTy() || RTy->isFP128Ty()) return B.CreateFPToUI(V, I64);
    return llvm::ConstantInt::get(I64, 0);
  }

  // ========= 从 args[idx] 读取 Ty =========
  static llvm::Value* loadFromArgsAt(llvm::IRBuilder<> &B,
                                     llvm::Type *Ty, unsigned idx,
                                     llvm::Value *ArgArgs,
                                     llvm::Type *I64, llvm::Type *I8Ptr)
  {
    using namespace llvm;
    Value *I = ConstantInt::get(I64, idx);
    Value *Slot = B.CreateGEP(I8Ptr, ArgArgs, I);            // &args[idx] : (i8**)
    Value *Elem = B.CreateLoad(I8Ptr, Slot);                 // i8*
    Value *TypedPtr = B.CreatePointerCast(Elem, PointerType::getUnqual(Ty)); // Ty*
    return B.CreateLoad(Ty, TypedPtr);                       // Ty
  }

  // ========= 在“空的或仅声明”的 handle_call 上构造完整分发体（含常量） =========
  void buildFreshDispatch(llvm::Function *HF, bool hasNumArg) {
    using namespace llvm;
    auto AI = HF->arg_begin();
    Argument *ArgId   = &*AI++; ArgId->setName("id");
    Argument *ArgArgs = &*AI++; ArgArgs->setName("args");
    if (hasNumArg) { Argument *ArgNum = &*AI++; ArgNum->setName("num"); (void)ArgNum; }

    BasicBlock *BBEntry = BasicBlock::Create(*Ctx, "entry", HF);
    BasicBlock *Cond  = BasicBlock::Create(*Ctx, "cond0", HF);
    IRBuilder<> B(BBEntry); B.CreateBr(Cond);

    BasicBlock *ChainTail = Cond;

    auto addConstCase = [&](const ConstEntry &K){
      IRBuilder<> BC(ChainTail);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, K.constId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_k_"+std::to_string(K.constId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond_"+std::to_string(K.constId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);
      IRBuilder<> BD(Do);
      switch (K.Kind) {
        case ConstEntry::K_Addr: {
          Value *PI = BD.CreatePtrToInt(K.AddrConst, I64);
          BD.CreateRet(PI);
        } break;
        case ConstEntry::K_IntBits: {
          BD.CreateRet(ConstantInt::get(I64, K.Bits)); // 按位/零扩展
        } break;
        case ConstEntry::K_FPBits: {
          BD.CreateRet(ConstantInt::get(I64, K.Bits)); // 浮点按位模式返回
        } break;
      }
      ChainTail = Next;
    };

    auto addCallCase = [&](const CallEntry &E){
      IRBuilder<> BC(ChainTail);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, E.callId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_call_"+std::to_string(E.callId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond_"+std::to_string(E.callId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);

      IRBuilder<> BD(Do);
      llvm::SmallVector<llvm::Value*, 8> CallArgs;

      for (const ArgSpec &A : E.Args) {
        if (A.isConst) CallArgs.push_back(A.C);
        else           CallArgs.push_back(loadFromArgsAt(BD, A.Ty, A.runtimeIndex, ArgArgs, I64, I8Ptr));
      }

      llvm::CallInst *NewCI = nullptr;
      if (E.DirectCallee) {
        NewCI = BD.CreateCall(E.FTy, E.DirectCallee, CallArgs);
      } else if (E.ConstCallee) {
        llvm::Value *Cal = E.ConstCallee;
        if (Cal->getType() != llvm::PointerType::getUnqual(E.FTy))
          Cal = BD.CreatePointerCast(Cal, llvm::PointerType::getUnqual(E.FTy));
        NewCI = BD.CreateCall(E.FTy, Cal, CallArgs);
      } else {
        llvm::Value *FnI8 = loadFromArgsAt(BD, I8Ptr, 0, ArgArgs, I64, I8Ptr);
        llvm::Value *Fn   = BD.CreatePointerCast(FnI8, llvm::PointerType::getUnqual(E.FTy));
        NewCI = BD.CreateCall(E.FTy, Fn, CallArgs);
      }

      NewCI->setCallingConv(E.CC);
      NewCI->setTailCallKind(E.TCK);
      NewCI->setAttributes(E.Attrs);
      NewCI->setDebugLoc(E.DL);

      BD.CreateRet(toU64(BD, NewCI, E.RetTy));
      ChainTail = Next;
    };

    // 先挂常量，再挂普通调用（顺序无所谓，只要 id 唯一）
    for (const auto &K : ConstEntries) addConstCase(K);
    for (const auto &E : Entries)      addCallCase(E);

    IRBuilder<> BE(ChainTail);
    BE.CreateRet(ConstantInt::get(I64, 0));
  }

  // ========= 在已有 handle_call 前插分发链；miss → 旧入口（含常量） =========
  void prependDispatchChain(llvm::Function *HF, bool hasNumArg) {
    using namespace llvm;
    auto AI = HF->arg_begin();
    Argument *ArgId   = &*AI++; ArgId->setName("id");
    Argument *ArgArgs = &*AI++; ArgArgs->setName("args");
    if (hasNumArg) { Argument *ArgNum = &*AI++; ArgNum->setName("num"); (void)ArgNum; }

    BasicBlock *OldEntryBB = &HF->getEntryBlock();
    BasicBlock *NewEntryBB = BasicBlock::Create(*Ctx, "entry.extend", HF, OldEntryBB);
    IRBuilder<> B(NewEntryBB);
    BasicBlock *CurCond = BasicBlock::Create(*Ctx, "cond.prepend.0", HF);
    B.CreateBr(CurCond);

    auto addConstCase = [&](const ConstEntry &K){
      IRBuilder<> BC(CurCond);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, K.constId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_k_"+std::to_string(K.constId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond.prepend."+std::to_string(K.constId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);
      IRBuilder<> BD(Do);
      switch (K.Kind) {
        case ConstEntry::K_Addr: { BD.CreateRet(BD.CreatePtrToInt(K.AddrConst, I64)); } break;
        case ConstEntry::K_IntBits: { BD.CreateRet(ConstantInt::get(I64, K.Bits)); } break;
        case ConstEntry::K_FPBits: { BD.CreateRet(ConstantInt::get(I64, K.Bits)); } break;
      }
      CurCond = Next;
    };

    auto addCallCase = [&](const CallEntry &E){
      IRBuilder<> BC(CurCond);
      auto *Hit  = BC.CreateICmpEQ(ArgId, ConstantInt::get(I64, E.callId));
      auto *Do   = BasicBlock::Create(*Ctx, ("do_call_"+std::to_string(E.callId)), HF);
      auto *Next = BasicBlock::Create(*Ctx, ("cond.prepend."+std::to_string(E.callId+1)), HF);
      BC.CreateCondBr(Hit, Do, Next);

      IRBuilder<> BD(Do);
      llvm::SmallVector<llvm::Value*, 8> CallArgs;
      for (const ArgSpec &A : E.Args) {
        if (A.isConst) CallArgs.push_back(A.C);
        else           CallArgs.push_back(loadFromArgsAt(BD, A.Ty, A.runtimeIndex, ArgArgs, I64, I8Ptr));
      }

      llvm::CallInst *NewCI = nullptr;
      if (E.DirectCallee) NewCI = BD.CreateCall(E.FTy, E.DirectCallee, CallArgs);
      else if (E.ConstCallee) {
        llvm::Value *Cal = E.ConstCallee;
        if (Cal->getType() != llvm::PointerType::getUnqual(E.FTy))
          Cal = BD.CreatePointerCast(Cal, llvm::PointerType::getUnqual(E.FTy));
        NewCI = BD.CreateCall(E.FTy, Cal, CallArgs);
      } else {
        llvm::Value *FnI8 = loadFromArgsAt(BD, I8Ptr, 0, ArgArgs, I64, I8Ptr);
        llvm::Value *Fn   = BD.CreatePointerCast(FnI8, llvm::PointerType::getUnqual(E.FTy));
        NewCI = BD.CreateCall(E.FTy, Fn, CallArgs);
      }

      NewCI->setCallingConv(E.CC);
      NewCI->setTailCallKind(E.TCK);
      NewCI->setAttributes(E.Attrs);
      NewCI->setDebugLoc(E.DL);

      BD.CreateRet(toU64(BD, NewCI, E.RetTy));
      CurCond = Next;
    };

    for (const auto &K : ConstEntries) addConstCase(K);
    for (const auto &E : Entries)      addCallCase(E);

    IRBuilder<> BE(CurCond);
    BE.CreateBr(OldEntryBB); // miss → 旧逻辑
  }

  // ========= 主实现：优先改写已有 handle_call；否则新建 =========
  llvm::Function* materializeImpl(llvm::Module &M, bool forceCreateStubIfEmpty) {
    using namespace llvm;

    if (!Ctx) bindModule(M); // init types

    Function *HF = M.getFunction("handle_call");

    // 无收集项且无常量
    if (Entries.empty() && ConstEntries.empty()) {
      if (!HF) {
        if (!forceCreateStubIfEmpty) return nullptr;
        // 建一个三参的空桩：i64(i64, i8**, i64)
        auto *FT = FunctionType::get(I64, { I64, PointerType::getUnqual(I8Ptr), I64 }, /*vararg*/false);
        HF = Function::Create(FT, GlobalValue::ExternalLinkage, "handle_call", &M);
        IRBuilder<> B(BasicBlock::Create(*Ctx, "entry", HF));
        B.CreateRet(ConstantInt::get(I64, 0));
        return HF;
      }
      return HF; // 已有 handle_call 且我们没任务：不改写
    }

    // 有任务：创建或改写
    if (!HF) {
      auto *FT = FunctionType::get(I64, { I64, PointerType::getUnqual(I8Ptr), I64 }, /*vararg*/false);
      HF = Function::Create(FT, GlobalValue::ExternalLinkage, "handle_call", &M);
      buildFreshDispatch(HF, /*hasNumArg=*/true);
    } else {
      auto *FTy = HF->getFunctionType();
      unsigned NP = FTy->getNumParams();
      bool hasNumArg = (NP >= 3);
      if (HF->empty()) buildFreshDispatch(HF, hasNumArg);
      else             prependDispatchChain(HF, hasNumArg);
    }

    Entries.clear();
    ConstEntries.clear();
    ConstIdMap.clear();
    ConstIntIdMap.clear();
    ConstFPIdMap.clear();
    return HF;
  }

  // ========= 数据结构 =========
  struct ArgSpec {
    llvm::Type *Ty{}; bool isConst{}; llvm::Constant *C{}; unsigned runtimeIndex{};
  };
  struct CallEntry {
    uint64_t callId{}; uint64_t methodId{};
    llvm::FunctionType *FTy{}; llvm::Function *DirectCallee{}; llvm::Constant *ConstCallee{}; bool NeedsRuntimeFnPtr{false};
    std::vector<ArgSpec> Args; llvm::Type *RetTy{};
    llvm::CallingConv::ID CC{llvm::CallingConv::C};
    llvm::AttributeList Attrs{}; llvm::CallInst::TailCallKind TCK{llvm::CallInst::TCK_None};
    llvm::DebugLoc DL{};
  };

  struct ConstEntry {
    enum Kind { K_Addr, K_IntBits, K_FPBits } Kind{};
    uint64_t constId{};
    // K_Addr
    llvm::Constant *AddrConst{}; // i8*
    // K_IntBits / K_FPBits
    uint64_t Bits{};

    static ConstEntry AddrOf(uint64_t id, llvm::Constant *C) {
      ConstEntry E; E.Kind=K_Addr; E.constId=id; E.AddrConst=C; return E;
    }
    static ConstEntry IntBits(uint64_t id, uint64_t bits) {
      ConstEntry E; E.Kind=K_IntBits; E.constId=id; E.Bits=bits; return E;
    }
    static ConstEntry FPBits(uint64_t id, uint64_t bits) {
      ConstEntry E; E.Kind=K_FPBits; E.constId=id; E.Bits=bits; return E;
    }
  };

  struct ConstIntKey {
    unsigned Width; uint64_t Bits;
    bool operator==(const ConstIntKey &o) const { return Width==o.Width && Bits==o.Bits; }
  };
  struct ConstIntKeyHash {
    std::size_t operator()(ConstIntKey const& k) const {
      return (std::size_t)k.Bits ^ ((std::size_t)k.Width<<1);
    }
  };
  struct ConstFPKey {
    unsigned Width; uint64_t Bits;
    bool operator==(const ConstFPKey &o) const { return Width==o.Width && Bits==o.Bits; }
  };
  struct ConstFPKeyHash {
    std::size_t operator()(ConstFPKey const& k) const {
      return (std::size_t)k.Bits ^ ((std::size_t)k.Width<<1);
    }
  };

  // Module / Context
  llvm::Module *Mod{nullptr};
  llvm::LLVMContext *Ctx{nullptr};
  llvm::Type *I64{nullptr};
  llvm::Type *I8{nullptr};
  llvm::Type *I8Ptr{nullptr};

  // 采集状态
  std::vector<CallEntry> Entries;
  std::vector<ConstEntry> ConstEntries;

  uint64_t NextMethodId{0};
  uint64_t NextCallId{0};
  std::unordered_map<std::string, uint64_t> MethodIdMap;
  llvm::DenseMap<const llvm::CallBase*, uint64_t> CallIdOf;

  // 常量去重
  llvm::DenseMap<const llvm::Constant*, uint64_t> ConstIdMap; // 仅 K_Addr：i8* 常量
  std::unordered_map<ConstIntKey, uint64_t, ConstIntKeyHash> ConstIntIdMap;
  std::unordered_map<ConstFPKey,  uint64_t, ConstFPKeyHash>  ConstFPIdMap;
};

// ====== 用法（关键片段） ======
//
// vmp::HandleCallTool tool;
// tool.collectFromFunction(F);   // 收集真实调用（可多函数累积）
//
// // —— 在 VMCodeGen 中：
// // 1) 碰到“基于常量的地址”（全局变量 / 常量 GEP）
// if (auto *Cptr = tool.tryMakeConstPtrExpr(SomeValue)) {
//   uint64_t kid = tool.ensureConstAddrId(Cptr);
//   // 生成字节码：OP_CALL, id=kid, dst=slot, dynN=0
// }
//
// // 2) 可选：需要整型/浮点常量“按位返回”
// if (auto *CI = dyn_cast<ConstantInt>(V))    kid = tool.ensureConstIntId(CI);
// if (auto *CF = dyn_cast<ConstantFP>(V))     kid = tool.ensureConstFPBitsId(CF);
//
// // 最后生成/改写 handle_call（会把“常量获取”分支也编进去）：
// auto *handle = tool.materializeHandle();  // 若已有 handle_call 则前置分发链；没有则新建
//
} // namespace vmp
