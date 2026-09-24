// FuncRedirector.hpp — LLVM 15.0.7  (rewrite to vm_exec(code,size, vm_args, vm_num))
#pragma once

#include <vector>
#include <string>
#include <cassert>

#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/DataLayout.h"
#include "llvm/ADT/Twine.h"
#include "llvm/Support/Casting.h"

namespace frx {
using namespace llvm;

// ------------------ 选项 ------------------
struct VMExecOptions {
  std::string VMName = "vm_exec"; // 入口函数名
  bool CreateStubIfMissing = true; // 模块里没有就生成弱定义
  bool UseTailCall = false;
  bool DisallowVarArg = true;      // 变参函数默认跳过
  bool BoxPointers = true;         // 指针参数也装箱成栈上的“地址语义”
};

// ------------------ 常量 GEP（typed） ------------------
inline Constant* constGEP_0_0(Type* PointeeTy, Constant* Base) {
  LLVMContext& Ctx = Base->getContext();
  Constant* Z = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
  Constant* Idx[] = { Z, Z };
  return ConstantExpr::getInBoundsGetElementPtr(PointeeTy, Base,
                                                ArrayRef<Constant*>(Idx, 2));
}

// ------------------ 取得/创建 vm_exec(code,size,args,num) ------------------
inline Function* getOrCreateVMExec(Module& M, StringRef Name,
                                   bool CreateStubIfMissing) {
  LLVMContext& Ctx = M.getContext();
  Type* I8   = Type::getInt8Ty(Ctx);
  Type* I8P  = PointerType::getUnqual(I8);      // i8*
  Type* I8PP = PointerType::getUnqual(I8P);     // i8**
  Type* I32  = Type::getInt32Ty(Ctx);
  Type* I64  = Type::getInt64Ty(Ctx);

  // uint64_t vm_exec(const uint8_t*, uint32_t, void** args, uint64_t num)
  auto* FT = FunctionType::get(I64, { I8P, I32, I8PP, I64 }, /*isVarArg=*/false);
  Function* F = cast<Function>(M.getOrInsertFunction(Name, FT).getCallee());

  if (CreateStubIfMissing && F->empty()) {
    F->setLinkage(GlobalValue::WeakODRLinkage);
    BasicBlock* BB = BasicBlock::Create(Ctx, "entry", F);
    IRBuilder<> B(BB);
    B.CreateRet(ConstantInt::get(I64, 0));
  }
  return F;
}

/*
 * rewriteToVMExec
 *    return vm_exec(code_ptr, code_size, args_array, num_args);
 *
 * 参数：
 *   CodeGV   : [code_size x i8] 的全局常量（字节码）
 *   CodeSize : 字节码长度
 *   Opt      : 行为选项
 */
inline bool rewriteToVMExec(Function& F,
                            GlobalVariable* CodeGV,
                            uint32_t CodeSize,
                            const VMExecOptions& Opt = {}) {
  if (F.isDeclaration()) return false;
  if (Opt.DisallowVarArg && F.isVarArg()) return false;

  Module& M = *F.getParent();
  LLVMContext& Ctx = M.getContext();
  IRBuilder<> B(Ctx);

  // 清空函数体
  while (!F.empty()) F.begin()->eraseFromParent();
  BasicBlock* Entry = BasicBlock::Create(Ctx, "entry", &F);
  B.SetInsertPoint(Entry);

  Type* I8   = Type::getInt8Ty(Ctx);
  Type* I8P  = PointerType::getUnqual(I8);
  Type* I8PP = PointerType::getUnqual(I8P);
  Type* I32  = Type::getInt32Ty(Ctx);
  Type* I64  = Type::getInt64Ty(Ctx);

  // vm_exec
  Function* VM = getOrCreateVMExec(M, Opt.VMName, Opt.CreateStubIfMissing);

  // -------- code 指针 / 长度 --------
  Constant* CodePtrC = nullptr;
  if (!CodeGV) {
    CodePtrC = ConstantPointerNull::get(static_cast<PointerType *>(I8P));
    CodeSize = 0;
  } else {
    auto* ArrTy = cast<ArrayType>(CodeGV->getValueType());
    CodePtrC = constGEP_0_0(ArrTy, CodeGV); // i8*
  }
  Constant* CodeSizeC = ConstantInt::get(I32, CodeSize);

  // -------- args: 统一装箱到栈上（按地址语义）--------
  const unsigned N = F.arg_size();
  Value* NumC = ConstantInt::get(I64, N);

  // 分配 i8** args（N==0 时也分配 1，避免非法 alloca(0)）
  Value* N32 = ConstantInt::get(Type::getInt32Ty(Ctx), N ? N : 1);
  AllocaInst* ArgsArr = B.CreateAlloca(I8P, N32, "args");

  unsigned idx = 0;
  for (Argument& A : F.args()) {
    Value* AddrI8 = nullptr;

    if (A.getType()->isPointerTy()) {
      if (Opt.BoxPointers) {
        // 把指针值存入一个栈槽，再把该栈槽地址当作参数传给 VM（OP_PARAMMAP 直接 memcpy）
        AllocaInst* Box = B.CreateAlloca(A.getType(), nullptr, A.getName() + ".box.p");
        B.CreateStore(&A, Box);
        AddrI8 = B.CreateBitCast(Box, I8P);
      } else {
        // 不装箱：把原指针当作“数据缓冲区地址”，不推荐（OP_PARAMMAP 会 memcpy）
        AddrI8 = B.CreateBitCast(&A, I8P);
      }
    } else if (A.getType()->isIntegerTy()) {
      AllocaInst* Box = B.CreateAlloca(I64, nullptr, A.getName() + ".box.i");
      Value* V = &A;
      unsigned bw = cast<IntegerType>(A.getType())->getBitWidth();
      if (bw < 64) V = B.CreateZExt(V, I64);
      else if (bw > 64) V = B.CreateTrunc(V, I64);
      B.CreateStore(V, Box);
      AddrI8 = B.CreateBitCast(Box, I8P);
    } else if (A.getType()->isFloatingPointTy()) {
      if (A.getType()->isDoubleTy()) {
        AllocaInst* BoxD = B.CreateAlloca(Type::getDoubleTy(Ctx), nullptr, A.getName() + ".box.f64");
        B.CreateStore(&A, BoxD);
        AddrI8 = B.CreateBitCast(BoxD, I8P);
      } else if (A.getType()->isFloatTy()) {
        AllocaInst* BoxF = B.CreateAlloca(Type::getFloatTy(Ctx), nullptr, A.getName() + ".box.f32");
        B.CreateStore(&A, BoxF);
        AddrI8 = B.CreateBitCast(BoxF, I8P);
      } else {
        // 其他 FP（half 等），简单按 bit 宽创建栈槽
        Type* FT = A.getType();
        AllocaInst* Box = B.CreateAlloca(FT, nullptr, A.getName() + ".box.fp");
        B.CreateStore(&A, Box);
        AddrI8 = B.CreateBitCast(Box, I8P);
      }
    } else {
      // 结构体/数组等复杂类型：直接按其类型开栈槽并 memcpy（这里简单存值）
      Type* T = A.getType();
      AllocaInst* Box = B.CreateAlloca(T, nullptr, A.getName() + ".box.any");
      B.CreateStore(&A, Box);
      AddrI8 = B.CreateBitCast(Box, I8P);
    }

    // args[idx] = AddrI8
    Value* Slot = B.CreateInBoundsGEP(I8P, ArgsArr,
                   ConstantInt::get(Type::getInt32Ty(Ctx), idx));
    B.CreateStore(AddrI8, Slot);
    ++idx;
  }

  // 断言类型正确
  assert(CodePtrC->getType() == I8P && "code must be i8*");
  assert(ArgsArr->getType()  == I8PP && "args must be i8**");

  // -------- 调用 vm_exec(code, size, args, num) --------
  CallInst* RetI64 = B.CreateCall(VM, { CodePtrC, CodeSizeC, ArgsArr, NumC });
  if (Opt.UseTailCall) RetI64->setTailCallKind(CallInst::TCK_Tail);

  // -------- 返回值回转 --------
  Type* RT = F.getReturnType();
  if (RT->isVoidTy()) {
    B.CreateRetVoid();
  } else if (RT->isIntegerTy()) {
    unsigned W = cast<IntegerType>(RT)->getBitWidth();
    Value* V = RetI64;
    if (W < 64) V = B.CreateTrunc(V, RT);
    else if (W > 64) V = UndefValue::get(RT);
    B.CreateRet(V);
  } else if (RT->isPointerTy()) {
    B.CreateRet(B.CreateIntToPtr(RetI64, RT));
  } else if (RT->isDoubleTy()) {
    AllocaInst* Box = B.CreateAlloca(I64);
    B.CreateStore(RetI64, Box);
    Value* P = B.CreateBitCast(Box, PointerType::getUnqual(Type::getDoubleTy(Ctx)));
    Value* D = B.CreateLoad(Type::getDoubleTy(Ctx), P);
    B.CreateRet(D);
  } else if (RT->isFloatTy()) {
    Value* I32v = B.CreateTrunc(RetI64, Type::getInt32Ty(Ctx));
    AllocaInst* Box = B.CreateAlloca(Type::getInt32Ty(Ctx));
    B.CreateStore(I32v, Box);
    Value* Pf = B.CreateBitCast(Box, PointerType::getUnqual(Type::getFloatTy(Ctx)));
    Value* Fv = B.CreateLoad(Type::getFloatTy(Ctx), Pf);
    B.CreateRet(Fv);
  } else {
    B.CreateRet(UndefValue::get(RT));
  }

  F.addFnAttr(Attribute::NoInline);
  return true;
}

} // namespace frx
