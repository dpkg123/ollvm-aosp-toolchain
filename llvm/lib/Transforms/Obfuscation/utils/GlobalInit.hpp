// GlobalInit.hpp — LLVM 15.0.7
#pragma once
#include <vector>
#include <string>
#include "llvm/IR/Module.h"
#include "llvm/IR/IRBuilder.h"
#include "llvm/IR/Constants.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/DerivedTypes.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/LLVMContext.h"
#include "llvm/IR/Type.h"
#include "llvm/ADT/ArrayRef.h"
#include "llvm/Support/Casting.h"
#include "llvm/Transforms/Utils/ModuleUtils.h" // appendToGlobalCtors

namespace ginit {
using namespace llvm;

// ===== 小工具 =====
inline IntegerType* IntPtrTy(Module& M) {
    return cast<IntegerType>(M.getDataLayout().getIntPtrType(M.getContext()));
}
inline Align PrefPtrAlign(Module& M) {
    return Align(M.getDataLayout().getPointerPrefAlignment(0).value());
}
inline bool isDefinableGlobal(GlobalVariable* GV) {
    // extern_weak 之类不应带 initializer
    return GV->getLinkage() != GlobalValue::ExternalWeakLinkage &&
           GV->getLinkage() != GlobalValue::CommonLinkage;
}

// 创建一个私有只读字符串 GV，并返回指向首元素的 i8*（ConstantExpr）
inline Constant* makePrivateROStringPtr(Module& M, StringRef NameHint, StringRef Bytes, bool AddNull = true) {
    LLVMContext& Ctx = M.getContext();
    auto* CDA = ConstantDataArray::getString(Ctx, Bytes, AddNull);
    auto* StrGV = new GlobalVariable(
        M, CDA->getType(), /*isConst=*/true,
        GlobalValue::PrivateLinkage, CDA,
        (NameHint + ".str").str()
    );
#if LLVM_VERSION_MAJOR >= 11
    StrGV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
#else
    StrGV->setUnnamedAddr(true);
#endif
    StrGV->setAlignment(Align(1));

    // ConstantExpr GEP 0,0（避免重载歧义）
    Type* IdxTy = Type::getInt64Ty(Ctx); // 用 64-bit 即可；亦可用 DL.getIndexType
    Constant* Z = ConstantInt::get(IdxTy, 0);
    Constant* Idxs[] = { Z, Z };
    return ConstantExpr::getInBoundsGetElementPtr(StrGV->getValueType(), StrGV,
                                                  ArrayRef<Constant*>(Idxs, 2)); // i8*
}

// ===== 1) 编译期初始化（首选） =====

// 把 GV 设成 zeroinitializer
inline bool setZero(GlobalVariable* GV) {
    if (!isDefinableGlobal(GV)) return false;
    GV->setInitializer(Constant::getNullValue(GV->getValueType()));
    return true;
}

// 整型常量（位宽需与 GV 类型匹配）
inline bool setInt(GlobalVariable* GV, uint64_t Val) {
    auto* ITy = dyn_cast<IntegerType>(GV->getValueType());
    if (!ITy) return false;
    if (!isDefinableGlobal(GV)) return false;
    GV->setInitializer(ConstantInt::get(ITy, Val));
    return true;
}

// 浮点常量（float/double/half）
inline bool setFP(GlobalVariable* GV, double Val) {
    Type* Ty = GV->getValueType();
    if (!Ty->isFloatingPointTy()) return false;
    if (!isDefinableGlobal(GV)) return false;
    GV->setInitializer(ConstantFP::get(Ty, Val));
    return true;
}

// 字节数组初始化到 [N x i8]
inline bool setBytes(GlobalVariable* GV, ArrayRef<uint8_t> Bytes) {
    auto* ArrTy = dyn_cast<ArrayType>(GV->getValueType());
    if (!ArrTy || !ArrTy->getElementType()->isIntegerTy(8) ||
        ArrTy->getNumElements() != Bytes.size())
        return false;
    if (!isDefinableGlobal(GV)) return false;

    auto* CDA = ConstantDataArray::get(GV->getContext(), Bytes);
    GV->setInitializer(CDA);
    GV->setAlignment(Align(1));
    return true;
}

// 为 i8* 全局变量设置为常量字符串地址（自动创建私有字符串符号）
inline bool setCStringPtr(GlobalVariable* GV, Module& M, StringRef Bytes, bool AddNull = true) {
    if (!GV->getValueType()->isPointerTy() ||
        GV->getValueType()->getPointerElementType() != Type::getInt8Ty(M.getContext()))
        return false;
    if (!isDefinableGlobal(GV)) return false;

    Constant* P = makePrivateROStringPtr(M, GV->getName(), Bytes, AddNull); // i8*
    GV->setInitializer(P);
    GV->setAlignment(PrefPtrAlign(M));
    return true;
}

// 把函数地址初始化到 GV：支持两种目的类型：指针类型 / 整数(=uintptr_t)
inline bool setFuncAddress(GlobalVariable* GV, Function* F, Module& M) {
    if (!isDefinableGlobal(GV)) return false;
    Type* Ty = GV->getValueType();
    Constant* Rhs = nullptr;
    if (Ty->isPointerTy()) {
        // 指针型：bitcast 函数指针到目标指针类型
        Rhs = ConstantExpr::getBitCast(F, Ty);
    } else if (auto* ITy = dyn_cast<IntegerType>(Ty)) {
        if (ITy->getBitWidth() != IntPtrTy(M)->getBitWidth()) return false;
        Rhs = ConstantExpr::getPtrToInt(F, ITy);
    } else {
        return false;
    }
    GV->setInitializer(Rhs);
    GV->setAlignment(Ty->isPointerTy() ? PrefPtrAlign(M) : PrefPtrAlign(M));
    return true;
}

// 把任意全局/常量地址初始化到 GV（同上：目的类型为指针或 uintptr_t）
inline bool setGlobalAddress(GlobalVariable* GV, Constant* Target, Module& M) {
    if (!isDefinableGlobal(GV)) return false;
    Type* Ty = GV->getValueType();
    Constant* Rhs = nullptr;
    if (Ty->isPointerTy()) {
        Rhs = ConstantExpr::getBitCast(Target, Ty);
    } else if (auto* ITy = dyn_cast<IntegerType>(Ty)) {
        if (ITy->getBitWidth() != IntPtrTy(M)->getBitWidth()) return false;
        Rhs = ConstantExpr::getPtrToInt(Target, ITy);
    } else {
        return false;
    }
    GV->setInitializer(Rhs);
    GV->setAlignment(Ty->isPointerTy() ? PrefPtrAlign(M) : PrefPtrAlign(M));
    return true;
}

// ===== 2) 运行期初始化（当 RHS 不是 Constant 时的兜底） =====
// 在 global ctor 中对 GV 执行 store RHS（RHS 为 Constant* 或将来可扩展成 Value*）
inline Function* emitCtorStore(Module& M, GlobalVariable* GV, Constant* RHS, unsigned Priority = 65535) {
    LLVMContext& Ctx = M.getContext();
    if (GV->isDeclaration() && GV->getLinkage() == GlobalValue::ExternalWeakLinkage)
        return nullptr; // extern_weak 不写入
    // 若没有初始值，填 0，便于 IR 合法化
    if (!GV->hasInitializer())
        GV->setInitializer(Constant::getNullValue(GV->getValueType()));

    auto* CtorFT = FunctionType::get(Type::getVoidTy(Ctx), false);
    Function* Ctor = Function::Create(CtorFT, GlobalValue::InternalLinkage,
                                      ("__ginit_ctor_" + GV->getName()).str(), &M);
    BasicBlock* BB = BasicBlock::Create(Ctx, "entry", Ctor);
    IRBuilder<> B(BB);

    // 如类型不一致，尝试常量 cast（指针 <-> 整数）
    Constant* ToStore = RHS;
    Type* Ty = GV->getValueType();
    if (ToStore->getType() != Ty) {
        if (Ty->isPointerTy() && ToStore->getType()->isPointerTy()) {
            ToStore = ConstantExpr::getBitCast(ToStore, Ty);
        } else if (Ty->isPointerTy() && ToStore->getType()->isIntegerTy()) {
            ToStore = ConstantExpr::getIntToPtr(cast<ConstantInt>(ToStore), Ty);
        } else if (Ty->isIntegerTy() && ToStore->getType()->isPointerTy()) {
            ToStore = ConstantExpr::getPtrToInt(ToStore, Ty);
        } else if (Ty->isIntegerTy() && ToStore->getType()->isIntegerTy()) {
            unsigned SW = cast<IntegerType>(ToStore->getType())->getBitWidth();
            unsigned DW = cast<IntegerType>(Ty)->getBitWidth();
            if (SW < DW) ToStore = ConstantExpr::getZExt(ToStore, Ty);
            else if (SW > DW) ToStore = ConstantExpr::getTrunc(ToStore, Ty);
        } else {
            // 其他复杂情况可以扩展
        }
    }

    B.CreateStore(ToStore, GV);
    B.CreateRetVoid();
    appendToGlobalCtors(M, Ctor, Priority);
    return Ctor;
}

// ===== 3) 便利辅助：按名字找/建，再初始化 =====

// 确保（或创建）一个可定义的全局：ExternalLinkage + 指定类型
inline GlobalVariable* ensureDefinableGV(Module& M, StringRef Name, Type* Ty, Align A = Align()) {
    if (auto* GV = M.getGlobalVariable(Name))
        return GV; // 若已存在，调用者应自行检查类型是否匹配
    auto* GV = new GlobalVariable(M, Ty, /*isConst=*/false,
                                  GlobalValue::ExternalLinkage,
                                  /*Init=*/nullptr, Name);
    if (A.value() != 0) GV->setAlignment(A);
    return GV;
}

// 把名为 GVName 的（uintptr_t 类型）变量设为名为 FuncName 的函数地址；可声明为 extern_weak
inline bool setUintPtrFromFuncName(Module& M, StringRef GVName, StringRef FuncName, bool WeakFunc = false) {
    LLVMContext& Ctx = M.getContext();
    auto* UPtrTy = IntPtrTy(M);
    GlobalVariable* GV = ensureDefinableGV(M, GVName, UPtrTy, PrefPtrAlign(M));

    Function* F = M.getFunction(FuncName);
    if (!F) {
        auto* FTy = FunctionType::get(Type::getVoidTy(Ctx), false);
        F = Function::Create(FTy,
                             WeakFunc ? GlobalValue::ExternalWeakLinkage
                                      : GlobalValue::ExternalLinkage,
                             FuncName, &M);
    } else if (WeakFunc && F->getLinkage() == GlobalValue::ExternalLinkage) {
        F->setLinkage(GlobalValue::ExternalWeakLinkage);
    }
    return setFuncAddress(GV, F, M);
}

// 为名为 GVName 的 i8* 写入常量字符串地址
inline bool setCStringPtrByName(Module& M, StringRef GVName, StringRef Str, bool AddNull = true) {
    auto* I8P = Type::getInt8PtrTy(M.getContext());
    GlobalVariable* GV = ensureDefinableGV(M, GVName, I8P, PrefPtrAlign(M));
    return setCStringPtr(GV, M, Str, AddNull);
}


    // 生成：@Name = [R x [W x i8]] 常量/可写二维字符数组
    // Strings: 行内容；Writable=false 放只读段；对 LLVM 15 友好
    inline GlobalVariable* createChar2DGV(
        Module& M, StringRef Name,
        ArrayRef<StringRef> Strings,
        bool Writable = false,
        GlobalValue::LinkageTypes Linkage = GlobalValue::ExternalLinkage,
        Align alignment = Align(1)) {

    StringRef Section = Writable ? ".data.irvm" : ".rodata.irvm" ;

    LLVMContext& Ctx = M.getContext();
    Type* I8 = Type::getInt8Ty(Ctx);

    // 1) 计算统一列宽 W（含 '\0'）
    size_t W = 1;
    for (auto s : Strings) W = std::max(W, s.size() + 1);

    // 2) 行类型 [W x i8]
    auto* RowTy = ArrayType::get(I8, W);

    // 3) 构造每一行的 Constant（手动 padding）
    std::vector<Constant*> Rows;
    Rows.reserve(Strings.size());
    for (auto s : Strings) {
        std::vector<uint8_t> buf(W, 0);
        const size_t copyN = std::min(s.size(), W - 1);
        if (copyN) std::memcpy(buf.data(), s.data(), copyN);
        // buf[copyN] 默认就是 0，相当于 '\0'
        Rows.push_back(ConstantDataArray::get(Ctx, buf)); // type: [W x i8]
    }

    // 4) 矩阵常量 [R x [W x i8]]
    auto* MatTy = ArrayType::get(RowTy, Rows.size());
    auto* MatC  = ConstantArray::get(MatTy, Rows);

    // 5) 建全局
    auto* GV = new GlobalVariable(
        M, MatTy, /*isConstant=*/!Writable, Linkage, MatC, Name);
#if LLVM_VERSION_MAJOR >= 11
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
#else
    GV->setUnnamedAddr(true);
#endif
    if (alignment.value() != 0) GV->setAlignment(alignment);
    if (!Section.empty()) GV->setSection(Section);
    return GV;
}


    inline llvm::GlobalVariable* createGlobalCStringTable(llvm::Module &M,
                                                      llvm::StringRef Name,
                                                      llvm::ArrayRef<llvm::StringRef> Items) {
    using namespace llvm;
    LLVMContext& Ctx = M.getContext();
    Type* I8   = Type::getInt8Ty(Ctx);
    Type* I8P  = PointerType::getUnqual(I8);

    std::vector<Constant*> Ptrs;
    Ptrs.reserve(Items.size());
    for (unsigned i = 0; i < Items.size(); ++i) {
        auto* CDA = ConstantDataArray::getString(Ctx, Items[i], /*AddNull=*/true);
        auto* S   = new GlobalVariable(M, CDA->getType(), /*isConst=*/true,
                                       GlobalValue::PrivateLinkage, CDA,
                                       (Name + ".str." + Twine(i)).str());
        S->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
        S->setAlignment(Align(1));

        // i8* &S[0]  —— 常量 GEP(0,0)
        Constant* Z = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
        Constant* Idx[] = { Z, Z };
        Constant* P = ConstantExpr::getInBoundsGetElementPtr(
            S->getValueType(), S, ArrayRef<Constant*>(Idx, 2));
        Ptrs.push_back(P); // i8*
    }

    auto* ArrTy = ArrayType::get(I8P, Ptrs.size());           // [N x i8*]
    auto* ArrC  = ConstantArray::get(ArrTy, Ptrs);
    auto* GV    = new GlobalVariable(M, ArrTy, /*isConst=*/true,
                                     GlobalValue::ExternalLinkage, ArrC, Name.str());
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(8));
    return GV;
}

} // namespace ginit
