#pragma once
// IRVMTool.hpp — 传入 llvm::Function，得到 code / g_syms / g_rels，并可 verify() 自检。
// 覆盖最小子集：alloca i32 / store i32 / load i32 / add i32 / call printf/putchar / ret i32

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <sstream>
#include <cassert>

#include "llvm/IR/Constants.h"
#include "llvm/IR/Function.h"
#include "llvm/IR/GlobalVariable.h"
#include "llvm/IR/InstrTypes.h"
#include "llvm/IR/Instructions.h"
#include "llvm/IR/Module.h"
#include "llvm/IR/Operator.h"
#include "llvm/IR/Type.h"
#include "llvm/IR/Value.h"
#include "llvm/Support/raw_ostream.h"
#include <cstdarg>  // va_list, va_start, va_end
namespace irvm {

enum Op : uint8_t {
  OP_HLT       = 0x00,
  OP_LDARG     = 0x01, // [op rd arg]
  OP_LOADK     = 0x02, // [op rd kidx]
  OP_MOV       = 0x03,

  OP_ADD       = 0x10, // [op rd ra rb]
  OP_SUB       = 0x11,
  OP_MUL       = 0x12,
  OP_UDIV      = 0x13,

  OP_PUSHARG   = 0x20, // [op rs]
  OP_CLEARARGS = 0x21, // [op]
  OP_CALL_SYM  = 0x22, // [op sym argc]
  OP_RET       = 0x30, // [op rs]

  OP_ALLOCA4   = 0x40, // [op rd count]
  OP_STORE32   = 0x41, // [op raddr rsrc]
  OP_LOAD32    = 0x42, // [op rd raddr]
  OP_SX32      = 0x43
};

struct Rel {
  enum Kind : uint8_t { IMM_U64 = 0, CSTR = 1 } kind;
  uint64_t     imm = 0;     // when IMM_U64：承载 i32 的二补值（有符号常量也正确）
  std::string  cstr;        // when CSTR：不含尾部 NUL
};

class IRVMTool {
public:
  struct VerifyResult {
    bool ok = true;
    std::vector<std::string> errors;
    std::vector<std::string> warnings;
  };

  // === 主入口 ===
  void encode(llvm::Function& F) {
    clear();

    // 参数顺序
    unsigned ai = 0;
    for (auto& A : F.args()) ArgIndex_[&A] = ai++;

    for (auto& BB : F) {
      for (auto& I : BB) {
        using namespace llvm;

        if (auto* Alloca = dyn_cast<AllocaInst>(&I)) {
          if (!Alloca->getAllocatedType()->isIntegerTy(32)) {
            warn("Only alloca i32 supported", &I); continue;
          }
          unsigned rd = getReg(Alloca);
          emit3(OP_ALLOCA4, (uint8_t)rd, /*count*/1);
          continue;
        }

        if (auto* Store = dyn_cast<StoreInst>(&I)) {
          auto* V = Store->getValueOperand();
          auto* P = Store->getPointerOperand();
          unsigned raddr = getReg(P);
          ensurePointerComputed(P);
          unsigned rsrc  = materializeI32(V, /*ctx*/"store.i32");
          emit3(OP_STORE32, (uint8_t)raddr, (uint8_t)rsrc);
          continue;
        }

        if (auto* Load = dyn_cast<LoadInst>(&I)) {
          auto* P = Load->getPointerOperand();
          unsigned raddr = getReg(P);
          ensurePointerComputed(P);
          unsigned rd = getReg(Load);
          emit3(OP_LOAD32, (uint8_t)rd, (uint8_t)raddr);
          continue;
        }

        if (auto* BO = dyn_cast<BinaryOperator>(&I)) {
          if (BO->getOpcode() == Instruction::Add &&
              BO->getType()->isIntegerTy(32)) {
            unsigned ra = materializeI32(BO->getOperand(0), "add.lhs");
            unsigned rb = materializeI32(BO->getOperand(1), "add.rhs");
            unsigned rd = getReg(&I);
            emit4(OP_ADD, (uint8_t)rd, (uint8_t)ra, (uint8_t)rb);
          } else {
            warn("Only add i32 supported", &I);
          }
          continue;
        }

        if (auto* CI = dyn_cast<CallInst>(&I)) {
          if (auto* Callee = CI->getCalledFunction()) {
            std::string name = Callee->getName().str();
            if (name == "printf" || name == "putchar") {
              unsigned sym = getSym(name);
              emit1(OP_CLEARARGS);
              currentPushCount_ = 0;

              if (name == "printf") {
                for (unsigned i=0;i<CI->arg_size();++i) {
                  llvm::Value* A = CI->getArgOperand(i);
                  unsigned r = 0;
                  if (i == 0) {
                    std::string s;
                    if (!extractCStringFromValue(A, s)) s = "%d";
                    unsigned k = getRelCStr(s);
                    r = newTmpReg();
                    emitLoadKWithRecord((uint8_t)r, (uint8_t)k, Rel::CSTR, "printf.fmt");
                  } else {
                    r = materializeI32(A, "printf.arg");
                  }
                  emit2(OP_PUSHARG, (uint8_t)r);
                  ++currentPushCount_;
                }
                emitCallSymWithRecord((uint8_t)sym, (uint8_t)CI->arg_size());
              } else { // putchar(int)
                unsigned r = materializeI32(CI->getArgOperand(0), "putchar.arg");
                emit2(OP_PUSHARG, (uint8_t)r);
                ++currentPushCount_;
                emitCallSymWithRecord((uint8_t)sym, 1);
              }
              continue;
            }
          }
          warn("Only printf/putchar supported in this minimal emitter", &I);
          continue;
        }

        if (auto* RI = llvm::dyn_cast<llvm::ReturnInst>(&I)) {
          if (auto* V = RI->getReturnValue()) {
            unsigned rs = materializeI32(V, "ret.i32");
            emit2(OP_RET, (uint8_t)rs);
          } else {
            unsigned k = getRelImmU64(0);
            unsigned r = newTmpReg();
            emitLoadKWithRecord((uint8_t)r, (uint8_t)k, Rel::IMM_U64, "ret.void.zero");
            emit2(OP_RET, (uint8_t)r);
          }
          continue;
        }

        // 其它 IR 先不支持
      }
    }
  }

  // === 自检：确保 code 中引用与 g_syms / g_rels 一致 ===
  VerifyResult verify() const {
    VerifyResult vr;

    // 1) 校验每个 LOADK 的 rel 索引与预期种类
    for (auto& u : RelUses_) {
      if (u.k >= GRel_.size()) {
        vr.ok = false;
        vr.errors.push_back(msgf("LOADK at %zu uses rel[%u] out of range (size=%zu)",
                                 u.code_off, u.k, GRel_.size()));
        continue;
      }
      const Rel& R = GRel_[u.k];
      if (u.expected != KindAny && R.kind != u.expected) {
        vr.ok = false;
        vr.errors.push_back(msgf("LOADK at %zu expects %s but rel[%u] is %s (ctx=%s)",
                    u.code_off, kindName(u.expected), u.k, kindName(R.kind), u.ctx.c_str()));
      }
      // 负数立即数检查（可选）：IMM_U64 中应是 i32 二补形态（我们编码时已保证）
      if (R.kind == Rel::IMM_U64 && (int32_t)(uint32_t)R.imm < 0) {
        // ok：负数保留了 i32 二补；不算错误，仅提示
        vr.warnings.push_back(msgf("IMM_U64 rel[%u] is negative i32 value 0x%08x", u.k, (unsigned)(uint32_t)R.imm));
      }
    }

    // 2) 校验每个 CALL_SYM 的 sym 索引和参数数
    for (auto& c : SymCalls_) {
      if (c.sym >= GSyms_.size()) {
        vr.ok = false;
        vr.errors.push_back(msgf("CALL_SYM at %zu uses sym[%u] out of range (size=%zu)",
                                 c.code_off, c.sym, GSyms_.size()));
      }
      if (c.argc > c.pushed_before) {
        vr.ok = false;
        vr.errors.push_back(msgf("CALL_SYM at %zu argc=%u > pushed=%u since last CLEARARGS",
                                 c.code_off, c.argc, c.pushed_before));
      }
      if (c.argc == 0) {
        vr.warnings.push_back(msgf("CALL_SYM at %zu has argc=0", c.code_off));
      }
      // 额外：printf 第一个参数应为 CSTR（通过上面的 RelUses_ 已检查）
    }

    return vr;
  }

  // === 结果访问 ===
  const std::vector<uint8_t>&               code()  const { return Code_;  }
  const std::vector<std::string>&           gsyms() const { return GSyms_; }
  const std::vector<Rel>&                   grels() const { return GRel_;  }

  void clear() {
    Code_.clear(); GSyms_.clear(); GRel_.clear();
    RegMap_.clear(); ArgIndex_.clear();
    RelImmMemo_.clear(); RelStrMemo_.clear(); SymMemo_.clear();
    RelUses_.clear(); SymCalls_.clear();
    nextReg_ = 2; currentPushCount_ = 0;
  }

// ===== 在 class IRVMTool 的 public: 区域里新增 =====
  // 把内部的 GRel_ 生成一个全局表：@Name = constant [N x i8*]
  // 返回值：nullptr 表示 N==0（无条目）；否则返回 GlobalVariable*
  llvm::GlobalVariable* emitGRelVoidPtrTable(llvm::Module& M, llvm::StringRef Name) const {
    using namespace llvm;
    if (GRel_.empty()) return nullptr;

    LLVMContext& Ctx = M.getContext();
    Type* I8Ptr   = Type::getInt8PtrTy(Ctx);
    Type* IntPtrT = M.getDataLayout().getIntPtrType(Ctx); // 32/64 位自适应

    auto makeVoidPtrFromU64 = [&](uint64_t v)->Constant* {
      Constant* Ci = ConstantInt::get(IntPtrT, v);
      return ConstantExpr::getIntToPtr(Ci, I8Ptr); // (void*)(uintptr_t)v
    };

    auto makeCStringPtrGlobal = [&](llvm::StringRef S, llvm::StringRef Prefix)->Constant* {
      auto* CDA = ConstantDataArray::getString(Ctx, S, /*AddNull=*/true);
      auto* GV  = new GlobalVariable(M, CDA->getType(), /*isConst=*/true,
                                     GlobalValue::PrivateLinkage, CDA,
                                     (Prefix + ".str").str());
      GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
      GV->setAlignment(Align(1));
      Constant* Z64 = ConstantInt::get(Type::getInt64Ty(Ctx), 0);
      Constant* Idx[] = { Z64, Z64 };
      Constant* P = ConstantExpr::getInBoundsGetElementPtr(
          GV->getValueType(), GV, ArrayRef<Constant*>(Idx, 2)); // &S[0]
      if (P->getType() != I8Ptr) P = ConstantExpr::getBitCast(P, I8Ptr);
      return P; // i8*
    };

    std::vector<Constant*> elems;
    elems.reserve(GRel_.size());
    unsigned si = 0;
    for (const auto& r : GRel_) {
      if (r.kind == Rel::IMM_U64) {
        elems.push_back(makeVoidPtrFromU64(r.imm));
      } else { // CSTR
        auto prefix = (Name + ".c" + Twine(si++)).str();
elems.push_back(makeCStringPtrGlobal(r.cstr, prefix));
      }
    }

    auto* ArrTy = ArrayType::get(I8Ptr, elems.size());
    auto* ArrC  = ConstantArray::get(ArrTy, elems);
    auto* GV = new GlobalVariable(M, ArrTy, /*isConst=*/true,
                                  GlobalValue::ExternalLinkage, ArrC, Name.str());
    GV->setUnnamedAddr(GlobalValue::UnnamedAddr::Global);
    GV->setAlignment(Align(M.getDataLayout().getPointerABIAlignment(0)));
    return GV;
  }



private:
  // 输出池
  std::vector<uint8_t>     Code_;
  std::vector<std::string> GSyms_;
  std::vector<Rel>         GRel_;

  // 状态
  std::unordered_map<const llvm::Value*, unsigned> RegMap_;
  std::unordered_map<const llvm::Value*, unsigned> ArgIndex_;
  struct PairHash {
    size_t operator()(const std::pair<uint8_t,uint64_t>& p) const noexcept {
      return (size_t)p.first ^ (size_t)(p.second * 1315423911u);
    }
  };
  std::unordered_map<std::pair<uint8_t,uint64_t>, unsigned, PairHash> RelImmMemo_;
  std::unordered_map<std::string, unsigned> RelStrMemo_;
  std::unordered_map<std::string, unsigned> SymMemo_;
  unsigned nextReg_ = 2;

  // 记录用途：用于自检
  enum ExpectKind : uint8_t { KindAny = 0xFF };
  struct RelUse { size_t code_off; unsigned k; uint8_t expected; std::string ctx; };
  struct SymUse { size_t code_off; unsigned sym; uint8_t argc; unsigned pushed_before; };
  std::vector<RelUse> RelUses_;
  std::vector<SymUse> SymCalls_;
  unsigned currentPushCount_ = 0;

  // 发码（带 code_off）
  void emit1(uint8_t op) { Code_.push_back(op); if (op==OP_CLEARARGS) currentPushCount_ = 0; }
  void emit2(uint8_t op, uint8_t a){ Code_.push_back(op); Code_.push_back(a); if (op==OP_PUSHARG) ++currentPushCount_; }
  void emit3(uint8_t op, uint8_t a, uint8_t b){ Code_.push_back(op); Code_.push_back(a); Code_.push_back(b); }
  void emit4(uint8_t op, uint8_t a, uint8_t b, uint8_t c){ Code_.push_back(op); Code_.push_back(a); Code_.push_back(b); Code_.push_back(c); }

  // 记录型发码
  void emitLoadKWithRecord(uint8_t rd, uint8_t k, uint8_t expectedKind, const char* ctx) {
    size_t off = Code_.size();
    emit3(OP_LOADK, rd, k);
    RelUses_.push_back(RelUse{off, k, expectedKind, ctx?ctx:""});
  }
  void emitCallSymWithRecord(uint8_t sym, uint8_t argc) {
    size_t off = Code_.size();
    emit3(OP_CALL_SYM, sym, argc);
    SymCalls_.push_back(SymUse{off, sym, argc, currentPushCount_});
    // CALL_SYM 不清空参数；按调用者是否随后 CLEARARGS
  }

  // 工具
  void warn(const char* msg, const llvm::Instruction* I) {
    llvm::errs() << "[IRVMTool] " << msg << ": " << *I << "\n";
  }
  static const char* kindName(uint8_t k) {
    if (k == Rel::IMM_U64) return "IMM_U64";
    if (k == Rel::CSTR)    return "CSTR";
    return "ANY";
  }


  static std::string msgf(const char* fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    char buf[512]; vsnprintf(buf, sizeof(buf), fmt, ap); va_end(ap);
    return std::string(buf);
  }

  unsigned newTmpReg() { unsigned r = nextReg_++; assert(r < 16 && "register spill not implemented"); return r; }

  unsigned getReg(const llvm::Value* V) {
    auto it = RegMap_.find(V);
    if (it != RegMap_.end()) return it->second;
    unsigned r = newTmpReg();
    RegMap_[V] = r;
    return r;
  }

  void ensureArgLoaded(const llvm::Value* V, unsigned rd) {
    auto it = ArgIndex_.find(V);
    if (it != ArgIndex_.end()) {
      if (RegMap_.find(V) == RegMap_.end()) {
        emit3(OP_LDARG, (uint8_t)rd, (uint8_t)it->second);
        RegMap_[V] = rd;
      }
    }
  }

  void ensurePointerComputed(const llvm::Value* Ptr) {
    (void)Ptr; // alloca 的地址在遇到时已写入其寄存器
  }

  // —— 核心：i32 值物化（**有符号**处理）——
  // 立即数：用 getSExtValue() 拿“有符号 i32”，再存入 IMM_U64（低 32 位保留二补）
  // 有符号 i32 物化，优先处理函数参数，强制发 LDARG
  unsigned materializeI32(llvm::Value* V, const char* ctx) {
    using namespace llvm;

    // 1) 参数 -> 直接发 LDARG（只发一次）
    if (auto* A = dyn_cast<Argument>(V)) {
      auto it = RegMap_.find(A);
      if (it != RegMap_.end()) return it->second;
      unsigned r = newTmpReg();
      auto ai = ArgIndex_.find(A); assert(ai != ArgIndex_.end());
      emit3(OP_LDARG, (uint8_t)r, (uint8_t)ai->second);
      RegMap_[A] = r;
      return r;
    }

    // 2) 常量 -> LOADK (IMM_U64，保存 i32 二补)
    if (auto* C = dyn_cast<ConstantInt>(V)) {
      int64_t s  = C->getSExtValue();
      uint32_t i = (uint32_t)(int32_t)s;
      unsigned k = getRelImmU64((uint64_t)i);
      unsigned r = newTmpReg();
      emitLoadKWithRecord((uint8_t)r, (uint8_t)k, Rel::IMM_U64, ctx ? ctx : "i32.imm");
      return r;
    }

    // 3) 其他值
    auto it = RegMap_.find(V);
    if (it != RegMap_.end()) return it->second;
    unsigned r = newTmpReg();
    RegMap_[V] = r;
    return r;
  }

  // 常量表索引
  unsigned getRelImmU64(uint64_t imm) {
    auto key = std::make_pair((uint8_t)Rel::IMM_U64, imm);
    auto it  = RelImmMemo_.find(key);
    if (it != RelImmMemo_.end()) return it->second;
    unsigned idx = (unsigned)GRel_.size();
    GRel_.push_back(Rel{Rel::IMM_U64, imm, {}});
    RelImmMemo_[key] = idx;
    return idx;
  }
  unsigned getRelCStr(const std::string& s) {
    auto it = RelStrMemo_.find(s);
    if (it != RelStrMemo_.end()) return it->second;
    unsigned idx = (unsigned)GRel_.size();
    GRel_.push_back(Rel{Rel::CSTR, 0, s});
    RelStrMemo_[s] = idx;
    return idx;
  }

  // 符号名表
  unsigned getSym(const std::string& name) {
    auto it = SymMemo_.find(name);
    if (it != SymMemo_.end()) return it->second;
    unsigned idx = (unsigned)GSyms_.size();
    GSyms_.push_back(name);
    SymMemo_[name] = idx;
    return idx;
  }

  // 提取全局 C 字符串（支持 bitcast/gep 常量表达式）
  bool extractCStringFromValue(llvm::Value* V, std::string& out) {
    using namespace llvm;
    const Value* cur = V;
    while (auto* CE = dyn_cast<ConstantExpr>(cur)) {
      if (CE->getOpcode() == Instruction::BitCast ||
          CE->getOpcode() == Instruction::GetElementPtr) {
        cur = CE->getOperand(0);
      } else break;
    }
    const GlobalVariable* GV = dyn_cast<GlobalVariable>(cur);
    if (!GV || !GV->hasInitializer()) return false;
    const Constant* Init = GV->getInitializer();

    if (auto* CDA = dyn_cast<ConstantDataArray>(Init)) {
      if (!CDA->isString()) return false;
      out = CDA->getAsCString().str();
      return true;
    }
    if (auto* CA = dyn_cast<ConstantArray>(Init)) {
      if (!CA->getType()->getElementType()->isIntegerTy(8)) return false;
      std::string s; s.reserve(CA->getNumOperands());
      for (auto& Op : CA->operands()) {
        if (auto* CI = dyn_cast<ConstantInt>(Op)) {
          uint64_t ch = CI->getZExtValue() & 0xFFu;
          if (ch == 0) break;
          s.push_back((char)ch);
        } else return false;
      }
      out = std::move(s);
      return true;
    }
    return false;
  }




};

} // namespace irvm
