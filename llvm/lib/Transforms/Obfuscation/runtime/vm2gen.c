// vm2gen.c — DEV-TIME generator for the level-2 VM programs (vm2_prog.h).
//
// Not shipped in builds, not compiled into any target: run it on the host to
// (re)generate runtime/vm2_prog.h:
//
//     cc vm2gen.c -o vm2gen && ./vm2gen > vm2_prog.h
//
// The three programs transliterate vm_exec.c's native evaluators
// (arith_eval / cmp_eval / cast_eval) branch-for-branch into L2 stack
// bytecode. Correctness is NOT trusted from transliteration alone —
// test_vm2.c cross-checks vm2_* against the native evaluators exhaustively;
// any drift fails the tests.
//
// Constants mirrored from vm_exec.c (AR_* sub-ops, FCMP_/ICMP_ predicates,
// CC_* cast kinds); the equivalence tests make any drift loud.
#include "vm2_exec.h"
#include "vm_crypt.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* AR_* (arith sub-ops, mirror vm_exec.c) */
enum { AR_ADD=0, AR_SUB, AR_MUL, AR_UDIV, AR_SDIV, AR_UREM, AR_SREM,
       AR_SHL, AR_LSHR, AR_ASHR, AR_AND, AR_OR, AR_XOR,
       AR_FADD, AR_FSUB, AR_FMUL, AR_FDIV, AR_FREM };
/* preds */
enum { ICMP_EQ=32, ICMP_NE, ICMP_UGT, ICMP_UGE, ICMP_ULT, ICMP_ULE,
       ICMP_SGT, ICMP_SGE, ICMP_SLT, ICMP_SLE };
/* CC_* */
enum { CC_TRUNC=1, CC_ZEXT, CC_SEXT, CC_FPTOUI, CC_FPTOSI,
       CC_UITOFP, CC_SITOFP, CC_FPTRUNC, CC_FPEXT, CC_PTRTOINT,
       CC_INTTOPTR, CC_BITCAST };

#define INT64MIN 0x8000000000000000ull
#define ALLONES  0xFFFFFFFFFFFFFFFFull

// ---------------------------------------------------------------------------
// tiny assembler: buffer + labels + rel32 backpatching
// ---------------------------------------------------------------------------
enum { MAXF = 8192 };
typedef struct {
  uint8_t b[65536];
  size_t n;
  size_t lblpos[1024];
  int nlbl;
  struct { size_t at; int l; } fix[MAXF];
  int nfix;
} P;

static void e8(P *p, uint8_t v)  { p->b[p->n++] = v; }
static void e32(P *p, uint32_t v){ for (int i=0;i<4;i++) e8(p,(uint8_t)(v>>(i*8))); }
static void eimm(P *p, uint64_t v){ for (int i=0;i<8;i++) e8(p,(uint8_t)(v>>(i*8))); }

static int  mklbl(P *p)            { return p->nlbl++; }
static void lbl(P *p, int l)       { p->lblpos[l] = p->n; }
static void j(P *p, uint8_t op, int l) {
  e8(p, op);
  p->fix[p->nfix].at = p->n; p->fix[p->nfix].l = l; p->nfix++;
  e32(p, 0);
}
static void patch(P *p) {
  for (int i = 0; i < p->nfix; i++) {
    size_t at   = p->fix[i].at;
    int    l    = p->fix[i].l;
    int64_t rel = (int64_t)p->lblpos[l] - (int64_t)(at + 4);
    p->b[at+0] = (uint8_t)(rel);
    p->b[at+1] = (uint8_t)(rel >> 8);
    p->b[at+2] = (uint8_t)(rel >> 16);
    p->b[at+3] = (uint8_t)(rel >> 24);
  }
}

// emit shorthands -------------------------------------------------------------
static void pushimm(P *p, uint64_t v) { e8(p, VM2_PUSH_IMM); eimm(p, v); }
static void pushl(P *p, int l)        { e8(p, VM2_PUSH_L); e8(p, (uint8_t)l); }
static void storel(P *p, int l)       { e8(p, VM2_STORE_L); e8(p, (uint8_t)l); }
static void bin(P *p, uint8_t op)     { e8(p, op); }
static void retp(P *p)                { e8(p, VM2_RET); }

/* push local l; push imm k; compare == ; JMPT label  (dispatch on a local) */
static void casel(P *p, int l, uint64_t k, int target) {
  pushl(p, l); pushimm(p, k); bin(p, VM2_EQ); j(p, VM2_JMPT, target);
}

/* mask(bits local bl) onto stack: bits>=64 ? ~0 : (1<<bits)-1 */
static void emit_mask(P *p, int bl) {
  int m64 = mklbl(p), mend = mklbl(p);
  pushl(p, bl); pushimm(p, 64); bin(p, VM2_GEU); j(p, VM2_JMPT, m64);
  pushimm(p, 1); pushl(p, bl); bin(p, VM2_SHL); pushimm(p, 1); bin(p, VM2_SUB);
  j(p, VM2_JMP, mend);
  lbl(p, m64); pushimm(p, ALLONES);
  lbl(p, mend);
}

/* sext(local vl with width local bl) onto stack  (sext_to_64 transliteration:
   bits==0 or bits>=64 -> value unchanged; else set high bits from the sign) */
static void emit_sext(P *p, int vl, int bl) {
  int lbig = mklbl(p), lpos = mklbl(p), lend = mklbl(p), lend2 = mklbl(p);
  pushl(p, bl); pushimm(p, 64); bin(p, VM2_GEU); j(p, VM2_JMPT, lbig);
  pushl(p, vl);
  pushl(p, vl); pushl(p, bl); pushimm(p, 1); bin(p, VM2_SUB);
  bin(p, VM2_LSHR); pushimm(p, 1); bin(p, VM2_AND);
  j(p, VM2_JMPT, lpos);
  j(p, VM2_JMP, lend);
  lbl(p, lpos); e8(p, VM2_DROP);
  pushl(p, vl); pushimm(p, ALLONES); pushl(p, bl); bin(p, VM2_SHL); bin(p, VM2_OR);
  lbl(p, lend); j(p, VM2_JMP, lend2);
  lbl(p, lbig); pushl(p, vl);
  lbl(p, lend2);
}

/* if local l != 0 jump target  (zero guard) */
static void jnzl(P *p, int l, int target) { pushl(p, l); j(p, VM2_JMPT, target); }

/* isnan(local) for width w (32/64), leaves 0/1 */
static void emit_isnan(P *p, int l, int w) {
  pushl(p, l); e8(p, w == 32 ? VM2_ISNAN32 : VM2_ISNAN64);
}

// ---------------------------------------------------------------------------
// gen_arith: locals L0=sub L1=tk L2=bits L3=a L4=b L5=mask L6=sa L7=sb
//            L8=x L9=y (scratch, SDIV/SREM)
// ---------------------------------------------------------------------------
static void gen_arith(P *p) {
  int L_fp = mklbl(p), L_f32 = mklbl(p), L_finf = mklbl(p), L_fin = mklbl(p);
  int sub[13] = {AR_ADD,AR_SUB,AR_MUL,AR_UDIV,AR_SDIV,AR_UREM,AR_SREM,
                 AR_SHL,AR_LSHR,AR_ASHR,AR_AND,AR_OR,AR_XOR};
  int subl[13]; for (int i=0;i<13;i++) subl[i]=mklbl(p);

  casel(p, 1, 1, L_fp);                       // tk==1 -> fp

  // ---- integer path ----
  emit_mask(p, 2); storel(p, 5);              // L5 = mask
  pushl(p, 3); pushl(p, 5); bin(p, VM2_AND); storel(p, 6);   // L6 = sa
  pushl(p, 4); pushl(p, 5); bin(p, VM2_AND); storel(p, 7);   // L7 = sb
  for (int i=0;i<13;i++) casel(p, 0, (uint64_t)sub[i], subl[i]);
  pushimm(p, 0); j(p, VM2_JMP, L_fin);        // default

  lbl(p, subl[0]);  pushl(p,6); pushl(p,7); bin(p,VM2_ADD);  j(p,VM2_JMP,L_fin); // ADD
  lbl(p, subl[1]);  pushl(p,6); pushl(p,7); bin(p,VM2_SUB);  j(p,VM2_JMP,L_fin);
  lbl(p, subl[2]);  pushl(p,6); pushl(p,7); bin(p,VM2_MUL);  j(p,VM2_JMP,L_fin);
  { // UDIV: sb? sa/sb : 0
    int nz = mklbl(p);
    lbl(p, subl[3]);
    jnzl(p, 7, nz); pushimm(p, 0); j(p, VM2_JMP, L_fin);
    lbl(p, nz); pushl(p,6); pushl(p,7); bin(p,VM2_UDIV); j(p,VM2_JMP,L_fin);
  }
  { // SDIV: sb? (overflow? x : x/y) : 0
    int nz = mklbl(p), ov = mklbl(p);
    lbl(p, subl[4]);
    jnzl(p, 7, nz); pushimm(p, 0); j(p, VM2_JMP, L_fin);
    lbl(p, nz);
    emit_sext(p, 6, 2); storel(p, 8);         // x
    emit_sext(p, 7, 2); storel(p, 9);         // y
    pushl(p,8); pushimm(p,INT64MIN); bin(p,VM2_EQ);
    pushl(p,9); pushimm(p,ALLONES); bin(p,VM2_EQ);
    bin(p, VM2_AND); j(p, VM2_JMPT, ov);
    pushl(p,8); pushl(p,9); bin(p,VM2_SDIV); j(p,VM2_JMP,L_fin);
    lbl(p, ov); pushl(p,8); j(p,VM2_JMP,L_fin);
  }
  { // UREM
    int nz = mklbl(p);
    lbl(p, subl[5]);
    jnzl(p, 7, nz); pushimm(p, 0); j(p, VM2_JMP, L_fin);
    lbl(p, nz); pushl(p,6); pushl(p,7); bin(p,VM2_UREM); j(p,VM2_JMP,L_fin);
  }
  { // SREM: overflow -> 0
    int nz = mklbl(p), ov = mklbl(p);
    lbl(p, subl[6]);
    jnzl(p, 7, nz); pushimm(p, 0); j(p, VM2_JMP, L_fin);
    lbl(p, nz);
    emit_sext(p, 6, 2); storel(p, 8);
    emit_sext(p, 7, 2); storel(p, 9);
    pushl(p,8); pushimm(p,INT64MIN); bin(p,VM2_EQ);
    pushl(p,9); pushimm(p,ALLONES); bin(p,VM2_EQ);
    bin(p, VM2_AND); j(p, VM2_JMPT, ov);
    pushl(p,8); pushl(p,9); bin(p,VM2_SREM); j(p,VM2_JMP,L_fin);
    lbl(p, ov); pushimm(p, 0); j(p,VM2_JMP,L_fin);
  }
  lbl(p, subl[7]);  pushl(p,6); pushl(p,7); pushimm(p,63); bin(p,VM2_AND);
                    bin(p,VM2_SHL); j(p,VM2_JMP,L_fin);              // SHL
  { // LSHR: bits>=64 ? sa>>(sb&63) : sa>>(sb%64)
    int l64 = mklbl(p);
    lbl(p, subl[8]);
    pushl(p,2); pushimm(p,64); bin(p,VM2_GEU); j(p,VM2_JMPT,l64);
    pushl(p,6); pushl(p,7); pushimm(p,64); bin(p,VM2_UREM);
    bin(p,VM2_LSHR); j(p,VM2_JMP,L_fin);
    lbl(p, l64);
    pushl(p,6); pushl(p,7); pushimm(p,63); bin(p,VM2_AND);
    bin(p,VM2_LSHR); j(p,VM2_JMP,L_fin);
  }
  lbl(p, subl[9]);  emit_sext(p, 6, 2); pushl(p,7); pushimm(p,63); bin(p,VM2_AND);
                    bin(p,VM2_SAR); j(p,VM2_JMP,L_fin);               // ASHR
  lbl(p, subl[10]); pushl(p,6); pushl(p,7); bin(p,VM2_AND); j(p,VM2_JMP,L_fin);
  lbl(p, subl[11]); pushl(p,6); pushl(p,7); bin(p,VM2_OR);  j(p,VM2_JMP,L_fin);
  lbl(p, subl[12]); pushl(p,6); pushl(p,7); bin(p,VM2_XOR); j(p,VM2_JMP,L_fin);

  lbl(p, L_fin); pushl(p, 5); bin(p, VM2_AND); retp(p);   // r & mask

  // ---- fp path ----
  lbl(p, L_fp);
  casel(p, 2, 32, L_f32);
  { // f64
    int fl[5] = {AR_FADD,AR_FSUB,AR_FMUL,AR_FDIV,AR_FREM};
    uint8_t ops[5] = {VM2_FADD64,VM2_FSUB64,VM2_FMUL64,VM2_FDIV64,VM2_FREM64};
    int lab[5]; for (int i=0;i<5;i++) lab[i]=mklbl(p);
    for (int i=0;i<5;i++) casel(p, 0, (uint64_t)fl[i], lab[i]);
    pushimm(p, 0); j(p, VM2_JMP, L_finf);
    for (int i=0;i<5;i++) {
      lbl(p, lab[i]);
      pushl(p,3); pushl(p,4); bin(p, ops[i]); j(p, VM2_JMP, L_finf);
    }
    lbl(p, L_finf); retp(p);
  }
  { // f32
    lbl(p, L_f32);
    int fend = mklbl(p);
    int fl[5] = {AR_FADD,AR_FSUB,AR_FMUL,AR_FDIV,AR_FREM};
    uint8_t ops[5] = {VM2_FADD32,VM2_FSUB32,VM2_FMUL32,VM2_FDIV32,VM2_FREM32};
    int lab[5]; for (int i=0;i<5;i++) lab[i]=mklbl(p);
    for (int i=0;i<5;i++) casel(p, 0, (uint64_t)fl[i], lab[i]);
    pushimm(p, 0); j(p, VM2_JMP, fend);
    for (int i=0;i<5;i++) {
      lbl(p, lab[i]);
      pushl(p,3); pushl(p,4); bin(p, ops[i]); j(p, VM2_JMP, fend);
    }
    lbl(p, fend); retp(p);
  }
  patch(p);
}

// ---------------------------------------------------------------------------
// gen_cmp: L0=pred L1=a L2=b L3=obits
// ---------------------------------------------------------------------------
static void gen_cmp(P *p) {
  int Lfp = mklbl(p), Lf32 = mklbl(p), Lfin = mklbl(p);
  int ipr[10] = {ICMP_EQ,ICMP_NE,ICMP_UGT,ICMP_UGE,ICMP_ULT,ICMP_ULE,
                 ICMP_SGT,ICMP_SGE,ICMP_SLT,ICMP_SLE};
  uint8_t iop[10] = {VM2_EQ,VM2_NE,VM2_GTU,VM2_GEU,VM2_LTU,VM2_LEU,
                     VM2_GTS,VM2_GES,VM2_LTS,VM2_LES};
  int ilab[10]; for (int i=0;i<10;i++) ilab[i]=mklbl(p);

  pushl(p,0); pushimm(p,16); bin(p,VM2_LTU); j(p,VM2_JMPT,Lfp); // pred<16 -> fp

  for (int i=0;i<10;i++) casel(p, 0, (uint64_t)ipr[i], ilab[i]);
  pushimm(p, 0); j(p, VM2_JMP, Lfin);
  for (int i=0;i<6;i++) {                    // unsigned & eq/ne: raw a b
    lbl(p, ilab[i]);
    pushl(p,1); pushl(p,2); bin(p, iop[i]); j(p, VM2_JMP, Lfin);
  }
  for (int i=6;i<10;i++) {                   // signed: sext both by obits
    lbl(p, ilab[i]);
    emit_sext(p, 1, 3); storel(p, 8);
    emit_sext(p, 2, 3); storel(p, 9);
    pushl(p,8); pushl(p,9); bin(p, iop[i]); j(p, VM2_JMP, Lfin);
  }
  lbl(p, Lfin); retp(p);

  // ---- fp ----
  lbl(p, Lfp);
  casel(p, 3, 32, Lf32);
  { // f64: preds 0..15
    int lab[16]; for (int i=0;i<16;i++) lab[i]=mklbl(p);
    int fend = mklbl(p);
    for (int i=0;i<16;i++) casel(p, 0, (uint64_t)i, lab[i]);
    pushimm(p, 0); j(p, VM2_JMP, fend);      // unreachable default
    lbl(p, lab[0]);  pushimm(p,0); j(p,VM2_JMP,fend);            // FALSE
    lbl(p, lab[1]);  pushl(p,1); pushl(p,2); bin(p,VM2_FEQ64); j(p,VM2_JMP,fend);
    lbl(p, lab[2]);  pushl(p,1); pushl(p,2); bin(p,VM2_FGT64); j(p,VM2_JMP,fend);
    lbl(p, lab[3]);  pushl(p,1); pushl(p,2); bin(p,VM2_FGE64); j(p,VM2_JMP,fend);
    lbl(p, lab[4]);  pushl(p,1); pushl(p,2); bin(p,VM2_FLT64); j(p,VM2_JMP,fend);
    lbl(p, lab[5]);  pushl(p,1); pushl(p,2); bin(p,VM2_FLE64); j(p,VM2_JMP,fend);
    lbl(p, lab[6]);  pushl(p,1); pushl(p,2); bin(p,VM2_FNE64); j(p,VM2_JMP,fend);
    { // ORD(7): !nan(x) && !nan(y)
      int z = mklbl(p);
      lbl(p, lab[7]);
      emit_isnan(p,1,64); j(p,VM2_JMPT,z);
      emit_isnan(p,2,64); j(p,VM2_JMPT,z);
      pushimm(p,1); j(p,VM2_JMP,fend);
      lbl(p, z); pushimm(p,0); j(p,VM2_JMP,fend);
    }
    { // UNO(8)
      int u = mklbl(p);
      lbl(p, lab[8]);
      emit_isnan(p,1,64); j(p,VM2_JMPT,u);
      emit_isnan(p,2,64); j(p,VM2_JMPT,u);
      pushimm(p,0); j(p,VM2_JMP,fend);
      lbl(p, u); pushimm(p,1); j(p,VM2_JMP,fend);
    }
    // UEQ/UGT/UGE/ULT/ULE (9..13): native code is `cmp || (x!=x && y!=y)`
    // (inherited from vm_exec.c — transliterated EXACTLY, quirks included)
    {
      uint8_t ops[5] = {VM2_FEQ64,VM2_FGT64,VM2_FGE64,VM2_FLT64,VM2_FLE64};
      for (int k=0;k<5;k++) {
        int t = mklbl(p), n2 = mklbl(p), f = mklbl(p);
        lbl(p, lab[9+k]);
        pushl(p,1); pushl(p,2); bin(p,ops[k]); j(p,VM2_JMPT,t);
        emit_isnan(p,1,64); j(p,VM2_JMPT,n2);
        pushimm(p,0); j(p,VM2_JMP,f);
        lbl(p, n2); emit_isnan(p,2,64); j(p,VM2_JMPT,t);
        pushimm(p,0); j(p,VM2_JMP,f);
        lbl(p, t); pushimm(p,1);
        lbl(p, f); j(p, VM2_JMP, fend);
      }
    }
    lbl(p, lab[14]); pushl(p,1); pushl(p,2); bin(p,VM2_FNE64); j(p,VM2_JMP,fend);
    lbl(p, lab[15]); pushimm(p,1); j(p,VM2_JMP,fend);             // TRUE
    lbl(p, fend); retp(p);
  }
  { // f32 mirror
    lbl(p, Lf32);
    int lab[16]; for (int i=0;i<16;i++) lab[i]=mklbl(p);
    int fend = mklbl(p);
    for (int i=0;i<16;i++) casel(p, 0, (uint64_t)i, lab[i]);
    pushimm(p, 0); j(p, VM2_JMP, fend);
    lbl(p, lab[0]);  pushimm(p,0); j(p,VM2_JMP,fend);
    lbl(p, lab[1]);  pushl(p,1); pushl(p,2); bin(p,VM2_FEQ32); j(p,VM2_JMP,fend);
    lbl(p, lab[2]);  pushl(p,1); pushl(p,2); bin(p,VM2_FGT32); j(p,VM2_JMP,fend);
    lbl(p, lab[3]);  pushl(p,1); pushl(p,2); bin(p,VM2_FGE32); j(p,VM2_JMP,fend);
    lbl(p, lab[4]);  pushl(p,1); pushl(p,2); bin(p,VM2_FLT32); j(p,VM2_JMP,fend);
    lbl(p, lab[5]);  pushl(p,1); pushl(p,2); bin(p,VM2_FLE32); j(p,VM2_JMP,fend);
    lbl(p, lab[6]);  pushl(p,1); pushl(p,2); bin(p,VM2_FNE32); j(p,VM2_JMP,fend);
    {
      int z = mklbl(p);
      lbl(p, lab[7]);
      emit_isnan(p,1,32); j(p,VM2_JMPT,z);
      emit_isnan(p,2,32); j(p,VM2_JMPT,z);
      pushimm(p,1); j(p,VM2_JMP,fend);
      lbl(p, z); pushimm(p,0); j(p,VM2_JMP,fend);
    }
    {
      int u = mklbl(p);
      lbl(p, lab[8]);
      emit_isnan(p,1,32); j(p,VM2_JMPT,u);
      emit_isnan(p,2,32); j(p,VM2_JMPT,u);
      pushimm(p,0); j(p,VM2_JMP,fend);
      lbl(p, u); pushimm(p,1); j(p,VM2_JMP,fend);
    }
    {
      uint8_t ops[5] = {VM2_FEQ32,VM2_FGT32,VM2_FGE32,VM2_FLT32,VM2_FLE32};
      for (int k=0;k<5;k++) {
        int t = mklbl(p), n2 = mklbl(p), f = mklbl(p);
        lbl(p, lab[9+k]);
        pushl(p,1); pushl(p,2); bin(p,ops[k]); j(p,VM2_JMPT,t);
        emit_isnan(p,1,32); j(p,VM2_JMPT,n2);
        pushimm(p,0); j(p,VM2_JMP,f);
        lbl(p, n2); emit_isnan(p,2,32); j(p,VM2_JMPT,t);
        pushimm(p,0); j(p,VM2_JMP,f);
        lbl(p, t); pushimm(p,1);
        lbl(p, f); j(p, VM2_JMP, fend);
      }
    }
    lbl(p, lab[14]); pushl(p,1); pushl(p,2); bin(p,VM2_FNE32); j(p,VM2_JMP,fend);
    lbl(p, lab[15]); pushimm(p,1); j(p,VM2_JMP,fend);
    lbl(p, fend); retp(p);
  }
  patch(p);
}

// ---------------------------------------------------------------------------
// gen_cast: L0=cop L1=sbits L2=dbits L3=v
// ---------------------------------------------------------------------------
static void gen_cast(P *p) {
  int Lfin = mklbl(p);
  int lab[12]; for (int i=0;i<12;i++) lab[i]=mklbl(p);
  for (int i=0;i<12;i++) casel(p, 0, (uint64_t)(i+1), lab[i]);
  pushl(p,3); j(p, VM2_JMP, Lfin);           // default: identity

  lbl(p, lab[0]);  emit_mask(p, 2); pushl(p,3); bin(p,VM2_AND); j(p,VM2_JMP,Lfin); // TRUNC
  lbl(p, lab[1]);  pushl(p,3); j(p,VM2_JMP,Lfin);                                 // ZEXT
  lbl(p, lab[2]);  emit_sext(p, 3, 1); j(p,VM2_JMP,Lfin);                          // SEXT
  { // FPTOUI / FPTOSI / UITOFP / SITOFP: width branch on sbits or dbits
    int w32;
    lbl(p, lab[3]);                                        // FPTOUI
    w32 = mklbl(p);
    casel(p, 1, 32, w32);
    pushl(p,3); bin(p,VM2_FPTOUI64); j(p,VM2_JMP,Lfin);
    lbl(p, w32); pushl(p,3); bin(p,VM2_FPTOUI32); j(p,VM2_JMP,Lfin);

    lbl(p, lab[4]);                                        // FPTOSI
    w32 = mklbl(p);
    casel(p, 1, 32, w32);
    pushl(p,3); bin(p,VM2_FPTOSI64); j(p,VM2_JMP,Lfin);
    lbl(p, w32); pushl(p,3); bin(p,VM2_FPTOSI32); j(p,VM2_JMP,Lfin);

    lbl(p, lab[5]);                                        // UITOFP
    w32 = mklbl(p);
    casel(p, 2, 32, w32);
    pushl(p,3); bin(p,VM2_UITOFP64); j(p,VM2_JMP,Lfin);
    lbl(p, w32); pushl(p,3); bin(p,VM2_UITOFP32); j(p,VM2_JMP,Lfin);

    lbl(p, lab[6]);                                        // SITOFP
    w32 = mklbl(p);
    casel(p, 2, 32, w32);
    pushl(p,3); bin(p,VM2_SITOFP64); j(p,VM2_JMP,Lfin);
    lbl(p, w32); pushl(p,3); bin(p,VM2_SITOFP32); j(p,VM2_JMP,Lfin);
  }
  lbl(p, lab[7]);  pushl(p,3); bin(p,VM2_FPTRUNC); j(p,VM2_JMP,Lfin);  // FPTRUNC
  lbl(p, lab[8]);  pushl(p,3); bin(p,VM2_FPEXT);   j(p,VM2_JMP,Lfin);  // FPEXT
  lbl(p, lab[9]);  pushl(p,3); j(p,VM2_JMP,Lfin);                      // PTRTOINT
  lbl(p, lab[10]); pushl(p,3); j(p,VM2_JMP,Lfin);                      // INTTOPTR
  lbl(p, lab[11]); pushl(p,3); j(p,VM2_JMP,Lfin);                      // BITCAST

  lbl(p, Lfin); retp(p);
  patch(p);
}

// ---------------------------------------------------------------------------
// seal & emit vm2_prog.h
// ---------------------------------------------------------------------------
static void dump_arr(FILE *f, const char *name, const uint8_t *b, size_t n) {
  fprintf(f, "static const uint8_t %s[] = {", name);
  for (size_t i = 0; i < n; i++)
    fprintf(f, "%s0x%02x,", (i % 16) ? "" : "\n    ", b[i]);
  fprintf(f, "\n};\n");
}
static void dump_key(FILE *f, const char *name, const uint8_t k[16]) {
  fprintf(f, "static const uint8_t %s[16] = {", name);
  for (int i = 0; i < 16; i++) fprintf(f, "0x%02x,", k[i]);
  fprintf(f, "};\n");
}
static void gen_out(P *p, uint64_t keyseed,
                    uint8_t key[16], uint8_t **out, size_t *outlen) {
  vm_derive_key16(key, keyseed);
  *outlen = p->n;
  *out = (uint8_t *)malloc(p->n);
  memcpy(*out, p->b, p->n);
  vm_keystream(*out, p->n, key);
}

int main(void) {
  static P pa, pc, ps;
  memset(&pa, 0, sizeof pa); memset(&pc, 0, sizeof pc); memset(&ps, 0, sizeof ps);
  pa.nlbl = pc.nlbl = ps.nlbl = 0;

  gen_arith(&pa);
  gen_cmp(&pc);
  gen_cast(&ps);

  uint8_t ka[16], kc[16], ks[16];
  uint8_t *ba, *bc, *bs; size_t na, nc, ns;
  gen_out(&pa, 0x562D1A9E00C0FFEEull, ka, &ba, &na);
  gen_out(&pc, 0x11E76B4D2A5F9031ull, kc, &bc, &nc);
  gen_out(&ps, 0x7C3A91F04E68B2D5ull, ks, &bs, &ns);

  FILE *f = stdout;
  fprintf(f, "// vm2_prog.h — GENERATED by vm2gen.c; DO NOT EDIT.\n");
  fprintf(f, "// L2 bytecode for the interpreter cores (展望③ 嵌套 VM),\n");
  fprintf(f, "// keystream-sealed with per-program keys. Regenerate:\n");
  fprintf(f, "//   cc vm2gen.c -o vm2gen && ./vm2gen > vm2_prog.h\n");
  fprintf(f, "#ifndef OBFUSCATION_IRVM_VM2_PROG_H\n");
  fprintf(f, "#define OBFUSCATION_IRVM_VM2_PROG_H\n\n");
  fprintf(f, "#define VM2_PROG_ARITH_LEN %zuu\n", na);
  fprintf(f, "#define VM2_PROG_CMP_LEN   %zuu\n", nc);
  fprintf(f, "#define VM2_PROG_CAST_LEN  %zuu\n\n", ns);
  dump_key(f, "VM2_PROG_ARITH_KEY", ka);
  dump_key(f, "VM2_PROG_CMP_KEY",   kc);
  dump_key(f, "VM2_PROG_CAST_KEY",  ks);
  fprintf(f, "\n");
  dump_arr(f, "VM2_PROG_ARITH_SEALED", ba, na);
  fprintf(f, "\n");
  dump_arr(f, "VM2_PROG_CMP_SEALED",   bc, nc);
  fprintf(f, "\n");
  dump_arr(f, "VM2_PROG_CAST_SEALED",  bs, ns);
  fprintf(f, "\n#endif\n");
  return 0;
}
