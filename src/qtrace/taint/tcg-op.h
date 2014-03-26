//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/taint.h"
#include "qtrace/taint/notify_taint.h"

#if TARGET_LONG_BITS != 32
#error 64-bit targets are not supported (yet)
#endif

#define REG_IDX(istmp, r) ((istmp) ? register_temp_index(r) : (r))

#define QTRACE_INSTRUMENT_START() {		\
    if (likely(!qtrace_taint_enabled)) {		\
      return;					\
    }						\
    if (unlikely(qtrace_instrument)) {		\
      return;					\
    }						\
    qtrace_instrument = true;			\
  }

#define QTRACE_INSTRUMENT_END() {		\
    qtrace_instrument = false;			\
  }

/* Flags for argument passed to QTrace TCG helpers */
#define QTRACE_TAINT_64BIT      (1 << 0)
#define QTRACE_TAINT_SIGNED     (1 << 1)
#define QTRACE_TAINT_CONST_WRAP (1 << 2)

#define QTRACE_ASSERT_TAINTED     0xabadb00b
#define QTRACE_ASSERT_NOT_TAINTED (QTRACE_ASSERT_TAINTED + 1)

/* Easy expression of flag-based conditions */
#define FLG(v, f) (((v) & (f)) != 0)

/* Check if an index identifies a temporary register */
static inline bool register_is_temp(target_ulong idx) {
  return idx >= tcg_ctx.nb_globals;
}

/* Get the TCG index of the "idx"-th temporary register */
static inline target_ulong register_temp_index(target_ulong idx) {
  assert(register_is_temp(idx));
  return idx - tcg_ctx.nb_globals;
}

static void tcg_helper_qtrace_assert(target_ulong reg, target_ulong istrue) {
  assert(!register_is_temp(reg));
  notify_taint_assert(REG_IDX(false, reg), istrue);
}

static void tcg_helper_qtrace_reg2mem(target_ulong reg, target_ulong addr,
                                     int size) {
  bool istmp = register_is_temp(reg);
  notify_taint_moveR2M(istmp, REG_IDX(istmp, reg), addr, size);
}

static void tcg_helper_qtrace_mem2reg(target_ulong reg, target_ulong addr,
                                     int size) {
  bool istmp = register_is_temp(reg);
  notify_taint_moveM2R(addr, size, istmp, REG_IDX(istmp, reg));
}

static void tcg_helper_qtrace_mov(target_ulong ret, target_ulong arg) {
  bool srctmp = register_is_temp(arg);
  bool dsttmp = register_is_temp(ret);
  notify_taint_moveR2R(srctmp, REG_IDX(srctmp, arg),
                       dsttmp, REG_IDX(dsttmp, ret));
}

static void tcg_helper_qtrace_clearR(target_ulong reg) {
  bool istmp = register_is_temp(reg);
  notify_taint_clearR(istmp, REG_IDX(istmp, reg));
}

static inline void tcg_helper_qtrace_endtb(void) {
  notify_taint_endtb();
}

/*
   Used for expressions like "A = A op B".

   labels(A) = labels(A) | labels(B)
 */
static void tcg_helper_qtrace_combine2(target_ulong dst, target_ulong src) {
  if (src == dst) {
    return;
  }

  bool dsttmp = register_is_temp(dst);
  bool srctmp = register_is_temp(src);

  notify_taint_combineR2R(srctmp, REG_IDX(srctmp, src),
                          dsttmp, REG_IDX(dsttmp, dst));
}

/*
   Used for expressions like "A = B op C".

   labels(A) = labels(B) | labels(C)
 */
static void tcg_helper_qtrace_combine3(target_ulong dst, target_ulong op1,
                                      target_ulong op2) {
  bool dsttmp = register_is_temp(dst);

  /* Clear destination first! */
  notify_taint_clearR(dsttmp, REG_IDX(dsttmp, dst));

  /* Combine op1 with dst */
  if (op1 != dst) {
    bool optmp = register_is_temp(op1);
    notify_taint_combineR2R(optmp,  REG_IDX(optmp, op1),
                            dsttmp, REG_IDX(dsttmp, dst));
  }

  /* Combine op2 with dst */
  if (op2 != dst) {
    bool optmp = register_is_temp(op2);
    notify_taint_combineR2R(optmp,  REG_IDX(optmp, op2),
                            dsttmp, REG_IDX(dsttmp, dst));
  }
}

/*
   Only for "deposit" QEMU opcodes.
 */
static void tcg_helper_qtrace_deposit(target_ulong dst,
                                     target_ulong op1, target_ulong op2,
                                     unsigned int ofs, unsigned int len) {
  /* We currently support only byte-level deposit instructions, also because
     taint-tracking is performed at the byte-level */
  assert((ofs % 8) == 0 && (len % 8) == 0 && (ofs+len) <= 32);

  bool dsttmp = register_is_temp(dst);
  bool op2tmp = register_is_temp(op2);

  if (dst != op1) {
    bool op1tmp = register_is_temp(op1);
    notify_taint_moveR2R(op1tmp, REG_IDX(op1tmp, op1),
                         dsttmp, REG_IDX(dsttmp, dst));
  }

  notify_taint_moveR2R_offset(op2tmp, REG_IDX(op2tmp, op2), 0,
                              dsttmp, REG_IDX(dsttmp, dst), ofs/8,
                              len/8);
}

#define OP_SET_ARG(num, var, flg)                                       \
  sizemask |= tcg_gen_sizemask((num), FLG((flg), QTRACE_TAINT_64BIT), FLG((flg), QTRACE_TAINT_SIGNED)); \
  args[num] = FLG((flg), QTRACE_TAINT_CONST_WRAP) ? tcg_const_i32((var)) : (var);

#define OP_FREE_ARG(num, flg)                                           \
  if (FLG((flg), QTRACE_TAINT_CONST_WRAP)) { tcg_temp_free_i32(args[num]); }

#define OP_CALL_HELPER()                                                \
  tcg_gen_helperN(helper, 0, sizemask, TCG_CALL_DUMMY_ARG, sizeof(args)/sizeof(TCGArg), args);

static inline void tcg_gen_qtrace_op1(void *helper,
                                     TCGArg a1, int a1_f) {
  int sizemask = 0;
  TCGArg args[1];

  QTRACE_INSTRUMENT_START();

  OP_SET_ARG(0, a1, a1_f);

  OP_CALL_HELPER();

  OP_FREE_ARG(0, a1_f);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_op2(void *helper,
                                     TCGArg a1, int a1_f,
                                     TCGArg a2, int a2_f) {
  int sizemask = 0;
  TCGArg args[2];

  QTRACE_INSTRUMENT_START();

  OP_SET_ARG(0, a1, a1_f);
  OP_SET_ARG(1, a2, a2_f);

  OP_CALL_HELPER();

  OP_FREE_ARG(0, a1_f);
  OP_FREE_ARG(1, a2_f);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_op3(void *helper,
                                     TCGArg a1, int a1_f,
                                     TCGArg a2, int a2_f,
                                     TCGArg a3, int a3_f) {
  int sizemask = 0;
  TCGArg args[3];

  QTRACE_INSTRUMENT_START();

  OP_SET_ARG(0, a1, a1_f);
  OP_SET_ARG(1, a2, a2_f);
  OP_SET_ARG(2, a3, a3_f);

  OP_CALL_HELPER();

  OP_FREE_ARG(0, a1_f);
  OP_FREE_ARG(1, a2_f);
  OP_FREE_ARG(2, a3_f);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_op5(void *helper,
                                     TCGArg a1, int a1_f,
                                     TCGArg a2, int a2_f,
                                     TCGArg a3, int a3_f,
                                     TCGArg a4, int a4_f,
                                     TCGArg a5, int a5_f) {
  int sizemask = 0;
  TCGArg args[5];

  QTRACE_INSTRUMENT_START();

  OP_SET_ARG(0, a1, a1_f);
  OP_SET_ARG(1, a2, a2_f);
  OP_SET_ARG(2, a3, a3_f);
  OP_SET_ARG(3, a4, a4_f);
  OP_SET_ARG(4, a5, a5_f);

  OP_CALL_HELPER();

  OP_FREE_ARG(0, a1_f);
  OP_FREE_ARG(1, a2_f);
  OP_FREE_ARG(2, a3_f);
  OP_FREE_ARG(3, a4_f);
  OP_FREE_ARG(4, a5_f);

  QTRACE_INSTRUMENT_END();
}

#undef OP_SET_ARG
#undef OP_FREE_ARG

static inline void tcg_gen_qtrace_endtb(void) {
  QTRACE_INSTRUMENT_START();

  tcg_gen_helperN(tcg_helper_qtrace_endtb, 0, 0, TCG_CALL_DUMMY_ARG, 0, NULL);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_ld(TCGv arg, TCGv addr, int size) {
  tcg_gen_qtrace_op3(tcg_helper_qtrace_mem2reg,
                    GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(addr), 0,
                    size, QTRACE_TAINT_CONST_WRAP | QTRACE_TAINT_SIGNED);
}

static inline void tcg_gen_qtrace_qemu_st(TCGv arg, TCGv addr, int size) {
  tcg_gen_qtrace_op3(tcg_helper_qtrace_reg2mem,
                    GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(addr), 0,
                    size, QTRACE_TAINT_CONST_WRAP | QTRACE_TAINT_SIGNED);
}

static inline void tcg_gen_qtrace_mov(TCGv_i32 ret, TCGv_i32 arg) {
  tcg_gen_qtrace_op2(tcg_helper_qtrace_mov,
                    GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_clearR(TCGv_i32 ret) {
  tcg_gen_qtrace_op1(tcg_helper_qtrace_clearR,
                    GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_combine2(TCGOpcode opc,
                                          TCGv_i32 ret, TCGv_i32 arg) {
  assert(!TCGV_EQUAL_I32(ret, arg));
  tcg_gen_qtrace_op2(tcg_helper_qtrace_combine2,
                    GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_combine3(TCGOpcode opc, TCGv_i32 ret,
                                          TCGv_i32 arg1, TCGv_i32 arg2) {
  assert(!TCGV_EQUAL_I32(arg1, arg2));
  tcg_gen_qtrace_op3(tcg_helper_qtrace_combine3,
                    GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(arg1), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(arg2), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_deposit(TCGv_i32 ret, TCGv_i32 arg1,
                                         TCGv_i32 arg2, unsigned int ofs,
                                         unsigned int len) {
  tcg_gen_qtrace_op5(tcg_helper_qtrace_deposit,
                    GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(arg1), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(arg2), QTRACE_TAINT_CONST_WRAP,
                    ofs, QTRACE_TAINT_CONST_WRAP,
                    len, QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_assert(TCGv reg, bool istrue) {
  tcg_gen_qtrace_op2(tcg_helper_qtrace_assert,
                    GET_TCGV_I32(reg), QTRACE_TAINT_CONST_WRAP,
                    GET_TCGV_I32(istrue), QTRACE_TAINT_CONST_WRAP);
}
