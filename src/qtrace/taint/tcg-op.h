//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/taint.h"
#include "qtrace/taint/notify_taint.h"

#if TARGET_LONG_BITS != 32
#warning Support for 64-bit targets is still experimental
#endif

#define QTRACE_INSTRUMENT_START() {		\
    if (likely(!qtrace_taint_enabled)) {	\
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

typedef void (*qtrace_handler_op1)(TCGv_ptr);
typedef void (*qtrace_handler_op2)(TCGv_ptr, TCGv_ptr);
typedef void (*qtrace_handler_op3)(TCGv_ptr, TCGv_ptr, TCGv_ptr);
typedef void (*qtrace_handler_op5)(TCGv_ptr, TCGv_ptr, TCGv_ptr, TCGv_ptr,
				   TCGv_ptr);

static inline int tcg_gen_qtrace_sizemask(int n, int is_64bit, int is_signed) {
    return (is_64bit << n*2) | (is_signed << (n*2 + 1));
}

static inline void tcg_gen_qtrace_helperN(void *func, int flags, int sizemask,
					  TCGArg ret, int nargs, TCGArg *args) {
    tcg_gen_callN(&tcg_ctx, func, ret, nargs, args);
}

#define OP_SET_ARG(num, var, flg)                                       \
  sizemask |= tcg_gen_qtrace_sizemask((num), FLG((flg), QTRACE_TAINT_64BIT), \
				      FLG((flg), QTRACE_TAINT_SIGNED));	\
  args[num] = FLG((flg), QTRACE_TAINT_CONST_WRAP) ? tcg_const_i32((var)) : (var);

#define OP_FREE_ARG(num, flg)                                           \
  if (FLG((flg), QTRACE_TAINT_CONST_WRAP)) { tcg_temp_free_i32(args[num]); }

static inline void tcg_gen_qtrace_op1(qtrace_handler_op1 helper,
				      TCGArg a1, int a1_f) {
  int sizemask = 0;
  TCGArg args[1];

  QTRACE_INSTRUMENT_START();

  OP_SET_ARG(0, a1, a1_f);

  helper(args[0]);

  OP_FREE_ARG(0, a1_f);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_op2(qtrace_handler_op2 helper,
				      TCGArg a1, int a1_f,
				      TCGArg a2, int a2_f) {
  int sizemask = 0;
  TCGArg args[2];

  QTRACE_INSTRUMENT_START();

  OP_SET_ARG(0, a1, a1_f);
  OP_SET_ARG(1, a2, a2_f);

  helper(args[0], args[1]);

  OP_FREE_ARG(0, a1_f);
  OP_FREE_ARG(1, a2_f);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_op3(qtrace_handler_op3 helper,
				      TCGArg a1, int a1_f,
				      TCGArg a2, int a2_f,
				      TCGArg a3, int a3_f) {
  int sizemask = 0;
  TCGArg args[3];

  QTRACE_INSTRUMENT_START();

  OP_SET_ARG(0, a1, a1_f);
  OP_SET_ARG(1, a2, a2_f);
  OP_SET_ARG(2, a3, a3_f);

  helper(args[0], args[1], args[2]);

  OP_FREE_ARG(0, a1_f);
  OP_FREE_ARG(1, a2_f);
  OP_FREE_ARG(2, a3_f);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_op5(qtrace_handler_op5 helper,
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

  helper(args[0], args[1], args[2], args[3], args[4]);

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

  tcg_gen_qtrace_helperN(helper_qtrace_endtb, 0, 0,
			 TCG_CALL_DUMMY_ARG, 0, NULL);

  QTRACE_INSTRUMENT_END();
}

static inline void tcg_gen_qtrace_qemu_ld(TCGv arg, TCGv addr, int size) {
  tcg_gen_qtrace_op3(gen_helper_qtrace_mem2reg,
		    GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP,
		    GET_TCGV_PTR(addr), 0,
		    size, QTRACE_TAINT_CONST_WRAP | QTRACE_TAINT_SIGNED);
}

static inline void tcg_gen_qtrace_qemu_st(TCGv arg, TCGv addr, int size) {
  tcg_gen_qtrace_op3(gen_helper_qtrace_reg2mem,
		    GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP,
		    GET_TCGV_PTR(addr), 0,
		    size, QTRACE_TAINT_CONST_WRAP | QTRACE_TAINT_SIGNED);
}

static inline void tcg_gen_qtrace_mov(TCGv_i32 ret, TCGv_i32 arg) {
  tcg_gen_qtrace_op2(gen_helper_qtrace_mov,
		     GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
		     GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_clearR(TCGv_i32 ret) {
  tcg_gen_qtrace_op1(gen_helper_qtrace_clearR,
		     GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_combine2(TCGOpcode opc,
					   TCGv_i32 ret, TCGv_i32 arg) {
  assert(!TCGV_EQUAL_I32(ret, arg));
  tcg_gen_qtrace_op2(gen_helper_qtrace_combine2,
		     GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
		     GET_TCGV_I32(arg), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_combine3(TCGOpcode opc, TCGv_i32 ret,
					   TCGv_i32 arg1, TCGv_i32 arg2) {
  assert(!TCGV_EQUAL_I32(arg1, arg2));
  tcg_gen_qtrace_op3(gen_helper_qtrace_combine3,
		    GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
		    GET_TCGV_I32(arg1), QTRACE_TAINT_CONST_WRAP,
		    GET_TCGV_I32(arg2), QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_deposit(TCGv_i32 ret, TCGv_i32 arg1,
					  TCGv_i32 arg2, unsigned int ofs,
					  unsigned int len) {
  tcg_gen_qtrace_op5(gen_helper_qtrace_deposit,
		    GET_TCGV_I32(ret), QTRACE_TAINT_CONST_WRAP,
		    GET_TCGV_I32(arg1), QTRACE_TAINT_CONST_WRAP,
		    GET_TCGV_I32(arg2), QTRACE_TAINT_CONST_WRAP,
		    ofs, QTRACE_TAINT_CONST_WRAP,
		    len, QTRACE_TAINT_CONST_WRAP);
}

static inline void tcg_gen_qtrace_assert(TCGv reg, bool istrue) {
  tcg_gen_qtrace_op2(gen_helper_qtrace_assert,
                     GET_TCGV_I32(reg), QTRACE_TAINT_CONST_WRAP,
                     GET_TCGV_I32(istrue), QTRACE_TAINT_CONST_WRAP);
}
