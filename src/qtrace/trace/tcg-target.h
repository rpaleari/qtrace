#include "qtrace/gate.h"

#if TARGET_LONG_BITS != 32
#warning 64-bit targets are currently experimental!
#endif

#define PUSH_ALL()						\
  for (reg_idx = 0; reg_idx < TCG_TARGET_NB_REGS; reg_idx++) {	\
    tcg_out_push(s, reg_idx);					\
  }

#define POP_ALL()							\
  for (reg_idx = TCG_TARGET_NB_REGS-1; reg_idx >= 0; reg_idx--) {	\
    tcg_out_pop(s, reg_idx);						\
  }

#if TCG_TARGET_REG_BITS == 32
#define ARG_REG(argno, reg) tcg_out_push(s, (reg))
#define ARG_IMM(argno, val) tcg_out_pushi(s, (val))
#define ARG_DEALLOC(n) tcg_out_addi(s, TCG_REG_CALL_STACK,	\
				    sizeof(tcg_target_long) * (n))
#else
#define ARG_REG(argno, reg) tcg_out_mov(s, TCG_TYPE_I64,		\
					tcg_target_call_iarg_regs[(argno)], \
					(reg))
#define ARG_IMM(argno, val) tcg_out_movi(s, TCG_TYPE_I64,		\
					 tcg_target_call_iarg_regs[(argno)], \
					 (val))
#define ARG_DEALLOC(n)
#endif

/* Pre-access read notification. The pre-access hook is needed because the
   register containing the memory address that is going to be accessed is
   *not* preserved by the TLB lookup procedure. Thus, in the pre-hook we
   save the memory address, while in the post-hook we process the read
   buffer. */
static void tcg_out_qtrace_memread_pre(TCGContext *s, TCGArg addrlo_reg, 
                                       TCGArg addrhi_reg, int size, int opc) {
  int reg_idx;

  if (unlikely(!gbl_qtrace_tracer_enabled)) {
    return;
  }

  PUSH_ALL();

  /* Prepare arguments */
  ARG_IMM(3, size);
  if (TCG_TARGET_REG_BITS == 32 && opc == 3) {
    ARG_REG(2, addrhi_reg);
  } else {
    ARG_IMM(2, 0);
  }
  ARG_REG(1, addrlo_reg);
  ARG_REG(0, TCG_AREG0);

  /* Call QTrace handler */
  tcg_out_call(s, (tcg_insn_unit*) qtrace_gate_memread_pre);

  /* Deallocate arguments */
  ARG_DEALLOC(4);

  POP_ALL();
}

/* Post-access read notification. Process the data that has just been read
   from memory. The memory address where data has been read is the one
   saved during the pre-hook. */
static void tcg_out_qtrace_memread_post(TCGContext *s, TCGArg datalo_reg, 
                                        TCGArg datahi_reg, int size, int opc) {
  int reg_idx;

  if (unlikely(!gbl_qtrace_tracer_enabled)) {
    return;
  }

  /* Save general purpose registers. These registers are not preserved by
     the QTrace callback, so they must be explicitly saved here. */
  PUSH_ALL();

  /* Prepare arguments */
  ARG_IMM(3, size);
  if (TCG_TARGET_REG_BITS == 32 && opc == 3) {
    /* 64-bit memory operation with a 32-bit target system. Also push the
       high part of the source address and data register */
    ARG_REG(2, datahi_reg);
  } else {
    ARG_IMM(2, 0);
  }
  ARG_REG(1, datalo_reg);
  ARG_REG(0, TCG_AREG0);

  /* Call QTrace handler */
  tcg_out_call(s, (tcg_insn_unit*) qtrace_gate_memread_post);

  /* Deallocate arguments */
  ARG_DEALLOC(4);

  /* Restore general purpose registers */
  POP_ALL();
}

/* Pre-access write notification. */
static void tcg_out_qtrace_memwrite_pre(TCGContext *s, TCGArg addrlo_reg,
                                        TCGArg addrhi_reg, TCGArg datalo_reg,
                                        TCGArg datahi_reg, int size, int opc) {
  int reg_idx;

  if (unlikely(!gbl_qtrace_tracer_enabled)) {
    return;
  }

  /* Save general purpose registers. These registers are not preserved by
     the QTrace callback, so they must be explicitly saved here. */
  PUSH_ALL();

  /* Prepare arguments */
  ARG_IMM(5, size);
  if (TCG_TARGET_REG_BITS == 32 && opc == 3) {
    /* 64-bit memory operation with a 32-bit target system */
    ARG_REG(4, datahi_reg);
    ARG_REG(3, datalo_reg);
    ARG_REG(2, addrhi_reg);
  } else {
    ARG_IMM(4, 0);
    ARG_REG(3, datalo_reg);
    ARG_IMM(2, 0);
  }
  ARG_REG(1, addrlo_reg);
  ARG_REG(0, TCG_AREG0);

  /* Call QTrace handler */
  tcg_out_call(s, (tcg_insn_unit*) qtrace_gate_memwrite_pre);

  /* Deallocate arguments */
  ARG_DEALLOC(6);

  /* Restore general purpose registers */
  POP_ALL();
}
