/*
  Copyright 2013, Roberto Paleari <roberto@greyhats.it>

  The "gate" module acts as a bridge between QEMU and the main QTrace library.

  This module was basically written to allow communication between the QEMU
  codebase (written in C) and QTrace (written in C++). A much simpler solution
  would have been to compile QEMU using a C++ compiler; unfortunately, this is
  not as easy as it may sound, due to several "peculiarities" of QEMU source
  code (e.g., variables named "class").
*/

/* Must come first */
#include "cpu.h"
#include "exec/memory.h"

#include <stdbool.h>

#include "qtrace/gate.h"

#ifdef CONFIG_QTRACE_SYSCALL
#include "qtrace/trace/notify_syscall.h"
#endif

#ifdef CONFIG_QTRACE_TAINT
#include "qtrace/taint/notify_taint.h"
#endif

static CPUX86State *cpu_current_env = NULL;

static inline void qtrace_update_current_env(CPUX86State *env) {
  cpu_current_env = env;  
}

hwaddr qtrace_gate_va2phy(CPUArchState *env, target_ulong va) {
#ifdef CONFIG_USER_ONLY
  return va;
#else
  hwaddr phyaddr;

  assert(env != NULL);
  CPUClass *cc = CPU_GET_CLASS(ENV_GET_CPU(env));
  phyaddr = cc->get_phys_page_debug(ENV_GET_CPU(env), va);
  if (phyaddr == -1) {
    return -1;
  }

  /* Add page offset */
  phyaddr += va & ~TARGET_PAGE_MASK;
  return phyaddr;
#endif
}

/* Translate the virtual address into a physical one */
hwaddr qtrace_gate_cb_va2phy(target_ulong va) {
  return qtrace_gate_va2phy(cpu_current_env, va);
}

/* Flush QEMU TB cache */
int qtrace_gate_cb_tbflush(void) {
  CPUState *cpu;
  for (cpu = first_cpu; cpu != NULL; cpu = cpu->next_cpu) {
    CPUArchState *env = cpu->env_ptr;
    tb_flush(env);
  }
  return 0;
}

/* Peek memory ('addr' is a VA) */
int qtrace_gate_cb_peek(target_ulong addr, unsigned char *buffer, int len) {
  int r;

  assert(cpu_current_env != NULL);
  r = cpu_memory_rw_debug(ENV_GET_CPU(cpu_current_env), addr, buffer, len, 0);

  return r;
}

/* Peek CPU registers */
int qtrace_gate_cb_regs(CpuRegisters *regs) {
  if (cpu_current_env == NULL) {
    return -1;
  }

#define R(src, dst) regs->dst = cpu_current_env->src
  R(regs[R_EAX], eax);
  R(regs[R_ECX], ecx);
  R(regs[R_ESP], esp);
  R(regs[R_EBP], ebp);

  R(cr[3], cr3);

  R(eip, pc);

  R(segs[R_CS].base, cs_base);
  R(segs[R_FS].base, fs_base);
#undef R

  return 0;
}

void qtrace_gate_cpl(CPUX86State *env, int oldcpl, int newcpl) {
  if (oldcpl == newcpl) {
    /* No CPL switch */
    return;
  }

  qtrace_update_current_env(env);
#ifdef CONFIG_QTRACE_TAINT
  notify_taint_cpl(env->cr[3], newcpl);
#endif

  return;
}

#ifdef CONFIG_QTRACE_SYSCALL
void qtrace_gate_syscall_start(CPUX86State *env) {
  target_ulong sysno = env->regs[R_EAX];
  target_ulong stack = env->regs[R_EDX];
  target_ulong cr3 = env->cr[3];

  qtrace_update_current_env(env);
  notify_syscall_start(cr3, sysno, stack);
}

void qtrace_gate_syscall_end(CPUX86State *env) {
  target_ulong retval = env->regs[R_EAX];
  target_ulong cr3 = env->cr[3];

  qtrace_update_current_env(env);
  notify_syscall_end(cr3, retval);
}

/* This function is eventually called by INDEX_op_qemu_ld* TCG
   micro-instructions */
void qtrace_gate_memread_post(CPUArchState *env, target_ulong buffer,
                             target_ulong buffer_hi, int size) {
  target_ulong cr3 = env->cr[3];
  target_ulong pc = env->eip;
  int cpl = (env->hflags & HF_CPL_MASK) >> HF_CPL_SHIFT;

  qtrace_update_current_env(env);
  notify_memread_post(cr3, pc, cpl, buffer, buffer_hi, size);
}

/* This callback is invoked before a memory read occurs. We store the memory
   address that is being accessed, its size and current PC. */
void qtrace_gate_memread_pre(CPUArchState *env, target_ulong addr,
                            target_ulong addr_hi, int size) {
  target_ulong pc = env->eip;

  qtrace_update_current_env(env);
  notify_memread_pre(pc, addr, addr_hi, size);
}

/* This callback is invoked before a memory write occurs. */
void qtrace_gate_memwrite_pre(CPUArchState *env, target_ulong addr,
                             target_ulong addr_hi, target_ulong buffer,
                             target_ulong buffer_hi, int size) {
  int cpl = (env->hflags & HF_CPL_MASK) >> HF_CPL_SHIFT;
  target_ulong cr3 = env->cr[3];

  qtrace_update_current_env(env);
  notify_memwrite_pre(cr3, env->eip, cpl,
                      addr, addr_hi,
                      buffer, buffer_hi, size);
}

void qtrace_gate_tracer_set_state(bool state) {
  notify_tracer_set_state(state);
}

bool qtrace_gate_tracer_get_state(void) {
  return notify_tracer_get_state();
}
#endif	/* CONFIG_QTRACE_SYSCALL */

#ifdef CONFIG_QTRACE_TAINT
void qtrace_gate_taint_set_state(bool state) {
  notify_taint_set_state(state);
}

bool qtrace_gate_taint_get_state(void) {
  return notify_taint_get_state();
}
#endif	/* CONFIG_QTRACE_TAINT */
