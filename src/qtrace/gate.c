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

#ifdef CONFIG_QTRACE_TRACER
#include "qtrace/trace/notify_syscall.h"
#endif

#ifdef CONFIG_QTRACE_TAINT
#include "qtrace/taint/notify_taint.h"
#endif

static CPUX86State *gbl_cpu_current_env = NULL;

#ifdef CONFIG_QTRACE_TRACER
static bool gbl_first_syscall = false;
#endif

static inline void qtrace_update_current_env(CPUX86State *env) {
  gbl_cpu_current_env = env;
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
  return qtrace_gate_va2phy(gbl_cpu_current_env, va);
}

/* Flush QEMU TB cache */
int qtrace_gate_cb_tbflush(void) {
  CPUState *cpu;

  CPU_FOREACH(cpu) {
    CPUArchState *env = cpu->env_ptr;
    tb_flush(env);
  }
  return 0;
}

/* Peek memory ('addr' is a VA) */
int qtrace_gate_cb_peek(target_ulong addr, unsigned char *buffer, int len) {
  int r;

  assert(gbl_cpu_current_env != NULL);
  r = cpu_memory_rw_debug(ENV_GET_CPU(gbl_cpu_current_env), addr, buffer,
			  len, 0);

  return r;
}

/* Peek CPU registers */
int qtrace_gate_cb_regs(enum CpuRegister reg, target_ulong *value) {
  if (gbl_cpu_current_env == NULL) {
    return -1;
  }

#define R(name, src)                               \
  case Register ## name:                           \
    *value = gbl_cpu_current_env->src;		   \
    break

  switch (reg) {
    R(Eax, regs[R_EAX]);
    R(Ecx, regs[R_ECX]);
    R(Edx, regs[R_EDX]);
    R(Ebx, regs[R_EBX]);
    R(Esp, regs[R_ESP]);
    R(Ebp, regs[R_EBP]);
    R(Esi, regs[R_ESI]);
    R(Edi, regs[R_EDI]);

#ifdef TARGET_X86_64
    R(R8,  regs[8]);
    R(R9,  regs[9]);
    R(R10, regs[10]);
    R(R11, regs[11]);
    R(R12, regs[12]);
    R(R13, regs[13]);
    R(R14, regs[14]);
    R(R15, regs[15]);
#endif

    R(Cr3, cr[3]);
    R(Pc, eip);
    R(CsBase, segs[R_CS].base);
    R(FsBase, segs[R_FS].base);
    R(GsBase, segs[R_GS].base);

  default:
    assert(0);
    break;
  }
#undef R

  return 0;
}

/* Peek CPU MSR registers. This function closely resembles to
   target-i386/misc_helper.c:helper_rdmsr(). However, the latter eventually
   writes the content of the requested MSR to EDX:EAX, so it does not fit our
   purposes. */
uint64_t qtrace_gate_cb_rdmsr(target_ulong num) {
  uint64_t val;

  assert(gbl_cpu_current_env != NULL);

#define C(num, field)				\
  case num:					\
    val = gbl_cpu_current_env->field;		\
    break;

  switch (num) {
    C(MSR_IA32_SYSENTER_CS, sysenter_cs);
    C(MSR_IA32_SYSENTER_ESP, sysenter_esp);
    C(MSR_IA32_SYSENTER_EIP, sysenter_eip);
#ifdef TARGET_X86_64
    C(MSR_FSBASE, segs[R_FS].base);
    C(MSR_GSBASE, segs[R_GS].base);
    C(MSR_KERNELGSBASE, kernelgsbase);
#endif
  default:
    val = 0;
    break;
  }

#undef C

  return val;
}

void qtrace_gate_cpl(CPUX86State *env, int oldcpl, int newcpl) {
  if (oldcpl == newcpl) {
    /* No CPL switch */
    return;
  }
  qtrace_update_current_env(env);
#ifdef CONFIG_QTRACE_TAINT
#ifdef CONFIG_QTRACE_TRACER
  /* We postpone CPL-change notifications until we see the first system
     call. This to prevent expensive taint-tracking analyses during early boot
     phases. */
  if (gbl_first_syscall)
#endif
    notify_taint_cpl(env->cr[3], newcpl);
#endif

  return;
}

#ifdef CONFIG_QTRACE_TRACER
void qtrace_gate_syscall_start(CPUX86State *env) {
  target_ulong sysno = env->regs[R_EAX];
  target_ulong cr3 = env->cr[3];

  qtrace_update_current_env(env);

  /* Check if this is the first syscall we encountered */
  if (unlikely(!gbl_first_syscall)) {
    gbl_first_syscall = true;
  }
  notify_syscall_start(cr3, sysno);
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
#endif	/* CONFIG_QTRACE_TRACER */

#ifdef CONFIG_QTRACE_TAINT
void qtrace_gate_taint_set_state(bool state) {
  notify_taint_set_state(state);
}

bool qtrace_gate_taint_get_state(void) {
  return notify_taint_get_state();
}
#endif	/* CONFIG_QTRACE_TAINT */
