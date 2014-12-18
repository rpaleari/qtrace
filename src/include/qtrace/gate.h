/*
   Copyright 2014, Roberto Paleari <roberto@greyhats.it>
*/

#ifndef SRC_INCLUDE_QTRACE_GATE_H_
#define SRC_INCLUDE_QTRACE_GATE_H_

#include "qtrace/qtrace.h"

/* Forward declaration */
typedef struct CPUX86State CPUX86State;

/* Notify a CPL transition from "oldcpl" to "newcpl" */
void qtrace_gate_cpl(CPUX86State *env, int oldcpl, int newcpl);

/* Translate a VA into a physical address, using an explicit "env" */
hwaddr qtrace_gate_va2phy(CPUArchState *env, target_ulong va);

/*
   Callback function for reading CPU memory.

   Returns "0" if everything was fine reading at this address, or "-1" if any
   error occurred.
 */
int qtrace_gate_cb_peek(target_ulong addr, unsigned char *buffer, int len);

/* Callback functions for reading CPU registers */
int qtrace_gate_cb_regs(enum CpuRegister reg, target_ulong *value);
uint64_t qtrace_gate_cb_rdmsr(target_ulong num);

/* Callback function for flushing translation blocks */
int qtrace_gate_cb_tbflush(void);

/* Callback function for translating a VA into a physical address */
hwaddr qtrace_gate_cb_va2phy(target_ulong va);

#ifdef CONFIG_QTRACE_TRACER

extern bool gbl_qtrace_tracer_enabled;

/*
   Notify the beginning of a system call.

   Preconditions: switch to ring 0 has already been performed, thus CPL == 0
   and program counter has been updated to the kernel syscall dispatcher.
*/
void qtrace_gate_syscall_start(CPUX86State *env);

/*
   Notify the end of a system call.

   Preconditions: execution is still in ring 0, and the instruction that
   performs the switch has not been executed yet. Thus, program counter still
   points to the ring-switch instruction.
*/
void qtrace_gate_syscall_end(CPUX86State *env);

/*
   Notify a pre-access memory read operation.

   Preconditions: the emulator is going to access a memory region, but the
   target memory address has not been accessed yet.
 */
void qtrace_gate_memread_pre(CPUArchState *env, target_ulong addr,
                            target_ulong addr_hi, int size);

/*
   Notify a post-read memory operation.

   Preconditions: the emulator has just accessed a memory region and data has
   been retrieved.
 */
void qtrace_gate_memread_post(CPUArchState *env, target_ulong buffer,
                              target_ulong buffer_hi, int size);

/* Notify a memory write operation */
void qtrace_gate_memwrite_pre(CPUArchState *env, target_ulong addr,
                              target_ulong addr_hi, target_ulong buffer,
                              target_ulong buffer_hi, int size);

/* Switch syscall tracer on/off */
void qtrace_gate_tracer_set_state(bool state);

/* Get current state of the syscall tracer */
bool qtrace_gate_tracer_get_state(void);
#endif  /* CONFIG_QTRACE_TRACER */

#ifdef CONFIG_QTRACE_TAINT
/* Switch taint-tracking engine on/off */
void qtrace_gate_taint_set_state(bool state);

/* Get current state of the taint-tracker */
bool qtrace_gate_taint_get_state(void);
#endif  /* CONFIG_QTRACE_TAINT */

#endif  /* SRC_INCLUDE_QTRACE_GATE_H_ */
