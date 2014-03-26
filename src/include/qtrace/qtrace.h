/*
   Copyright 2014, Roberto Paleari <roberto@greyhats.it>

   This module is part of the C-to-C++ bridge developed to interconnect QEMU C
   code and QTrace C++ library.
 */

#ifndef SRC_INCLUDE_QTRACE_QTRACE_H_
#define SRC_INCLUDE_QTRACE_QTRACE_H_

#ifdef CONFIG_USER_ONLY
/* To provide a definition for type "hwaddr" when using QEMU user-mode */
#include "exec/hwaddr.h"
#endif

/* Notable syscall registers, to ease porting to different architectures */
#define QTRACE_REG_SYSCALL_RESULT eax

/* Stringification */
#define _XSTR(s) _STR(s)
#define _STR(s) #s

typedef struct {
  /* General-purpose registers */
  target_ulong eax;
  target_ulong ecx;
  target_ulong esp;
  target_ulong ebp;

  /* Control registers */
  target_ulong cr3;

  /* Program counter */
  target_ulong pc;

  /* Segments */
  target_ulong cs_base;
  target_ulong fs_base;
} CpuRegisters;

/*
   Callbacks prototypes
 */
typedef int (*qtrace_func_memread)(target_ulong addr, unsigned char *buffer,
                                   int len);
typedef int (*qtrace_func_regread)(CpuRegisters *regs);
typedef int (*qtrace_func_tbflush)(void);
typedef hwaddr (*qtrace_func_va2phy)(target_ulong va);

#ifdef __cplusplus
extern "C" {
#endif
  /*
    Initialize the whole QTrace subsystem. This function is invoked only once
    during QEMU main() procedure
  */
  int qtrace_initialize(qtrace_func_memread   func_peek,
                        qtrace_func_regread   func_regs,
                        qtrace_func_tbflush   func_tbflush,
                        qtrace_func_va2phy    func_va2phy);

  /*
     Returns "true" if system call number "sysno" should be processed,
     according to user-supplied system calls filter
   */
  bool qtrace_should_process_syscall(target_ulong sysno);
#ifdef __cplusplus
}
#endif

#endif  /* SRC_INCLUDE_QTRACE_QTRACE_H_ */
