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
#ifdef TARGET_X86_64
#define QTRACE_REG_SYSCALL_RESULT rax
#else
#define QTRACE_REG_SYSCALL_RESULT eax
#endif

/* Stringification */
#define _XSTR(s) _STR(s)
#define _STR(s) #s

enum CpuRegister {
  /* General-purpose registers */

  RegisterEax, RegisterEcx, RegisterEdx, RegisterEbx,
  RegisterEsp, RegisterEbp, RegisterEsi, RegisterEdi,
#ifdef TARGET_X86_64
  RegisterRax = RegisterEax, RegisterRcx = RegisterEcx,
  RegisterRdx = RegisterEdx, RegisterRbx = RegisterEbx,
  RegisterRsp = RegisterEsp, RegisterRbp = RegisterEbp,
  RegisterRsi = RegisterEsi, RegisterRdi = RegisterEdi,

  RegisterR8,  RegisterR9,  RegisterR10, RegisterR11,
  RegisterR12, RegisterR13, RegisterR14, RegisterR15,
#endif

  /* Control registers */
  RegisterCr3,

  /* Program counter */
  RegisterPc,

  /* Segments */
  RegisterCsBase, RegisterFsBase, RegisterGsBase,
};

/*
   Callbacks prototypes
 */
typedef int (*qtrace_func_memread)(target_ulong addr, unsigned char *buffer,
                                   int len);
typedef int (*qtrace_func_regread)(enum CpuRegister reg, target_ulong *value);
typedef uint64_t (*qtrace_func_msrread)(target_ulong num);
typedef int (*qtrace_func_tbflush)(void);
typedef hwaddr (*qtrace_func_va2phy)(target_ulong va);

#ifdef __cplusplus
extern "C" {
#endif
  /*
    Initialize the whole QTrace subsystem. This function is invoked only once
    during QEMU main() procedure
  */
  int qtrace_initialize(qtrace_func_memread func_peek,
                        qtrace_func_regread func_regs,
                        qtrace_func_msrread func_rdmsr,
                        qtrace_func_tbflush func_tbflush,
                        qtrace_func_va2phy func_va2phy);

  /*
     Returns "true" if system call number "sysno" should be processed,
     according to user-supplied system calls filter
   */
  bool qtrace_should_process_syscall(target_ulong sysno);
#ifdef __cplusplus
}
#endif

#endif  /* SRC_INCLUDE_QTRACE_QTRACE_H_ */
