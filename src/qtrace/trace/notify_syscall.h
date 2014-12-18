//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_NOTIFY_SYSCALL_H_
#define SRC_QTRACE_TRACE_NOTIFY_SYSCALL_H_

#ifdef __cplusplus
#include "qtrace/common.h"
extern "C" {
#endif

  void notify_syscall_start(target_ulong cr3, target_ulong sysno);

  void notify_syscall_end(target_ulong cr3, target_ulong retval);

  void notify_memread_post(target_ulong cr3, target_ulong pc, int cpl,
                           target_ulong buffer, target_ulong buffer_hi,
                           int size);

  void notify_memread_pre(target_ulong pc, target_ulong addr,
                          target_ulong addr_hi, int size);

  void notify_memwrite_pre(target_ulong cr3, target_ulong pc, int cpl,
                           target_ulong addr, target_ulong addr_hi,
                           target_ulong buffer, target_ulong buffer_hi,
                           int size);

  void notify_tracer_set_state(bool state);

  bool notify_tracer_get_state(void);
#ifdef __cplusplus
}
#endif

#endif  // SRC_QTRACE_TRACE_NOTIFY_SYSCALL_H_
