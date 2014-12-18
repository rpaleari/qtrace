//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//
// Callbacks for the "0-knowledge" syscall tracing plugin.
//

#ifndef SRC_QTRACE_TRACE_PLUGIN_DUMMY_CALLBACKS_H_
#define SRC_QTRACE_TRACE_PLUGIN_DUMMY_CALLBACKS_H_

#include "qtrace/common.h"

void cb_dummy_syscall_start(target_ulong cr3, target_ulong sysno);
void cb_dummy_syscall_end(target_ulong cr3, target_ulong retval);
void cb_dummy_memread_post(target_ulong cr3, target_ulong pc, int cpl,
			   target_ulong buffer, target_ulong buffer_hi,
			   int size);
void cb_dummy_memread_pre(target_ulong pc, target_ulong addr,
			  target_ulong addr_hi, int size);
void cb_dummy_memwrite_pre(target_ulong cr3, target_ulong pc, int cpl,
			   target_ulong addr, target_ulong addr_hi,
			   target_ulong buffer, target_ulong buffer_hi,
			   int size);

#endif  // SRC_QTRACE_TRACE_PLUGIN_DUMMY_CALLBACKS_H_
