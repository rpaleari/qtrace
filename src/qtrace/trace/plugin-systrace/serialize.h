//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_SERIALIZE_H_
#define SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_SERIALIZE_H_

#include "qtrace/trace/plugin-systrace/syscall.h"

int serialize_init(void);
void serialize_syscall(const Syscall *syscall);

#endif  // SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_SERIALIZE_H_
