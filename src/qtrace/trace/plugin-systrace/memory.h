//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_MEMORY_H_
#define SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_MEMORY_H_

#include "qtrace/common.h"
#include "qtrace/trace/plugin-systrace/syscall.h"

// Process memory read access to a level-0 argument
void memory_read_level0(Syscall *syscall, target_ulong addr, int size,
			target_ulong buffer);

// Process memory read access to a higher-level argument
void memory_read_levelN(target_ulong pc, Syscall *syscall, target_ulong addr,
                        int size, target_ulong buffer);

// Process memory write access from kernel to user-space address
void memory_write(target_ulong pc, Syscall *syscall, target_ulong addr,
                  int size, target_ulong buffer);

#endif  // SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_MEMORY_H_
