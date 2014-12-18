//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//
// FIXME: Move this module to qtrace/trace/plugin-systrace/
//

#ifndef SRC_QTRACE_TAINT_TRACKER_H_
#define SRC_QTRACE_TAINT_TRACKER_H_

#include "qtrace/trace/plugin-systrace/syscall.h"

void track_syscall_deps(Syscall &syscall);
void track_sysarg_reg(SyscallArg *arg, const std::string &reg_name);

#endif  // SRC_QTRACE_TAINT_TRACKER_H_
