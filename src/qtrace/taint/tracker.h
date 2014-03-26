//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TAINT_TRACKER_H_
#define SRC_QTRACE_TAINT_TRACKER_H_

#include "qtrace/trace/syscall.h"

void track_syscall_deps(Syscall &syscall);

#endif  // SRC_QTRACE_TAINT_TRACKER_H_
