//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_COMMON_H_
#define SRC_QTRACE_COMMON_H_

#include "config-target.h"

#define NEED_CPU_H
#ifndef TARGET_LONG_BITS
#ifdef TARGET_X86_64
#define TARGET_LONG_BITS 64
#else
#define TARGET_LONG_BITS 32
#endif
#endif

#include "exec/cpu-defs.h"
#undef NEED_CPU_H

#include "qtrace/qtrace.h"

// Maximum distance between the address of a system call argument and the
// address of its "parent" argument
const target_ulong MAX_ARGUMENT_OFFSET = 0x1000;

#endif  // SRC_QTRACE_COMMON_H_
