//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_CONTEXT_H_
#define SRC_QTRACE_CONTEXT_H_

#include "qtrace/common.h"
#include "qtrace/options.h"

#ifdef CONFIG_QTRACE_SYSCALL
#include "qtrace/trace/manager.h"
#include "qtrace/trace/windows.h"
#endif

#ifdef CONFIG_QTRACE_TAINT
#include "qtrace/taint/taintengine.h"
#endif

struct QTraceContext {
  // The global structure accessed by the QEMU core module to store
  // command-line options
  struct QTraceOptions options;

  // Callback for flushing TCG TB cache
  qtrace_func_tbflush cb_tbflush;

  // Callback to translate a physical address in a virtual one
  qtrace_func_va2phy cb_va2phy;

#ifdef CONFIG_QTRACE_SYSCALL
  // Callback to peek memory
  qtrace_func_memread cb_peek;

  // Callback to read CPU registers
  qtrace_func_regread cb_regs;

  // Syscall tracer manager
  TraceManager *trace_manager;

  // State of the syscall tracer (ON/OFF)
  bool tracer_enabled;

  // Windows object, for OS-specific operations
  Windows *windows;
#endif

#ifdef CONFIG_QTRACE_TAINT
  TaintEngine *taint_engine;
#endif
};

extern struct QTraceContext gbl_context;

void context_print();

#endif  // SRC_QTRACE_CONTEXT_H_
