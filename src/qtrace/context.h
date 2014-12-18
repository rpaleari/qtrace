//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_CONTEXT_H_
#define SRC_QTRACE_CONTEXT_H_

#include "qtrace/common.h"
#include "qtrace/options.h"

#ifdef CONFIG_QTRACE_TRACER
#include "qtrace/trace/plugin.h"
#include "qtrace/profiles/guest_os.h"
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

#ifdef CONFIG_QTRACE_TRACER
  // Callback to peek memory
  qtrace_func_memread cb_peek;

  // Callbacks to read CPU registers
  qtrace_func_regread cb_regs;
  qtrace_func_msrread cb_rdmsr;

  // Notification callbacks (plugin-specific)
  struct PluginCallbacks callbacks;

  // State of the syscall tracer (ON/OFF)
  bool tracer_enabled;

  // Windows object, for OS-specific operations
  GuestOS *guest;
#endif

#ifdef CONFIG_QTRACE_TAINT
  TaintEngine *taint_engine;
#endif
};

extern struct QTraceContext gbl_context;

#ifdef CONFIG_QTRACE_TRACER
// Helper function to read CPU registers
target_ulong context_reg_safe(enum CpuRegister);
#endif

// Pretty print context
void context_print();

#endif  // SRC_QTRACE_CONTEXT_H_
