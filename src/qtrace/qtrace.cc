//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include <cassert>
#include <cstring>

#include "config-target.h"
#include "config-host.h"

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"

#ifdef CONFIG_QTRACE_SYSCALL
#include "qtrace/trace/manager.h"
#include "qtrace/trace/memory.h"
#include "qtrace/trace/serialize.h"
#include "qtrace/trace/syscall.h"
#include "qtrace/trace/windows.h"
#endif

#ifdef CONFIG_QTRACE_TAINT
#include "qtrace/taint/taintengine.h"
#endif

#ifndef TARGET_I386
#error "QTrace currently supports x86 architecture only!"
#endif

// Set to "true" after initialization
static bool qtrace_initialized = false;

// The global structure accessed by the QEMU core module (vl.c) to store
// command-line options
struct QTraceOptions qtrace_options = {
#ifdef CONFIG_QTRACE_SYSCALL
  false,                        // trace_disabled
  NULL,                         // filename_log
  ProfileUnknown,               // profile
  NULL,                         // filename_trace
  NULL,                         // filter_syscalls
  NULL,                         // filter_process
  false,                        // track_foreign
#endif
#ifdef CONFIG_QTRACE_TAINT
  false,                        // taint_disabled
#endif
};

int qtrace_initialize(qtrace_func_memread func_peek,
                      qtrace_func_regread func_regs,
                      qtrace_func_tbflush func_tbflush,
                      qtrace_func_va2phy func_va2phy) {
  DEBUG("Initalization started");
  assert(!qtrace_initialized);

#define CHECK(r, msg)                                                   \
  if ((r) != 0) {                                                       \
    ERROR(msg " initialization failed");                                \
    return -1;                                                          \
  }

  // These modules are initialized in all QTrace configurations (e.g.,
  // syscall tracing and/or taint tracking)
  memset(&gbl_context, 0, sizeof(gbl_context));

  // Set QEMU callbacks
  assert(func_tbflush && func_va2phy);
  gbl_context.cb_tbflush = func_tbflush;
  gbl_context.cb_va2phy = func_va2phy;

  // Copy command-line options
  memcpy(&gbl_context.options, &qtrace_options, sizeof(gbl_context.options));

#ifdef CONFIG_QTRACE_SYSCALL
  // Continue with module-specific intialization
  CHECK(log_init(gbl_context.options.filename_log), "Log");

  // Syscall tracing setup
  assert(func_peek && func_regs);
  gbl_context.cb_peek = func_peek;
  gbl_context.cb_regs = func_regs;

  CHECK(windows_init(&gbl_context.windows), "Windows");
  CHECK(serialize_init(), "Serialize");

  gbl_context.tracer_enabled = !gbl_context.options.trace_disabled;
  gbl_context.trace_manager =
    new TraceManager(gbl_context.options.track_foreign,
                     gbl_context.options.filter_syscalls,
                     gbl_context.options.filter_process);
#endif

#ifdef CONFIG_QTRACE_TAINT
  // Setup of the taint propagation engine
  gbl_context.taint_engine = new TaintEngine();
#ifdef CONFIG_USER_ONLY
  gbl_context.taint_engine->setEnabled(true);
  gbl_context.taint_engine->setUserEnabled(true);
#else
  gbl_context.taint_engine->setEnabled(false);
  gbl_context.taint_engine->setUserEnabled(!gbl_context.options.taint_disabled);
#endif
#endif

#undef CHECK

  context_print();

  DEBUG("Initalization completed");
  qtrace_initialized = true;

  return 0;
}
