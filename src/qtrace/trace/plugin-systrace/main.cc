//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/plugin-systrace/main.h"

#include "qtrace/trace/plugin-systrace/callbacks.h"
#include "qtrace/trace/plugin-systrace/serialize.h"
#include "qtrace/trace/plugin-systrace/manager.h"
#include "qtrace/logging.h"

#define CHECK(r, msg)                           \
  if ((r) != 0) {                               \
    ERROR(msg " initialization failed");        \
    return -1;                                  \
  }

void print_state() {
  INFO("Tracking of foreign pointers:  %s",
       gbl_trace_manager->isForeignEnabled() ? "ON" : "OFF");
  INFO("Tracking of repeated accesses: %s",
       gbl_trace_manager->isRepEnabled() ? "ON" : "OFF");
}

int plugin_init(struct PluginCallbacks *callbacks,
                const struct QTraceOptions *options) {
  // Initialize notification callbacks
  callbacks->syscall_start = cb_systrace_syscall_start;
  callbacks->syscall_end = cb_systrace_syscall_end;
  callbacks->memread_pre = cb_systrace_memread_pre;
  callbacks->memread_post = cb_systrace_memread_post;
  callbacks->memwrite_pre = cb_systrace_memwrite_pre;
  callbacks->print_state = print_state;

  // Create the trace manager
  gbl_trace_manager = new TraceManager(options->track_foreign,
                                       options->track_rep_accesses,
                                       options->filter_syscalls,
                                       options->filter_process);

  // Initialize serialization module
  CHECK(serialize_init(), "Serialize");

  return 0;
}
