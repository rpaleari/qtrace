//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//
// Definition of QTrace plugins interface.
//

#ifndef SRC_QTRACE_TRACE_PLUGIN_H_
#define SRC_QTRACE_TRACE_PLUGIN_H_

#include "qtrace/common.h"
#include "qtrace/options.h"

typedef void (*cb_syscall_start_t)(target_ulong cr3, target_ulong sysno);
typedef void (*cb_syscall_end_t)(target_ulong cr3, target_ulong retval);
typedef void (*cb_memread_post_t)(target_ulong cr3, target_ulong pc, int cpl,
                                  target_ulong buffer, target_ulong buffer_hi,
                                  int size);
typedef void (*cb_memread_pre_t)(target_ulong pc, target_ulong addr,
                                 target_ulong addr_hi, int size);
typedef void (*cb_memwrite_pre_t)(target_ulong cr3, target_ulong pc, int cpl,
                                  target_ulong addr, target_ulong addr_hi,
                                  target_ulong buffer, target_ulong buffer_hi,
                                  int size);
typedef void (*cb_change_state_t)(bool enable);
typedef void (*cb_print_state)(void);

struct PluginCallbacks {
  // ==== Notification routines ====
  cb_syscall_start_t syscall_start;
  cb_syscall_end_t syscall_end;
  cb_memread_pre_t memread_pre;
  cb_memread_post_t memread_post;
  cb_memwrite_pre_t memwrite_pre;

  // ==== Auxiliary callbacks ====

  // Print the plugin state (use logging functions)
  cb_print_state print_state;
};

// Plugin initialization function. This function is declared "extern", as it is
// exported by the specific plugin object.
extern int plugin_init(struct PluginCallbacks *callbacks,
                       const struct QTraceOptions *options);

#endif  // SRC_QTRACE_TRACE_PLUGIN_H_
