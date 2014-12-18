//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/plugin-dummy/main.h"

#include "qtrace/trace/plugin-dummy/callbacks.h"

int plugin_init(struct PluginCallbacks *callbacks,
		const struct QTraceOptions *options) {
  // Initialize notification callbacks

  callbacks->syscall_start = cb_dummy_syscall_start;
  callbacks->syscall_end = cb_dummy_syscall_end;
  callbacks->memread_pre = cb_dummy_memread_pre;
  callbacks->memread_post = cb_dummy_memread_post;
  callbacks->memwrite_pre = cb_dummy_memwrite_pre;

  return 0;
}
