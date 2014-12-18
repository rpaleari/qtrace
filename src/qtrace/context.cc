//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/context.h"

#include <cassert>

#include "qtrace/logging.h"
#include "qtrace/options.h"

struct QTraceContext gbl_context;

void context_print() {
#ifdef CONFIG_QTRACE_TRACER
  INFO("Log file:                     %s",
       gbl_context.options.filename_log ?
       gbl_context.options.filename_log : "<stdout>");

  INFO("Trace file:                   %s",
       gbl_context.options.filename_trace ?
       gbl_context.options.filename_trace : "none");

  INFO("Guest OS profile:             %s",
       qtrace_get_profile_name(gbl_context.options.profile));

  INFO("Tracked process:              %s",
       gbl_context.options.filter_process ?
       gbl_context.options.filter_process : "all");

  INFO("Syscall filter:               %s",
       gbl_context.options.filter_syscalls ?
       gbl_context.options.filter_syscalls : "none");

  if (gbl_context.callbacks.print_state) {
    gbl_context.callbacks.print_state();
  }
#endif

#ifdef CONFIG_QTRACE_TAINT
  INFO("Taint tracking:               %s",
       gbl_context.options.taint_disabled ? "OFF" : "ON");
#endif
}

#ifdef CONFIG_QTRACE_TRACER
target_ulong context_reg_safe(enum CpuRegister reg) {
  target_ulong value;
  int r;
  assert(gbl_context.cb_regs);
  r = gbl_context.cb_regs(reg, &value);
  assert(r == 0);
  return value;
}
#endif
