//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/options.h"

struct QTraceContext gbl_context;

void context_print() {
#ifdef CONFIG_QTRACE_SYSCALL
  INFO("Log file:                     %s",
       gbl_context.options.filename_log ?
       gbl_context.options.filename_log : "<stdout>");

  INFO("Trace file:                   %s",
       gbl_context.options.filename_trace ?
       gbl_context.options.filename_trace : "none");

  INFO("Target OS profile:            %s",
       qtrace_get_profile_name(gbl_context.options.profile));

  INFO("Tracking of foreign pointers: %s",
       gbl_context.trace_manager->isForeignEnabled() ? "ON" : "OFF");

  INFO("Tracked process:              %s",
       gbl_context.options.filter_process ?
       gbl_context.options.filter_process : "all");

  INFO("Syscall filter:               %s",
       gbl_context.options.filter_syscalls ?
       gbl_context.options.filter_syscalls : "none");
#endif

#ifdef CONFIG_QTRACE_TAINT
  INFO("Taint tracking:               %s",
       gbl_context.options.taint_disabled ? "OFF" : "ON");
#endif
}
