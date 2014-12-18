//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/notify_syscall.h"

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"

// True if tracing is enabled. This variable mirrors
// gbl_context.tracer_enabled, but is externally used by the QEMU core
// (TCG). The reason why we duplicate it is that we cannot include "complex"
// C++ structures from QEMU code (such as QTraceContext).
bool gbl_qtrace_tracer_enabled = false;

// True if a state change (ON/OFF) for the syscall tracer is currently
// pending. The state change will be applied as soon a safe execution state is
// reached
static bool gbl_tracer_state_change = false;

// Return the plugin callback for the specified event
#define CB(event) (gbl_context.callbacks.event)

void notify_syscall_start(target_ulong cr3, target_ulong sysno) {
  if (gbl_context.tracer_enabled && CB(syscall_start)) {
    CB(syscall_start)(cr3, sysno);
  }
}

void notify_syscall_end(target_ulong cr3, target_ulong retval) {
  if (gbl_context.tracer_enabled && CB(syscall_start)) {
    CB(syscall_end)(cr3, retval);
  }

  // Handle tracer state changes. We postpone state changes at the end of the
  // most "coarse-grained" event, i.e., at a "syscall end" event
  if (gbl_tracer_state_change) {
    gbl_context.tracer_enabled = !gbl_context.tracer_enabled;
    gbl_qtrace_tracer_enabled = gbl_context.tracer_enabled;
    INFO("Switching tracer state, now %s",
         gbl_context.tracer_enabled ? "ON" : "OFF");
    gbl_tracer_state_change = false;

    // Flush TB cache
    gbl_context.cb_tbflush();
  }
}

void notify_memread_post(target_ulong cr3, target_ulong pc, int cpl,
                         target_ulong buffer, target_ulong buffer_hi,
                         int size) {
  if (gbl_context.tracer_enabled && CB(memread_post)) {
    CB(memread_post)(cr3, pc, cpl, buffer, buffer_hi, size);
  }
}

void notify_memread_pre(target_ulong pc, target_ulong addr,
                        target_ulong addr_hi, int size) {
  if (gbl_context.tracer_enabled && CB(memread_pre)) {
    CB(memread_pre)(pc, addr, addr_hi, size);
  }
}

void notify_memwrite_pre(target_ulong cr3, target_ulong pc, int cpl,
                         target_ulong addr, target_ulong addr_hi,
                         target_ulong buffer, target_ulong buffer_hi,
                         int size) {
  if (gbl_context.tracer_enabled && CB(memwrite_pre)) {
    CB(memwrite_pre)(cr3, pc, cpl, addr, addr_hi, buffer, buffer_hi, size);
  }
}

void notify_tracer_set_state(bool state) {
  if (gbl_tracer_state_change) {
    ERROR("A state change is already pending, ignoring request");
    return;
  }

  if (state != gbl_context.tracer_enabled) {
    // Request a state change. Tracer state is changed only at a safe execution
    // point
    gbl_tracer_state_change = true;
  }
}

bool notify_tracer_get_state(void) {
  return gbl_context.tracer_enabled;
}
