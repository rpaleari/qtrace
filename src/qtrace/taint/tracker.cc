//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/taint/notify_taint.h"
#include "qtrace/taint/tracker.h"

static void track_copy_labels(SyscallArg *arg) {
  hwaddr phyaddr = gbl_context.cb_va2phy(arg->addr);
  assert(phyaddr != static_cast<hwaddr>(-1));
  gbl_context.taint_engine->copyMemoryLabels(arg->taint_labels,
                                             phyaddr, arg->getSize());
}

static void track_syscall_arg(SyscallArg *arg, target_ulong label) {
  if (!gbl_context.taint_engine->isUserEnabled()) {
    return;
  }

  // FIXME: This check applies a workaround for a nasty bug. Sometimes, for
  // IN/OUT arguments we see the kernel reading a "large" argument buffer, due
  // to an unexpected memory access to a pointer close to the argument base
  // address. We can sometimes recognize these situations by comparing the size
  // of the input and output buffers. Try tracing system calls NtOpenKey and
  // NtQueryValueKey for an example of this behavior.
  if (arg->direction == DirectionInOut &&
      (arg->indata.getMaxLength() != arg->outdata.getMaxLength()) &&
      notify_taint_check_memory(arg->addr, arg->getSize())) {
    TRACE("Applying 'big buffer' workaround for argument %.8x-%.8x",
          arg->addr, arg->addr + arg->getSize() - 1);
    notify_taint_clearM(arg->addr, arg->getSize());
  }

  // Check and copy taintedness of IN and IN/OUT arguments
  if (arg->direction == DirectionIn) {
    if (notify_taint_check_memory(arg->addr, arg->getSize())) {
      TRACE("Found tainted IN | IN/OUT arg in range %.8x-%.8x "
            "[phy %.8x-%.8x]",
            arg->addr, arg->addr + arg->getSize() - 1,
            gbl_context.cb_va2phy(arg->addr),
            gbl_context.cb_va2phy(arg->addr + arg->getSize() - 1));
      track_copy_labels(arg);
    }
  }

  // Clear taint status of OUT and IN/OUT arguments
  if (arg->direction == DirectionOut || arg->direction == DirectionInOut) {
    notify_taint_clearM(arg->addr, arg->getSize());
  }

  // Add new taint labels for OUT arguments
  if (arg->direction == DirectionOut &&
      arg->getSize() == sizeof(target_ulong)) {
    notify_taint_memory(arg->addr, sizeof(target_ulong), label);
  }

  // Recurse
  for (auto it = arg->ptrs.begin(); it != arg->ptrs.end(); it++) {
    track_syscall_arg(*it, label);
  }
}

void track_syscall_deps(Syscall &syscall) {
  for (auto it = syscall.args.begin(); it != syscall.args.end(); it++) {
    track_syscall_arg(*it, syscall.id);

    // Also clear taint-status of level-0 argument addresses
    notify_taint_clearM((*it)->addr, sizeof(target_ulong));
  }

  // Add a taint label for the syscall return value
  target_ulong retreg;
  bool b = gbl_context.taint_engine->
    getRegisterIdByName(_XSTR(QTRACE_REG_SYSCALL_RESULT), retreg);
  assert(b == true);
  notify_taint_register(false, retreg, syscall.id);
}
