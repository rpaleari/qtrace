//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include <cassert>

#include "qtrace/trace/process.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"

RunningProcess::RunningProcess(target_ulong cr3)
  : cr3_(cr3), initialized_(false) {
}

bool RunningProcess::canInitialize() const {
  return gbl_context.guest->isKernelReady();
}

void RunningProcess::init(void) {
  if (initialized_) {
    return;
  }

  TRACE("Performing OS-dependent initialization for process @%.8x", cr3_);

  // Initialize PID, TID and process name fields
  int r;

  name_ = std::unique_ptr<std::string>(new std::string());
  r = gbl_context.guest->getProcessData(pid_, tid_, *(name_.get()));

  if (r != 0) {
    // FIXME: error handling
  }

  initialized_ = true;
}
