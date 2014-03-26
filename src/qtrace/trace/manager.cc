//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/manager.h"

#include <algorithm>
#include <sstream>
#include <vector>
#include <string>

#include "qtrace/logging.h"
#include "qtrace/context.h"
#include "qtrace/trace/serialize.h"

#ifdef CONFIG_QTRACE_TAINT
#include "qtrace/taint/tracker.h"
#endif

TraceManager::TraceManager(bool track_foreign,
                           const char *filtersyscalls,
                           const char *filterprocess)
  : current_syscall_id_(0), track_foreign_(track_foreign) {
  // Split the system calls filter string on commas and resolve syscall names
  // to numbers
  if (filtersyscalls) {
    std::stringstream ss(filtersyscalls);
    std::string syscall_name;
    while (std::getline(ss, syscall_name, ',')) {
      int sysno = gbl_context.windows->getSyscallNumber(syscall_name);
      if (sysno == -1) {
        WARNING("Invalid syscall name '%s', ignoring", syscall_name.c_str());
      }
      filter_sysno_.push_back(sysno);
    }

    // Keep filter_sysno_ sorted to optimize lookups
    std::sort(filter_sysno_.begin(), filter_sysno_.end());
  }

  if (filterprocess) {
    filter_process_ = std::string(filterprocess);
  }
}

Syscall* TraceManager::getSyscallForProcess(RunningProcess &rp) const {
  auto it = current_syscalls_.find(rp.getCr3());
  if (it == current_syscalls_.end()) {
    return NULL;
  }

  Syscall *syscall = it->second;

  // We take this opportunity also to update the OS-dependent attributes of the
  // Syscall object, according to its corresponding RunningProcess
  // instance. This is not perfomed when the Syscall object is instantiated
  // first, as they must be performed when executing in a "sane" ring-0
  // environment (e.g., when all segment registers have been switched,
  // especially %fs)
  if (!syscall->isOSInitialized()) {
    syscall->tryOSInitialize(rp);
  }

  return it->second;
}

void TraceManager::addSyscallForProcess(RunningProcess &rp, Syscall *syscall) {
  assert(getSyscallForProcess(rp) == NULL);
  current_syscalls_[rp.getCr3()] = syscall;
}

bool TraceManager::hasSyscallForProcess(const target_ulong cr3) const {
  return current_syscalls_.count(cr3) > 0;
}

void TraceManager::deleteSyscallForProcess(const RunningProcess &rp) {
  delete current_syscalls_[rp.getCr3()];
  current_syscalls_.erase(rp.getCr3());
}

bool TraceManager::shouldProcessSyscall(target_ulong sysno,
                                        RunningProcess &rp) const {
  bool traceme = true;

  // Check on syscall filter
  if (filter_sysno_.size() > 0) {
    // Here we exploit the fact that filter_sysno_ is sorted
    auto low = std::lower_bound(filter_sysno_.begin(),
                                filter_sysno_.end(),
                                sysno);

    traceme = (low != filter_sysno_.end() && *low == sysno);
  }

  // Check on process name
  if (traceme && filter_process_.length() > 0 &&
      (rp.isInitialized() || rp.canInitialize())) {
    traceme = (rp.getName() == filter_process_);
  }

  return traceme;
}

void TraceManager::eventSyscallStart(RunningProcess &rp, target_ulong sysno,
                                     target_ulong stack) {
  if (getSyscallForProcess(rp)) {
    // Current system call is still active, terminate it.
    // FIXME: We put a dummy return value here, as we already missed the real
    // one
    WARNING("Finalizing a pending system call");
    eventSyscallEnd(rp, 0x0badb00b);
    assert(getSyscallForProcess(rp) == NULL);
  }

  // Check if we should process this system call
  if (!shouldProcessSyscall(sysno, rp)) {
    TRACE("Filtering out syscall (#%d, %s)", sysno,
          gbl_context.windows->getSyscallName(sysno));
    return;
  }

  // Initiate a new Syscall object
  Syscall *current_syscall = new Syscall(current_syscall_id_++,
                                         sysno, stack, rp.getCr3());

  addSyscallForProcess(rp, current_syscall);

  DEBUG("Starting system call #%d (stack %08x): %s",
        current_syscall->sysno, current_syscall->stack,
        gbl_context.windows->getSyscallName(current_syscall->sysno));
}

void TraceManager::eventSyscallEnd(RunningProcess &rp, target_ulong retval) {
  Syscall *current_syscall = getSyscallForProcess(rp);

  if (!current_syscall) {
    TRACE("Returning from a pending system call");
    return;
  }

  // Update the system call return value
  current_syscall->retval = retval;

  // Cleanup foreign data pointers
  if (isForeignEnabled()) {
    current_syscall->cleanupForeignPointers();
    if (current_syscall->foreign_ptrs.size() > 0) {
      DEBUG("Got %d foreign pointer(s)",
            current_syscall->foreign_ptrs.size());
      for (auto it = current_syscall->foreign_ptrs.begin();
           it != current_syscall->foreign_ptrs.end(); it++) {
        DEBUG("Foreign pointer: addr 0x%.8x, value 0x%.8x, pc 0x%.8x",
              (*it)->addr, (*it)->value, (*it)->pc);
      }
    }
  }

#ifdef CONFIG_QTRACE_TAINT
  // Perform dependency tracking on system call arguments
  track_syscall_deps(*current_syscall);
#endif

  // Dump this system call
  DEBUG(current_syscall->to_string().c_str());

  // Ensure we processed all "level 0" arguments. The '< 0' case is for system
  // calls with no arguments, as in this case missing_args equals to -1 (not
  // initialized).
  if (current_syscall->missing_args <= 0) {
    serialize_syscall(current_syscall);

    DEBUG("Returning from system call #%d (%.8x): %s",
          current_syscall->sysno, current_syscall->sysno,
          gbl_context.windows->getSyscallName(current_syscall->sysno));
  } else {
    ERROR("Still %d missing arguments for this system call. Skipping it!");
  }

  deleteSyscallForProcess(rp);
}
