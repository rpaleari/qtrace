//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//
// This QTrace module implements the TraceManager object, used to coordinate
// and supervise the whole tracing activity.
//

#ifndef SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_MANAGER_H_
#define SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_MANAGER_H_

#include <unordered_map>
#include <vector>
#include <string>

#include "qtrace/common.h"
#include "qtrace/trace/process.h"

#include "qtrace/trace/plugin-systrace/memory.h"
#include "qtrace/trace/plugin-systrace/syscall.h"

class TraceManager {
 private:
  // Identifier of of the last instantiated system call object
  unsigned int current_syscall_id_;

  // Should we track external references?
  bool track_foreign_;

  // Should we monitor for reapeated memory accesses to the same location?
  bool track_rep_accesses_;

  // The structure that represents current system calls. Map key is the process
  // CR3 value
  std::unordered_map<target_ulong, Syscall*> current_syscalls_;

  // List of system call numbers to process, extracted from command-line
  //
  // Constraint: after initialization, this vector is sorted
  std::vector<target_ulong> filter_sysno_;

  // Name of the process to trace. If not set (i.e., empty string), trace all
  // system processes
  std::string filter_process_;

  // Syscalls filtering
  bool shouldProcessSyscall(target_ulong sysno, RunningProcess &rp) const;

  // Add a system call for the specified process
  void addSyscallForProcess(RunningProcess &rp, Syscall *syscall);

  // Remove the system call for the specified process
  void deleteSyscallForProcess(const RunningProcess &rp);

 public:
  explicit TraceManager(bool track_foreign, bool track_rep_accesses,
			const char *filter_syscalls,
			const char *filter_process);

  // Tracing of foreign data pointers
  bool isForeignEnabled() const {
    return track_foreign_;
  }

  // Tracing of repeated memory accesses
  bool isRepEnabled() const {
    return track_rep_accesses_;
  }

  // Check if the specified process is traced
  inline bool isTracedProcess(RunningProcess &rp) const {
    bool is_traced = true;
    if (unlikely(filter_process_.length() > 0) &&
	(rp.isInitialized() || rp.canInitialize())) {
      is_traced = (rp.getName() == filter_process_);
    }
    return is_traced;
  }

  // Get the system call for the specified process, or NULL is none is pending
  Syscall *getSyscallForProcess(RunningProcess &rp) const;

  // Check if there exist any pending system call for a given process
  bool hasSyscallForProcess(const target_ulong cr3) const;

  // Event processing for syscall start/end
  void eventSyscallStart(RunningProcess &rp, target_ulong sysno,
			 target_ulong stack);
  void eventSyscallEnd(RunningProcess &rp, target_ulong retval);
};

extern TraceManager *gbl_trace_manager;

#endif  // SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_MANAGER_H_
