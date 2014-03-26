//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_PROCESS_H_
#define SRC_QTRACE_TRACE_PROCESS_H_

#include <string>
#include <memory>
#include <utility>

#include "qtrace/common.h"

// A running process object encapsulates data about the current OS process
class RunningProcess {
 private:
  target_ulong cr3_;

  // These fields are initialized lazily (i.e., upon first access)
  target_ulong pid_;
  target_ulong tid_;
  std::unique_ptr<std::string> name_;

  // Flag to implement lazy initialization of expensive process fields
  bool initialized_;

  // Complete the initialization of the process object, if required
  void init();

 public:
  // Instantiate an object representing the current process. The @cr3 argument
  // is the content of the CR3 register for the running process
  explicit RunningProcess(target_ulong cr3);

  target_ulong getCr3() const { return cr3_; }

  // Check if we can perform "late" initialization of this object, i.e.,
  // initialization operations that requires a fully-initialized kernel
  // environment
  bool canInitialize() const;

  // Check if OS-dependent initialization has already been performed
  inline bool isInitialized() const { return initialized_; }

  target_ulong getPid() { init(); return pid_; }
  target_ulong getTid() { init(); return tid_; }
  const std::string& getName() { init(); return *name_; }
};

#endif  // SRC_QTRACE_TRACE_PROCESS_H_
