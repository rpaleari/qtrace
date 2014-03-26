//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_WINDOWS_H_
#define SRC_QTRACE_TRACE_WINDOWS_H_

#include <string>
#include <vector>

#include "qtrace/common.h"

class Windows {
 private:
  std::vector<std::string> syscall_names_;

 protected:
  // Local caching for the KPCR address. Note we assume we are emulating a
  // single-processor machine, thus we have a *single* KPCR
  target_ulong kpcr_;
  target_ulong getKPCR(void);

 public:
  explicit Windows(const char **names, unsigned int names_size);
  ~Windows() {}

  // Determine if a given VA is a user-space address
  virtual bool isUserAddress(target_ulong addr) const = 0;

  // Guess (remind it is just a guess!) if a size-byte memory buffer contains a
  // user-space pointer
  virtual bool isUserPointer(target_ulong buffer, int size) const;

  // Return the name of the system call with the given ID
  const char *getSyscallName(target_ulong sysno) const;

  // Return the ID of a system call, given its name
  int getSyscallNumber(std::string name) const;

  // Get basic information about the current process: PID, TID and process name
  virtual int getProcessData(uint32_t &pid, uint32_t &tid,
                             std::string &name) = 0;

  // Check if we are in a "sane" kernel execution environment (e.g., segment
  // registers have already been updated with ring-0 selectors)
  virtual bool isKernelReady() const;
};

// Initialize the Windows module
int windows_init(Windows **windows_obj);

#endif  // SRC_QTRACE_TRACE_WINDOWS_H_
