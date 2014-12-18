//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//
// GuestOS is an abstract class to represent a generic guest operating
// system.
//
// According to the current profile, a concrete subclass is eventually
// instantiated and used to perform VM-instrospection operations.
//

#ifndef SRC_QTRACE_PROFILES_GUEST_OS_H_
#define SRC_QTRACE_PROFILES_GUEST_OS_H_

#include <string>
#include <vector>

#include "qtrace/common.h"

typedef struct {
  target_ulong value;
  const std::string name;
} GuestRegisterParam;

class GuestOS {
 protected:
  std::vector<std::string> syscall_names_;

  // Check if a given VA is a valid user/kernel address. On 32-bit systems
  // always return true, but on 64-bit systems check if the address is
  // canonical.
  bool isValidAddress(target_ulong addr) const;

 public:
  explicit GuestOS(const char **names, unsigned int names_size);
  ~GuestOS() {}

  // Determine if a given VA is a user-space address
  virtual bool isUserAddress(target_ulong addr) const = 0;

  // Determine if a given VA is a kernel-space address
  bool isKernelAddress(target_ulong addr) const {
    return isValidAddress(addr) && !isUserAddress(addr);
  }

  // Guess (remind it is just a guess!) if a size-byte memory buffer contains a
  // user-space pointer
  virtual bool isUserPointer(target_ulong buffer, int size) const;

  // Perform a "stack walk" of max_depth frames, saving the return address of
  // each frame in the "addresses" array. This function returns the actual
  // number of return addresses save in the "addresses" array (<= "max_depth").
  void getStackTrace(std::vector<target_ulong> &addresses,
                     unsigned int max_depth) const;

  // Return the name of the system call with the given ID
  virtual const char *getSyscallName(target_ulong sysno) const;

  // Return the ID of a system call, given its name
  virtual int getSyscallNumber(const std::string &name) const;

  // Get basic information about the current process: PID, TID and process name
  virtual int getProcessData(uint32_t &pid, uint32_t &tid,
                             std::string &name) = 0;

  // Check if we are in a "sane" kernel execution environment (e.g., segment
  // registers have already been updated with ring-0 selectors)
  virtual bool isKernelReady() = 0;

  // NOTE: The following methods implement the ABI for system call
  // parameters. All these methods assume the guest OS is stopped right after
  // beginning the execution of the system call (e.g., after the context-switch
  // in kernel land)

  // Populate vector "params" with the value of system call parameters passed
  // using CPU registers
  virtual void getSyscallParamsRegister(std::vector<GuestRegisterParam> &params)
    const = 0;

  // Return the number of syscall parameters passed through CPU registers
  virtual int getNumSyscallParamsRegister() const = 0;

  // Return the address of the memory location that holds the first syscall
  // parameter passed on the stack
  virtual target_ulong getSyscallParamsStack() const = 0;
};

// Initialize the Windows module
int guest_os_init(GuestOS **guest_obj);

#endif  // SRC_QTRACE_PROFILES_GUEST_OS_H_
