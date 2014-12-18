//
// Copyright 2014
//   Roberto Paleari <roberto@greyhats.it>
//   Aristide Fattori <aristidefattori@gmail.com>
//
// MacOSX Mavericks 10.9.4
//

#ifndef SRC_QTRACE_PROFILES_OSXMAV_H_
#define SRC_QTRACE_PROFILES_OSXMAV_H_

#include <string>
#include <vector>

#include "qtrace/common.h"
#include "qtrace/profiles/guest_os.h"

class OSXMavericks : public GuestOS {
 private:
  std::vector<std::string> mach_trap_names_;

 protected:
  target_ulong current_;
  bool ready_;
  target_ulong getCurrentTask(void);

 public:
  virtual bool isUserAddress(target_ulong addr) const {
    return (addr >> 47) == 0;
  }

  virtual int getProcessData(uint32_t &pid, uint32_t &tid, std::string &name);

  explicit OSXMavericks();
  ~OSXMavericks() {}

  virtual bool isKernelReady();
  virtual void setupTraps();

  //
  // Parameter-passing ABI for OSX 64-bit syscalls
  //
  int getNumSyscallParamsRegister() const {
    return 6;
  }
  std::vector<std::string> getSyscallTable(target_ulong sysno) const;
  virtual const char *getSyscallName(target_ulong sysno) const;
  virtual int getSyscallNumber(const std::string &name) const;

  void getSyscallParamsRegister(std::vector<GuestRegisterParam> &params) const;
  target_ulong getSyscallParamsStack() const;
};

#endif  // SRC_QTRACE_PROFILES_OSXMAV_H_
