//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_PROFILES_WINDOWS_H_
#define SRC_QTRACE_PROFILES_WINDOWS_H_

#include <string>
#include <vector>

#include "qtrace/common.h"
#include "qtrace/profiles/guest_os.h"

class Windows : public GuestOS {
 protected:
  // Local caching for the KPCR address. Note we assume we are emulating a
  // single-processor machine, thus we have a *single* KPCR
  target_ulong kpcr_;
  target_ulong getKPCR(void);

 public:
  explicit Windows(const char **names, unsigned int names_size);
  ~Windows() {}

  // Check we have an initialized KPCR and %fs points to a user-space address
  virtual bool isKernelReady();

  // 32-bit Windows does not pass syscall params by register
  int getNumSyscallParamsRegister() const { return 0; }
  void getSyscallParamsRegister(std::vector<GuestRegisterParam> &params)
    const {}
  target_ulong getSyscallParamsStack() const;
};

#endif  // SRC_QTRACE_PROFILES_WINDOWS_H_
