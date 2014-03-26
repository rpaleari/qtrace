//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/windows.h"

#include <cstdio>
#include <cstring>
#include <cassert>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/trace/winxpsp3.h"
#include "qtrace/trace/win7sp0.h"

int windows_init(Windows **windows_obj) {
  switch (gbl_context.options.profile) {
  case ProfileWindowsXPSP3:
    *windows_obj = new WindowsXPSP3();
    break;
  case ProfileWindows7SP0:
    *windows_obj = new Windows7SP0();
    break;
  default:
    ERROR("Unsupported guest OS version. "
          "Have you specified which QTrace profile to use?");
    return -1;
  }

  return 0;
}

target_ulong Windows::getKPCR(void) {
  if (kpcr_ == 0) {
    CpuRegisters regs;
    int err = gbl_context.cb_regs(&regs);
    assert(err == 0);

    // Ensure we are in kernel land, thus regs.fs_base points at the KPCR
    assert(!isUserAddress(regs.fs_base));
    kpcr_ = regs.fs_base;
  }

  return kpcr_;
}

bool Windows::isUserPointer(target_ulong buffer, int size) const {
  if (size != sizeof(target_ulong)) {
    return false;
  }

  if (!isUserAddress(buffer)) {
    return false;
  }

  return true;
}

Windows::Windows(const char **names, unsigned int names_size)
  : kpcr_(0) {
  for (unsigned int i = 0; i < names_size; i++) {
    syscall_names_.push_back(names[i]);
  }
}

// FIXME: this function is *not* reentrant, as it returns a pointer to a
// statically allocated buffer
const char *Windows::getSyscallName(target_ulong sysno) const {
  static char name[64];

  if (sysno > syscall_names_.size()) {
    snprintf(name, sizeof(name), "unknown%d", sysno);
  } else {
    strncpy(name, syscall_names_[sysno].c_str(), sizeof(name));
  }

  return name;
}

int Windows::getSyscallNumber(std::string name) const {
  int r = -1, i = 0;
  for (auto it = syscall_names_.begin();
       it != syscall_names_.end();
       i++, it++) {
    if (*it == name) {
      r = i;
      break;
    }
  }
  return r;
}

bool Windows::isKernelReady() const {
  // Check if we already cached the address of the KPCB
  if (kpcr_ != 0) {
    return true;
  }

  CpuRegisters regs;
  int err = gbl_context.cb_regs(&regs);
  assert(err == 0);

  return !isUserAddress(regs.fs_base);
}
