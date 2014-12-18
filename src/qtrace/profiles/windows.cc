//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/profiles/windows.h"

#include <cstdio>
#include <cstring>
#include <cassert>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"

target_ulong Windows::getKPCR(void) {
  if (kpcr_ == 0) {
    target_ulong fs = context_reg_safe(RegisterFsBase);

    // Ensure we are in kernel land, thus regs.fs_base points at the KPCR
    assert(!isUserAddress(fs));
    kpcr_ = fs;
  }

  return kpcr_;
}

Windows::Windows(const char **names, unsigned int names_size)
  : GuestOS(names, names_size), kpcr_(0) {
}

bool Windows::isKernelReady() {
  // Check if we already cached the address of the KPCB
  if (kpcr_ != 0) {
    return true;
  }

  target_ulong fs = context_reg_safe(RegisterFsBase);
  return !isUserAddress(fs);
}

target_ulong Windows::getSyscallParamsStack() const {
  // At syscall invocation, %edx contains the user-space stack pointer
  target_ulong edx = context_reg_safe(RegisterEdx);

  // Check %edx holds a user-space address (i.e., stack pointer)
  assert(isUserAddress(edx));

  // Skip two stack entries, the next one is the first syscall argument
  target_ulong stack_param = edx + sizeof(target_ulong)*2;

  return stack_param;
}
