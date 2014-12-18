//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/profiles/guest_os.h"

#include <cstdio>
#include <cstring>
#include <cassert>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/profiles/winxpsp3.h"
#include "qtrace/profiles/win7sp0.h"

#if TARGET_LONG_BITS != 32
#include "qtrace/profiles/linux64.h"
#include "qtrace/profiles/osxmav.h"
#include "qtrace/profiles/win81.h"
#endif

int guest_os_init(GuestOS **guest_obj) {
  switch (gbl_context.options.profile) {
#define FOO(popt, pclass, pname)                \
    case Profile ## pclass:                     \
      *guest_obj = new pclass();                \
      break;
#include "profiles/profiles.h"
#undef FOO

  default:
    ERROR("Unsupported guest OS version. "
          "Have you specified which QTrace profile to use?");
    return -1;
  }

  return 0;
}

GuestOS::GuestOS(const char **names, unsigned int names_size) {
  for (unsigned int i = 0; i < names_size; i++) {
    syscall_names_.push_back(names[i]);
  }
}

bool GuestOS::isValidAddress(target_ulong addr) const {
#if TARGET_LONG_BITS == 32
  // 32-bit
  return true;
#else
  // 64-bit, return true iff addr is canonical
  return !(addr >> 47) ? true : (addr >> 47) == 0x1ffff;
#endif
}

void GuestOS::getStackTrace(std::vector<target_ulong> &addresses,
                            unsigned int max_depth) const {
  unsigned int r;
  target_ulong ra;

  target_ulong fp = context_reg_safe(RegisterEbp);

  for (unsigned int i = 0; i < max_depth; i++) {
    r = gbl_context.cb_peek(fp + sizeof(target_ulong),
                            reinterpret_cast<unsigned char *>(&ra),
                            sizeof(target_ulong));
    if (r != 0) {
      DEBUG("Unable to read from fp+%d (0x%016llx). "
            "Stopping backtrace after %d records.",
            sizeof(target_ulong), fp + sizeof(target_ulong), i);
      break;
    }

    DEBUG("%016llx: %016llx", fp + sizeof(target_ulong), ra);
    addresses.push_back(ra);

    // Read the next frame pointer
    r = gbl_context.cb_peek(fp, reinterpret_cast<unsigned char *>(&fp),
                            sizeof(target_ulong));

    if (r != 0) {
      DEBUG("Stopping backtrace, cannot read fp @0x%016llx", fp);
      break;
    }
  }
}

// FIXME: this function is *not* reentrant, as it returns a pointer to a
// statically allocated buffer
const char *GuestOS::getSyscallName(target_ulong sysno) const {
  static char name[64];
  if (sysno > syscall_names_.size()) {
    snprintf(name, sizeof(name), "unknown%ld", sysno);
  } else {
    strncpy(name, syscall_names_[sysno].c_str(), sizeof(name));
  }

  return name;
}

int GuestOS::getSyscallNumber(const std::string &name) const {
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

bool GuestOS::isUserPointer(target_ulong buffer, int size) const {
  if (size != sizeof(target_ulong)) {
    return false;
  }

  if (!isUserAddress(buffer)) {
    return false;
  }

  return true;
}
