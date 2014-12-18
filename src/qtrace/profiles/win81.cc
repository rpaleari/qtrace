//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include <cassert>
#include <cstring>
#include <memory>

#include "qtrace/context.h"
#include "qtrace/profiles/win81.h"
#include "qtrace/profiles/win81_symbols.h"
#include "qtrace/profiles/win81_syscalls.h"

Windows8_1::Windows8_1()
  : Windows(Windows8_1_syscalls,
            sizeof(Windows8_1_syscalls) / sizeof(char *)) {
}

bool Windows8_1::isUserAddress(target_ulong addr) const {
  return (addr >> 48) == 0;
}

int Windows8_1::getProcessData(uint32_t &pid, uint32_t &tid,
                                std::string &name) {
  target_ulong kpcr = getKPCR();

  // TODO
  return -1;
}
