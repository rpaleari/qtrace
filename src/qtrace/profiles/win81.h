//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_PROFILES_WIN81_H_
#define SRC_QTRACE_PROFILES_WIN81_H_

#include <string>

#include "qtrace/common.h"
#include "qtrace/profiles/windows.h"

class Windows8_1 : public Windows {
 public:
  explicit Windows8_1();
  ~Windows8_1() {}

  virtual int getProcessData(uint32_t &pid, uint32_t &tid,
                             std::string &name);
  virtual bool isUserAddress(target_ulong addr) const;
};

#endif  // SRC_QTRACE_PROFILES_WIN81_H_
