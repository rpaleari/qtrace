//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_WINXPSP3_H_
#define SRC_QTRACE_TRACE_WINXPSP3_H_

#include <string>

#include "qtrace/common.h"
#include "qtrace/trace/windows.h"

class WindowsXPSP3 : public Windows {
 public:
  explicit WindowsXPSP3();
  ~WindowsXPSP3() {}

  virtual int getProcessData(uint32_t &pid, uint32_t &tid,
                             std::string &name);
  virtual bool isUserAddress(target_ulong addr) const;
};

#endif  // SRC_QTRACE_TRACE_WINXPSP3_H_
