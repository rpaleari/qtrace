//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include <algorithm>
#include <string>

#include "qtrace/options.h"

const char* qtrace_get_profile_name(const enum QTraceProfile profile) {
  const char *name;
  switch (profile) {
  case ProfileWindowsXPSP3:
    name = "Windows XP SP3";
    break;
  case ProfileWindows7SP0:
    name = "Windows 7 SP0";
    break;
  case ProfileUnknown:
  default:
    name = "Unknown";
    break;
  }
  return name;
}

enum QTraceProfile qtrace_parse_profile(const char *profilestring) {
  std::string str(profilestring);
  std::transform(str.begin(), str.end(), str.begin(), ::tolower);

  enum QTraceProfile profile;
  if (str == "winxpsp3") {
    profile = ProfileWindowsXPSP3;
  } else if (str == "win7sp0") {
    profile = ProfileWindows7SP0;
  } else {
    profile = ProfileUnknown;
  }

  return profile;
}
