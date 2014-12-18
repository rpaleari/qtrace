//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <string>

#include "qtrace/common.h"
#include "qtrace/options.h"

#include "qemu-options.h"

extern struct QTraceOptions qtrace_options;

const char* qtrace_get_profile_name(const enum QTraceProfile profile) {
  const char *name;

  switch (profile) {

#define FOO(popt, pclass, pname)		\
    case Profile ## pclass:			\
      name = # pname;				\
      break;
#include "profiles/profiles.h"
#undef FOO

  case ProfileUnknown:
  default:
    name = "Unknown";
    break;
  }
  return name;
}

static enum QTraceProfile qtrace_parse_profile(const char *profilestring) {
  std::string str(profilestring);
  std::transform(str.begin(), str.end(), str.begin(), ::tolower);

  if (str == "help") {
    // Show available profiles
    std::cout << "Available QTrace profiles:" << std::endl;
#define FOO(popt, pclass, pname)				\
    std::cout << "- [ " << std::setw(15) << # popt << " ] " <<	\
      pname << std::endl;
#include "profiles/profiles.h"
#undef FOO
    exit(0);
  }

  enum QTraceProfile profile;

#define FOO(popt, pclass, pname)	\
  if (str == # popt) {			\
    profile = Profile ## pclass;	\
  } else
#include "profiles/profiles.h"
#undef FOO
    {
      profile = ProfileUnknown;
    }

  return profile;
}

int qtrace_parse_option(int opt, const char *optarg) {
  int r = 0;

  switch (opt) {
#ifdef CONFIG_QTRACE_TRACER
  case QEMU_OPTION_qtrace_log:
    qtrace_options.filename_log = optarg;
    break;
  case QEMU_OPTION_qtrace_profile:
    qtrace_options.profile = qtrace_parse_profile(optarg);
    break;
  case QEMU_OPTION_qtrace_trace_disabled:
    qtrace_options.trace_disabled = true;
    break;
  case QEMU_OPTION_qtrace_trace:
    qtrace_options.filename_trace = optarg;
    break;
  case QEMU_OPTION_qtrace_syscalls:
    qtrace_options.filter_syscalls = optarg;
    break;
  case QEMU_OPTION_qtrace_process:
    qtrace_options.filter_process = optarg;
    break;
  case QEMU_OPTION_qtrace_foreign:
    qtrace_options.track_foreign = true;
    break;
  case QEMU_OPTION_qtrace_rep_accesses:
    qtrace_options.track_rep_accesses = true;
    break;
#endif
#ifdef CONFIG_QTRACE_TAINT
  case QEMU_OPTION_qtrace_taint_disabled:
    qtrace_options.taint_disabled = true;
    break;
#endif
  default:
    r = 1;
    break;
  }

  return r;
}
