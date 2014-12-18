//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_OPTIONS_H_
#define SRC_QTRACE_OPTIONS_H_

enum QTraceProfile {
  ProfileUnknown = 0,

#define FOO(popt, pclass, pname) Profile ## pclass,
#include "profiles/profiles.h"
#undef FOO
};

struct QTraceOptions {
#ifdef CONFIG_QTRACE_TRACER
  // Disable syscall tracer
  bool trace_disabled;

  // Filename where log messages should be logged. If not specified, defaults
  // to stderr
  const char *filename_log;

  // Profile (guest OS)
  enum QTraceProfile profile;

  // Filename of the syscalls trace file
  const char *filename_trace;

  // Comma-separated list of system calls to process
  const char *filter_syscalls;

  // Name of the process to trace
  const char *filter_process;

  // Tracking of foreign data pointers
  bool track_foreign;

  // Should we track repeated memory accesses?
  bool track_rep_accesses;
#endif

#ifdef CONFIG_QTRACE_TAINT
  // Disable taint-propagation engine
  bool taint_disabled;
#endif
};

#ifdef __cplusplus
extern "C" {
#endif
  const char *qtrace_get_profile_name(const enum QTraceProfile profile);
  int qtrace_parse_option(int opt, const char *optarg);
#ifdef __cplusplus
}
#endif

#endif  // SRC_QTRACE_OPTIONS_H_
