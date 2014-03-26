//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_OPTIONS_H_
#define SRC_QTRACE_OPTIONS_H_

enum QTraceProfile {
  ProfileUnknown = 0,
  ProfileWindowsXPSP0,
  ProfileWindowsXPSP1,
  ProfileWindowsXPSP2,
  ProfileWindowsXPSP3,
  ProfileWindows7SP0,
  ProfileWindows7SP1,
};

struct QTraceOptions {
#ifdef CONFIG_QTRACE_SYSCALL
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
#endif

#ifdef CONFIG_QTRACE_TAINT
  // Disable taint-propagation engine
  bool taint_disabled;
#endif
};

#ifdef __cplusplus
extern "C" {
#endif
  enum QTraceProfile qtrace_parse_profile(const char *profilestring);
  const char *qtrace_get_profile_name(const enum QTraceProfile profile);
#ifdef __cplusplus
}
#endif

#endif  // SRC_QTRACE_OPTIONS_H_
