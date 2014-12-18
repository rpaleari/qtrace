//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/logging.h"

#include <cstdio>
#include <cstdarg>
#include <cstring>

#include "qtrace/common.h"
#include "qtrace/context.h"

static FILE *logfile;

int log_init(const char *filename) {
  if (!filename) {
    return 0;
  }

  // Initialize the log file
  logfile = fopen(filename, "w+");
  if (!logfile) {
    ERROR("Cannot open log file for writing");
    return -1;
  }

  return 0;
}

void qtrace_log_(const char *f, unsigned int l, const char *tag,
                 const char *fmt, ...) {
  va_list ap;
  char tmp[1024];

  va_start(ap, fmt);
  vsnprintf(tmp, sizeof(tmp), fmt, ap);
  va_end(ap);

  char pc[32];

#if defined(LOG_PC) && defined(CONFIG_QTRACE_TRACER)
  {
    target_ulong tmp_pc;
    if (gbl_context.cb_regs && gbl_context.cb_regs(RegisterPc, &tmp_pc) == 0) {
      snprintf(pc, sizeof(pc), "@%.8lx ", tmp_pc);
    } else {
      snprintf(pc, sizeof(pc), "@_unknown ");
    }
  }
#else
  pc[0] = '\0';
#endif

  fprintf(logfile ? logfile : stderr, "_QTrace_ %s[%s:%d] [%s] %s\n", pc, f, l,
          tag, tmp);
}
