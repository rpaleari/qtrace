/*
  Copyright 2014, Roberto Paleari <roberto@greyhats.it>

  The "taint" module acts as a bridge between QEMU and QTrace taint engine.

  See comments at the top of "gate.c" for a motivation of this hack :-)
*/

/* Must come first */
#include "cpu.h"

#include <stdbool.h>
#include <assert.h>

#include "qtrace/taint.h"
#include "qtrace/gate.h"
#include "qtrace/taint/notify_taint.h"

void qtrace_taint_register(CPUArchState *env,
			   bool istmp, unsigned char regno,
			   int label) {
#ifndef CONFIG_USER_ONLY
  if (!qtrace_taint_enabled) {
    return;
  }
#endif

  notify_taint_register(istmp, regno, label);
}

void qtrace_taint_memory(CPUArchState *env,
			 target_ulong addr, int size,
			 int label) {
#ifndef CONFIG_USER_ONLY
  if (!qtrace_taint_enabled) {
    return;
  }
#endif

  /* Assume the memory region does not span multiple pages */
  assert((addr & TARGET_PAGE_MASK) == ((addr+size-1) & TARGET_PAGE_MASK));

  notify_taint_memory(addr, size, label);
}
