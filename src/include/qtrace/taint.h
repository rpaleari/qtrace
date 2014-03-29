/*
   Copyright 2014, Roberto Paleari <roberto@greyhats.it>
*/

#ifndef SRC_INCLUDE_QTRACE_TAINT_H_
#define SRC_INCLUDE_QTRACE_TAINT_H_

#include "labels.h"

/* External variable that indicates whether taint propagation is currently
   enabled or not */
extern bool qtrace_taint_enabled;

/* "true" when generating instrumentation micro-ops. This flag is necessary to
   avoid instrumentation of our own code (and thus possible endless loops) */
extern bool qtrace_instrument;

/* Set a taint label for a CPU register */
void qtrace_taint_register(CPUArchState *env, bool istmp,
                           unsigned char regno, int label);

/* Set a taint label for a memory location */
void qtrace_taint_memory(CPUArchState *env, target_ulong addr,
                         int size, int label);

#endif  /* SRC_INCLUDE_QTRACE_TAINT_H_ */
