/*
   Copyright 2014, Roberto Paleari <roberto@greyhats.it>

   This module includes QEMU monitor commands to interact with QTrace.
*/

#ifndef SRC_INCLUDE_QTRACE_MONITOR_H_
#define SRC_INCLUDE_QTRACE_MONITOR_H_

#include "monitor/monitor.h"

void qtrace_qmp_qtrace_enable(Monitor *mon, const QDict *qdict);
void qtrace_qmp_qtrace_query(Monitor *mon, const QDict *qdict);

#ifdef CONFIG_QTRACE_TRACER
void qtrace_qmp_tracer_enable(Monitor *mon, const QDict *qdict);
void qtrace_qmp_tracer_query(Monitor *mon, const QDict *qdict);
#endif

#ifdef CONFIG_QTRACE_TAINT
void qtrace_qmp_taint_enable(Monitor *mon, const QDict *qdict);
void qtrace_qmp_taint_query(Monitor *mon, const QDict *qdict);
#endif

#endif  /* SRC_INCLUDE_QTRACE_MONITOR_H_ */
