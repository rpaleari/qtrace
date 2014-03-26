/*
  Copyright 2014, Roberto Paleari <roberto@greyhats.it>
*/

#include "qtrace/monitor.h"
#include "qtrace/gate.h"

void qtrace_qmp_qtrace_enable(Monitor *mon, const QDict *qdict) {
#ifdef CONFIG_QTRACE_SYSCALL
  qtrace_qmp_tracer_enable(mon, qdict);
#endif
#ifdef CONFIG_QTRACE_TAINT
  qtrace_qmp_taint_enable(mon, qdict);
#endif
}

void qtrace_qmp_qtrace_query(Monitor *mon, const QDict *qdict) {
#ifdef CONFIG_QTRACE_SYSCALL
  qtrace_qmp_tracer_query(mon, qdict);
#endif
#ifdef CONFIG_QTRACE_TAINT
  qtrace_qmp_taint_query(mon, qdict);
#endif
}

#ifdef CONFIG_QTRACE_SYSCALL
void qtrace_qmp_tracer_enable(Monitor *mon, const QDict *qdict) {
  bool state = qdict_get_bool(qdict, "enabled");
  qtrace_gate_tracer_set_state(state);
}

void qtrace_qmp_tracer_query(Monitor *mon, const QDict *qdict) {
  bool state = qtrace_gate_tracer_get_state();
  monitor_printf(mon, "QTrace syscall tracer is currently %s\n",
		 state ? "ON" : "OFF");

}
#endif

#ifdef CONFIG_QTRACE_TAINT
void qtrace_qmp_taint_enable(Monitor *mon, const QDict *qdict) {
  bool state = qdict_get_bool(qdict, "enabled");
  qtrace_gate_taint_set_state(state);
}

void qtrace_qmp_taint_query(Monitor *mon, const QDict *qdict) {
  bool state = qtrace_gate_taint_get_state();
  monitor_printf(mon, "QTrace taint tracker is currently %s\n",
		 state ? "ON" : "OFF");

}
#endif
