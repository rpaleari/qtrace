//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_PLUGIN_DUMMY_MAIN_H_
#define SRC_QTRACE_TRACE_PLUGIN_DUMMY_MAIN_H_

#include "qtrace/trace/plugin.h"
#include "qtrace/options.h"

int plugin_init(struct PluginCallbacks *callbacks,
		const struct QTraceOptions *options);

#endif  // SRC_QTRACE_TRACE_PLUGIN_DUMMY_MAIN_H_
