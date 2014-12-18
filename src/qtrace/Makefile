.PHONY: all clean distclean

include ../config-host.mak

CC=g++
CPPFLAGS=-Wall -O3 -fPIC -std=c++11 -I. -I.. -I../target-i386/ -I../include/
LDFLAGS=

ifdef CONFIG_QTRACE_PLUGIN
# This part is disable for user-emulation builds
PLUGIN_DIR=trace/plugin-$(CONFIG_QTRACE_PLUGIN)
include $(PLUGIN_DIR)/plugin.mak
plugin-objs := $(addprefix $(PLUGIN_DIR)/, $(plugin-objs))
else
plugin-objs=
plugin-generated=
endif

ifneq (,$(findstring x86_64-linux-user,$(TARGET_DIRS)))
# 64-bit, user mode
CPPFLAGS += -I../x86_64-linux-user/
else ifneq (,$(findstring x86_64,$(TARGET_DIRS)))
# 64-bit, whole system emulation
CPPFLAGS += -I../x86_64-softmmu/
else ifneq (,$(findstring i386-linux-user,$(TARGET_DIRS)))
# 32-bit, user mode
CPPFLAGS += -I../i386-linux-user/
else
# 32-bit, whole system emulation
CPPFLAGS += -I../i386-softmmu/
endif

libqtrace-objs = logging.o options.o context.o qtrace.o

ifeq ($(CONFIG_QTRACE_TRACER),y)
libqtrace-objs += trace/process.o trace/notify_syscall.o trace/intervals.o
libqtrace-objs += profiles/guest_os.o \
	profiles/windows.o profiles/winxpsp3.o profiles/win7sp0.o

ifneq (,$(findstring x86_64,$(TARGET_DIRS)))
# 64-bit profiles
libqtrace-objs += profiles/linux64.o profiles/osxmav.o profiles/win81.o
endif
endif

ifeq ($(CONFIG_QTRACE_TAINT),y)
libqtrace-objs += taint/notify_taint.o taint/shadow.o taint/taintengine.o
endif

ifeq ($(CONFIG_QTRACE_TRACER),y)
ifeq ($(CONFIG_QTRACE_TAINT),y)
libqtrace-objs += taint/tracker.o
endif
endif

all: libqtrace.so
clean:
	-rm $(libqtrace-objs) $(plugin-objs) $(plugin-generated)
distclean:
	-rm libqtrace.so

qtrace.o: qtrace.cc
	$(CC) $(CPPFLAGS) -c -o $@ $<

%.o: %.cc %.h logging.h
	$(CC) $(CPPFLAGS) -c -o $@ $<

libqtrace.so: $(libqtrace-objs) $(plugin-objs)
	$(CC) $(CPPFLAGS) -shared -o $@ $^ $(LDFLAGS)
