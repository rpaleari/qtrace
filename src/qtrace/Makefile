.PHONY: all clean distclean

include ../config-host.mak

CC=g++
CPPFLAGS=-Wall -O3 -fPIC -std=c++11 -I. -I.. -I../target-i386/ -I../i386-softmmu/ -I../i386-linux-user/ -I../include/
LDFLAGS=-lprotobuf

libqtrace-objs  = logging.o options.o context.o qtrace.o

ifeq ($(CONFIG_QTRACE_SYSCALL),y)
libqtrace-objs += pb/syscall.pb.o trace/syscall.o
libqtrace-objs += trace/process.o trace/manager.o trace/serialize.o trace/memory.o \
	trace/notify_syscall.o trace/intervals.o
libqtrace-objs += trace/windows.o trace/winxpsp3.o trace/win7sp0.o
endif

ifeq ($(CONFIG_QTRACE_TAINT),y)
libqtrace-objs += taint/notify_taint.o taint/shadow.o taint/taintengine.o
endif

ifeq ($(CONFIG_QTRACE_SYSCALL),y)
ifeq ($(CONFIG_QTRACE_TAINT),y)
libqtrace-objs += taint/tracker.o
endif
endif

protobuf-files = pb/syscall.pb.cc pb/syscall.pb.h

all: libqtrace.so
clean:
	-rm $(libqtrace-objs) $(protobuf-files)
distclean:
	-rm libqtrace.so

pb/syscall.pb.cc: pb/syscall.proto
	protoc $^ --cpp_out=$(CURDIR)/

pb/syscall.pb.h: pb/syscall.pb.cc

syscall.pb.o: $(protobuf-files)
	$(CC) $(CPPFLAGS) -c -o $@ $<

qtrace.o: qtrace.cc
	$(CC) $(CPPFLAGS) -c -o $@ $<

%.o: %.cc %.h logging.h
	$(CC) $(CPPFLAGS) -c -o $@ $<

libqtrace.so: $(libqtrace-objs)
	$(CC) $(CPPFLAGS) -shared -o $@ $^ $(LDFLAGS)
