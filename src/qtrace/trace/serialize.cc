//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/serialize.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <cstdio>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/trace/intervals.h"
#include "qtrace/trace/syscall.h"
#include "qtrace/pb/syscall.pb.h"

// Output file stream for serialized system calls
static std::unique_ptr<std::fstream> outstream;

static void serialize_interval(const DataInterval &di,
                               syscall::DataInterval *out_di) {
  out_di->set_offset(di.getLow());
  out_di->set_data(di.getData());
  assert(di.getHigh() == di.getLow() + di.getData().length() - 1);
}

static void serialize_argument(SyscallArg *arg,
                               syscall::SyscallArg *out_arg) {
  out_arg->set_addr(arg->addr);

  for (auto it = arg->indata.begin(); it != arg->indata.end(); it++) {
    syscall::DataInterval *di = out_arg->add_indata();
    serialize_interval(*it, di);
  }

  for (auto it = arg->outdata.begin(); it != arg->outdata.end(); it++) {
    syscall::DataInterval *di = out_arg->add_outdata();
    serialize_interval(*it, di);
  }

  syscall::SyscallArg_Direction direction;
  switch (arg->direction) {
  case DirectionIn:
    direction = syscall::SyscallArg::IN;
    break;
  case DirectionOut:
    direction = syscall::SyscallArg::OUT;
    break;
  case DirectionInOut:
    direction = syscall::SyscallArg::INOUT;
    break;
  default:
    assert(false);
    break;
  }

  out_arg->set_direction(direction);
  out_arg->set_offset(arg->offset);

#ifdef CONFIG_QTRACE_TAINT
  for (auto it = arg->taint_labels.begin(); it != arg->taint_labels.end();
       it++) {
    out_arg->add_taintlabels(*it);
  }
#endif

  for (auto it = arg->ptrs.begin(); it != arg->ptrs.end(); it++) {
    syscall::SyscallArg *child = out_arg->add_ptr();
    serialize_argument(*it, child);
  }
}

static void
serialize_external_reference(const std::shared_ptr<ForeignPointer> &ptr,
                             syscall::ExternalReference *out_ref) {
  out_ref->set_pc(ptr->pc);
  out_ref->set_addr(ptr->addr);
  out_ref->set_value(ptr->value);
}

static void serialize_header() {
  syscall::TraceHeader header;
  header.set_magic(syscall::TraceHeader::TRACE_MAGIC);
  header.set_timestamp(time(NULL));

  switch (gbl_context.options.profile) {
#define P(n)                                                            \
    case n:                                                             \
      header.set_targetos(syscall::TraceHeader::n);                     \
      break
    P(ProfileWindowsXPSP0);
    P(ProfileWindowsXPSP1);
    P(ProfileWindowsXPSP2);
    P(ProfileWindowsXPSP3);
    P(ProfileWindows7SP0);
#undef P
  default:
    header.set_targetos(syscall::TraceHeader::ProfileUnknown);
    break;
  }

#ifdef CONFIG_QTRACE_TAINT
  header.set_hastaint(!gbl_context.options.taint_disabled);
#else
  header.set_hastaint(false);
#endif

  unsigned int header_size = header.ByteSize();
  outstream.get()->write(reinterpret_cast<char *>(&header_size),
                         sizeof(header_size));
  header.SerializeToOstream(outstream.get());
}

int serialize_init(void) {
  if (gbl_context.options.filename_trace) {
    outstream = std::unique_ptr<std::fstream>(
        new std::fstream(gbl_context.options.filename_trace,
                         std::ios::out | std::ios::trunc | std::ios::binary));
    serialize_header();
  }

  return 0;
}

void serialize_syscall(const Syscall *syscall) {
  if (!gbl_context.options.filename_trace) {
    // Serialization is disabled
    return;
  }

  syscall::Syscall_Process out_process;
  out_process.set_pid(syscall->pid);
  out_process.set_tid(syscall->tid);
  out_process.set_name(syscall->name);

  syscall::Syscall out_syscall;
  out_syscall.set_id(syscall->id);
  out_syscall.set_sysno(syscall->sysno);
  out_syscall.set_retval(syscall->retval);
  out_syscall.mutable_process()->CopyFrom(out_process);

  for (auto it = syscall->args.begin(); it != syscall->args.end(); it++) {
    syscall::SyscallArg *out_arg = out_syscall.add_arg();
    serialize_argument(*it, out_arg);
  }

  for (auto it = syscall->foreign_ptrs.begin();
       it != syscall->foreign_ptrs.end(); it++) {
    syscall::ExternalReference *ref = out_syscall.add_ref();
    serialize_external_reference(*it, ref);
  }

  unsigned int syscall_size = out_syscall.ByteSize();
  outstream.get()->write(reinterpret_cast<char *>(&syscall_size),
                         sizeof(syscall_size));
  out_syscall.SerializeToOstream(outstream.get());
}
