//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/plugin-systrace/serialize.h"

#include <fstream>
#include <iostream>
#include <memory>
#include <cstdio>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/trace/intervals.h"
#include "qtrace/trace/plugin-systrace/syscall.h"
#include "qtrace/trace/plugin-systrace/pb/syscall.pb.h"

// Output file stream for serialized system calls
static std::unique_ptr<std::fstream> outstream;

// Translate a SyscallDirection value into a syscall::SyscallArg_Direction
// value (i.e., from syscall.h to protobuf)
static syscall::SyscallArg_Direction translate_direction(SyscallDirection dir) {
  syscall::SyscallArg_Direction r;
  switch (dir) {
  case DirectionIn:
    r = syscall::SyscallArg::IN;
    break;
  case DirectionOut:
    r = syscall::SyscallArg::OUT;
    break;
  case DirectionInOut:
    r = syscall::SyscallArg::INOUT;
    break;
  default:
    assert(false);
    break;
  }
  return r;
}

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

  out_arg->set_direction(translate_direction(arg->direction));
  out_arg->set_offset(arg->offset);

#ifdef CONFIG_QTRACE_TAINT
  for (auto it = arg->taint_labels_in.begin();
       it != arg->taint_labels_in.end();
       it++) {
    out_arg->add_taintlabels_in(*it);
  }

  for (auto it = arg->taint_labels_out.begin();
       it != arg->taint_labels_out.end();
       it++) {
    out_arg->add_taintlabels_out(*it);
  }
#endif

  // Serialize repeated memory accesses
  for (auto it = arg->rep_accesses_begin(); it != arg->rep_accesses_end();
       it++) {
    syscall::SyscallArg::MemoryAccess *mem_access = out_arg->add_rep_read();

    for (auto it_pc = (*it)->call_stack.begin(); it_pc != (*it)->call_stack.end();
	 it_pc++) {
      mem_access->add_pc(*it_pc);
    }

    mem_access->set_addr((*it)->addr);
    mem_access->set_size((*it)->size);
    mem_access->set_direction(translate_direction((*it)->direction));
  }

  // Process sub-arguments
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

#define FOO(popt, pclass, pname)                                        \
    case Profile ## pclass:                                             \
      header.set_targetos(syscall::TraceHeader::Profile ## pclass);     \
      break;
#include "profiles/profiles.h"
#undef FOO

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

#ifdef CONFIG_QTRACE_TAINT
  out_syscall.set_taintlabel_retval(syscall->taint_label_retval);
#endif

  unsigned int syscall_size = out_syscall.ByteSize();
  outstream.get()->write(reinterpret_cast<char *>(&syscall_size),
                         sizeof(syscall_size));
  out_syscall.SerializeToOstream(outstream.get());
}
