//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/plugin-systrace/callbacks.h"

#include <cstring>
#include <cstdlib>
#include <cassert>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/trace/process.h"
#include "qtrace/trace/plugin-systrace/memory.h"
#include "qtrace/trace/plugin-systrace/manager.h"
#include "qtrace/trace/plugin-systrace/syscall.h"

// Parameters for memory read operations. These are saved before the operation
// is performed (qtrace_gate_memread_pre()), and used after the memory location
// is accessed (qtrace_gate_memread_post()).
static target_ulong gbl_memread_addr;
static target_ulong gbl_memread_addr_hi;
static target_ulong gbl_memread_pc;
static int gbl_memread_size;

// Check if a size-byte memory access operation (read/write) should be
// analyzed.
static inline bool qtrace_should_process_memaccess(target_ulong cr3, int cpl,
                                                   int size) {
  // FIXME: Skip memory access operations larger than the host system's word
  // size.
  if (sizeof(void *) < size) {
    return false;
  }

  // We are only interested in ring-0 reads
  if (cpl != 0) {
    // FIXME: The CPL check should be redundant, as the QEMU hook notifies only
    // ring-0 memory reads
    return false;
  }

  // Check if we have any pending system call for the current process
  if (!gbl_trace_manager->hasSyscallForProcess(cr3)) {
    return false;
  }

  // ...otherwise, process this memory access operation
  return true;
}

void cb_systrace_syscall_start(target_ulong cr3, target_ulong sysno) {
  RunningProcess running_process(cr3);
  target_ulong stack = gbl_context.guest->getSyscallParamsStack();
  gbl_trace_manager->eventSyscallStart(running_process, sysno, stack);
}

void cb_systrace_syscall_end(target_ulong cr3, target_ulong retval) {
  RunningProcess running_process(cr3);
  gbl_trace_manager->eventSyscallEnd(running_process, retval);
}

void cb_systrace_memread_post(target_ulong cr3, target_ulong pc, int cpl,
                              target_ulong buffer, target_ulong buffer_hi,
                              int size) {
  if (!qtrace_should_process_memaccess(cr3, cpl, size)) {
    return;
  }

  // Sanity checks. The first assertion is false only for 64-bit memory
  // accesses where the target host is a 32-bit system. This combination is
  // currently unsupported.
  assert(gbl_memread_addr_hi == 0 && buffer_hi == 0);
  assert(pc == gbl_memread_pc && size == gbl_memread_size);

  // Analyze only kernel reads to user-space addresses
  if (!gbl_context.guest->isUserAddress(gbl_memread_addr)) {
    return;
  }

  RunningProcess running_process(cr3);
  Syscall *current_syscall =
    gbl_trace_manager->getSyscallForProcess(running_process);

  //
  // Number of this memory-based system call argument.
  //
  // Given a memory address "a" we suppose refers to a level-0 syscall
  // argument, we compute the number of argument "a" as:
  //   [(a - reg_stack_addr) / sizeof(target_ulong)] + n_reg_args
  //
  // Where:
  // - "reg_stack_addr" is the memory address of the first stack argument
  // - "n_reg_args" is the number of syscall arguments passed via CPU registers
  //
  // Both "reg_stack_addr" and "n_reg_args" are determined in a guest-dependent
  // manner using the configured profile.
  //
  const int argno =
    (gbl_memread_addr - current_syscall->stack) / sizeof(target_ulong) +
    gbl_context.guest->getNumSyscallParamsRegister();

  // Start processing first-level arguments
  if (gbl_memread_addr >= current_syscall->stack &&
      gbl_memread_addr <
      (current_syscall->stack + sizeof(target_ulong) * MAX_SYSCALL_ARGS)) {
    // FIXME: this is *not* OS-independent!
    if (argno == 0 && current_syscall->missing_args < 0) {
      current_syscall->missing_args = context_reg_safe(RegisterEcx);
    }
  }

  if (current_syscall->missing_args > 0) {
    if (argno == 0 ||  // First argument?
        (current_syscall->args.size() >
         0 &&             // Do we already have other arguments?
         gbl_memread_addr ==  // Is the current address equal to the address of
                              // the next argument?
         current_syscall->args[current_syscall->args.size() - 1]->addr +
         sizeof(target_ulong))) {
      assert(size == sizeof(target_ulong));
      TRACE("Copying first-level argument #%d (addr: %.8x, cr3: %.8x, "
            "data %.8x)", argno, gbl_memread_addr, cr3, buffer);

      memory_read_level0(current_syscall, gbl_memread_addr, size, buffer);
      current_syscall->missing_args--;
    }
  } else {
    // TODO(roberto): check this is a "candidate" address
    // DEBUG CODE
#if 0
    if ((gbl_memread_addr & 0xf0000000) != 0x80000000) {
      TRACE("Accessing upper-level argument (addr: %.8x, cr3: %.8x, eip: %.8x, "
            "data %.8x)",
            gbl_memread_addr, cr3, pc, buffer);
    }
#endif
    memory_read_levelN(pc, current_syscall, gbl_memread_addr, size, buffer);
  }
}

void cb_systrace_memread_pre(target_ulong pc, target_ulong addr,
                             target_ulong addr_hi, int size) {
  gbl_memread_addr = addr;
  gbl_memread_addr_hi = addr_hi;
  gbl_memread_size = size;
  gbl_memread_pc = pc;
}

void cb_systrace_memwrite_pre(target_ulong cr3, target_ulong pc, int cpl,
                              target_ulong addr, target_ulong addr_hi,
                              target_ulong buffer, target_ulong buffer_hi,
                              int size) {
  if (!qtrace_should_process_memaccess(cr3, cpl, size)) {
    return;
  }

  // Analyze only kernel reads to user-space addresses
  if (!gbl_context.guest->isUserAddress(addr)) {
    return;
  }

  RunningProcess running_process(cr3);
  Syscall *current_syscall =
    gbl_trace_manager->getSyscallForProcess(running_process);

  memory_write(pc, current_syscall, addr, size, buffer);
}
