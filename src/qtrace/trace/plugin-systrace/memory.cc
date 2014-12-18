//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/plugin-systrace/memory.h"

#include <string>

#include <cstring>
#include <cstdlib>
#include <cassert>
#include <vector>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/trace/intervals.h"
#include "qtrace/trace/plugin-systrace/manager.h"
#include "qtrace/trace/plugin-systrace/syscall.h"

static void memory_process_access(target_ulong pc,
                                  Syscall *syscall,
                                  target_ulong addr, int size,
                                  target_ulong buffer,
                                  SyscallDirection direction);

static inline bool memory_check_probing(SyscallDirection direction,
                                        target_ulong offset, int size,
                                        target_ulong buffer, SyscallArg *arg);

static void check_repeated_accesses(target_ulong pc, target_ulong addr,
                                    int size, target_ulong buffer,
                                    SyscallDirection direction,
                                    SyscallArg *nearest);


// Check for repeated memory accesses during the execution of the very same
// location. Parameters "pc", "addr", "size", "buffer" and "direction"
// characterize the current memory access operation, while "nearest" is the
// nearest syscall argument laready observed for the current system call.
static void check_repeated_accesses(target_ulong pc, target_ulong addr,
                                    int size, target_ulong buffer,
                                    SyscallDirection direction,
                                    SyscallArg *nearest) {
  assert(direction == DirectionIn && addr >= nearest->addr);

  for (int offset = 0; offset < size; offset++) {
    unsigned char value;
    int r = nearest->indata.read((addr - nearest->addr) + offset, 1, &value);
    if (r != 0) {
      // No rep access on IN data (read vs read), try with OUT (write vs read)
      r = nearest->outdata.read((addr - nearest->addr) + offset, 1, &value);
    }

    if (r == 0) {
      DEBUG("Repeated memory access to address 0x%lx (value 0x%02x) @0x%lx",
	    addr+offset, value, pc);

      // Inspect call stack
      std::vector<target_ulong> call_stack;

      call_stack.push_back(pc);
      gbl_context.guest->getStackTrace(call_stack, 5);

      unsigned int i = 0;
      for (auto it = call_stack.begin(); it != call_stack.end(); it++, i++) {
        if (!gbl_context.guest->isKernelAddress(*it)) {
          break;
        }
        DEBUG("Call stack entry #%d: %016llx", i, *it);
      }

      call_stack.erase(call_stack.begin() + i, call_stack.end());
      nearest->addRepeatedAccess(addr+offset, value, 1, direction, call_stack);
    }
  }
}

void memory_read_level0(Syscall *syscall, target_ulong addr, int size,
                        target_ulong buffer) {
  SyscallArg *arg = new SyscallArg();

  // Create the new argument object
  arg->addr = addr;
  arg->direction = DirectionIn;

  // Copy the data buffer
  std::string datastring(reinterpret_cast<char*>(&buffer), size);
  DataInterval di(0, size - 1, datastring);
  arg->indata.add(di, false);

  // Store this argument
  syscall->addArgument(arg);

  // Record this argument as a candidate data pointer
  if (gbl_context.guest->isUserPointer(buffer, size)) {
    TRACE("Adding 0-level candidate %.8lx (closest %.8lx, off %d, buf %.8lx)",
          addr, arg->addr, 0, buffer);
    syscall->addCandidate(arg, 0);
  }
}

// When we detect a memory output operation for a region that was also read
// before, we must check for memory probing attempts by the kernel (e.g.,
// accesses due to a ProbeForWrite(), on Windows); in these cases we could
// incorrectly assume the location is "IN/OUT". We detect these situations by
// comparing the "output" data buffer with the "input" one: if they match, we
// simply ignore this write operation.
static inline bool memory_check_probing(SyscallDirection direction,
                                        target_ulong offset, int size,
                                        target_ulong buffer, SyscallArg *arg) {
  bool isprobing = false;

  if (direction == DirectionOut &&
      arg->indata.getNumDataIntervals() == 1) {
    // Get the data region that was previously read
    unsigned char *olddata = new unsigned char[size];
    int err = arg->indata.read(offset, size, olddata);
    if (err == 0 && !memcmp(olddata, &buffer, size)) {
      TRACE("Found output buffer matching input @%.8lx, assuming "
            "kernel is probing memory",
            arg->addr + offset);
      isprobing = true;
    }
    delete[] olddata;
  }

  return isprobing;
}

// Process a @size-byte memory access at address @addr. @buffer holds the data
// that has been read or that is going to be written, while @is_input indicates
// if this is a "read" (true) or "write" operation.
static void memory_process_access(target_ulong pc,
                                  Syscall *syscall,
                                  target_ulong addr, int size,
                                  target_ulong buffer,
                                  SyscallDirection direction) {
  // DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG
  // Do we need this check????? Why?????
  bool is_pointer = gbl_context.guest->isUserPointer(buffer, size);
  // DEBUG DEBUG DEBUG DEBUG DEBUG DEBUG

  // Actualize candidate pointers: if this memory access reads from a location
  // that was previously inserted inside the candidate pointers list, then
  // assume this address corresponds to a true user-space data pointer.
  bool is_actualized = false;
  if (syscall->hasCandidate(addr)) {
    DEBUG("Actualizing (%s) user-space pointer at %.8lx, size %d, buffer %.8lx",
          SyscallArg::directionToString(direction), addr, size, buffer);
    syscall->actualizeCandidate(addr, buffer, size, direction);
    is_actualized = true;
  } else if (gbl_trace_manager->isForeignEnabled() &&
             syscall->hasForeignCandidate(addr)) {
    DEBUG("Actualizing foreign user-space pointer at %.8lx, size %d",
          addr, size);
    syscall->actualizeForeignCandidate(addr);
    is_actualized = true;
  }

  // Process arguments access: we now have to store the contents of system call
  // arguments. The tricky part here is to ascertain the memory address we are
  // accessing really belongs to a syscall argument.
  if (gbl_context.guest->isUserPointer(addr, sizeof(addr))) {
    SyscallArg *nearest;

    nearest = syscall->findClosestArgument(addr);
    TRACE("Accessing (%s) memory at %.8lx, size %d, buf %.8lx",
          SyscallArg::directionToString(direction), addr, size, buffer);

    // Set to "true" if address "addr" is detected as a candidate syscall
    // data pointer
    bool is_syscall_candidate = false;

    if (nearest != NULL) {
      assert(addr >= nearest->addr);
      target_ulong offset = addr - nearest->addr;

      // FIXME: We need to make an educated guess to determine if an address
      // being read from user-space belongs to an existing syscall argument.
      //
      // The current check (i.e., the offset is not too big) is quite bad
      // (hack).
      if (offset < MAX_ARGUMENT_OFFSET) {
        TRACE(" -> nearest %.8lx, offset: %d", nearest->addr, offset);

        // Track repeated memory accesses to the same location
        if (unlikely(gbl_trace_manager->isRepEnabled()) &&
            direction == DirectionIn && !is_actualized) {
          check_repeated_accesses(pc, addr, size, buffer, direction, nearest);
        }

        // Update the data buffer of the nearest argument, storing the pointer
        // at the specifier offset
        std::string datastring(reinterpret_cast<char*>(&buffer), size);
        DataInterval di(offset, offset + size - 1, datastring);

        assert(direction == DirectionIn || direction == DirectionOut);
        if (direction == DirectionIn) {
          nearest->indata.add(di, false);
        } else if (direction == DirectionOut) {
          nearest->outdata.add(di, true);
        }

        // Update the argument direction
        if (nearest->direction != direction) {
          // Check if this write access is due to a memory probing attempt
          // (i.e., writing the same data that was reade before)
          bool isprobing =
            memory_check_probing(direction, offset, size, buffer, nearest);

          if (isprobing) {
            assert(nearest->indata.getNumDataIntervals() == 1);
            nearest->indata.flush();
            nearest->direction = DirectionOut;
          } else {
            nearest->direction = DirectionInOut;
          }
        }

        // Record this argument as a candidate data pointer
        if (is_pointer) {
          is_syscall_candidate = true;
          syscall->addCandidate(nearest, offset);
        }
      }
    }

    // If this is not a candidate syscall data pointer, then use it as a
    // "foreign" data pointer
    if (gbl_trace_manager->isForeignEnabled() && !is_syscall_candidate) {
      TRACE("Adding foreign candidate %.8lx (val %.8lx, pc %.8lx)",
            addr, buffer, pc);
      syscall->addForeignCandidate(addr, buffer, pc);
    }
  }
}

void memory_read_levelN(target_ulong pc, Syscall *syscall, target_ulong addr,
                        int size, target_ulong buffer) {
  memory_process_access(pc, syscall, addr, size, buffer, DirectionIn);
}

void memory_write(target_ulong pc, Syscall *syscall, target_ulong addr,
                  int size, target_ulong buffer) {
  memory_process_access(pc, syscall, addr, size, buffer, DirectionOut);
}
