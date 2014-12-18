//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_SYSCALL_H_
#define SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_SYSCALL_H_

#include <cstdbool>
#include <memory>
#include <set>
#include <string>
#include <vector>
#include <map>

#include "qtrace/common.h"
#include "qtrace/trace/intervals.h"
#include "qtrace/trace/process.h"

// Maximum number of first-level arguments for a system call
const target_ulong MAX_SYSCALL_ARGS = 64;

class SyscallArg;

// Possible directions of a system call argument
typedef enum {
  DirectionIn = 0,
  DirectionOut,
  DirectionInOut,
} SyscallDirection;

// A SyscallPointer object represents a data pointer inside a syscall
// argument data buffer (or inside the data buffer within another
// SyscallPointer object). Attributes are defined as:
// - parent: the parent SyscallArg object (must not be NULL).
// - offset: the offset of this pointer within the parent data buffer.
// - addr:   address of this pointer (redundant, replicated in the parent).
class SyscallPointer {
 public:
  explicit SyscallPointer() : parent(NULL) {}
  ~SyscallPointer() {}

  SyscallArg *parent;
  int offset;
  target_ulong addr;
};

// A ForeignPointer object represents a data pointer outside any syscall
// argument. Attributes are defined as:
// - pc:     program counter of the first referer instruction
// - addr:   address of this pointer
// - value:  value of this pointer
class ForeignPointer {
 public:
  explicit ForeignPointer(target_ulong pc, target_ulong addr,
			  target_ulong value) :
  pc(pc), addr(addr), value(value) {}
  ~ForeignPointer() {}

  target_ulong pc;
  target_ulong addr;
  target_ulong value;
};

// A MemoryAccess represents a memory access operation, characterized by the
// following attributes:
// - addr:      base address of the memory location involved.
// - pc:        program counter when the memory access operation was performed.
// - size:      size of the accessed memory location.
// - direction: direction of the operation (IN, OUT or IN/OUT).

class MemoryAccess {
 public:
  explicit MemoryAccess(target_ulong addr, int size, SyscallDirection direction)
    : addr(addr), size(size), direction(direction) {}
  ~MemoryAccess() {}

  target_ulong addr;
  std::vector<target_ulong> call_stack;
  int size;
  SyscallDirection direction;
};

// A SyscallArg object represents a level-0 or a higher level argument of a
// system call. This class has the following member fields:
// - addr:   address of this argument.
// - indata: data intervals read from input argument.
// - outdata: data intervals wrote to output argument.
// - direction: argument direction (in/out/inout).
// - ptrs:   data pointers embedded in this argument.
// - nptrs:  number of pointer objects.
// - parent: the parent SyscallArg object, or NULL for level-0 arguments.
// - offset: offset of the pointer to this argument inside the parent.

class SyscallArg {
 private:
  // Repeated memory accesses are stored as a vector of MemoryAccess objects
  typedef std::vector<std::shared_ptr<MemoryAccess> > RepAccesses;
  RepAccesses rep_accesses_;

 public:
  explicit SyscallArg() : parent(NULL), offset(0) {}
  ~SyscallArg();

  target_ulong addr;

  DataIntervalSet indata, outdata;
  SyscallDirection direction;

  std::vector<SyscallArg *> ptrs;

  SyscallArg *parent;
  int offset;

  typedef RepAccesses::const_iterator ConstMemoryAccessIt;

  // Return a read-only iterator that points to the first in the repeated
  // memory accesses vector
  ConstMemoryAccessIt rep_accesses_begin() const {
    return rep_accesses_.begin();
  }

  // Return a read-only iterator that points one past the last in the repeated
  // memory accesses vector
  ConstMemoryAccessIt rep_accesses_end() const {
    return rep_accesses_.end();
  }

  // Translate a SyscallDirection enum value to string
  static const char *directionToString(const SyscallDirection direction);

  // Get the current size of this syscall argument (in bytes). Size of a system
  // call argument is defined as the maximum size of input and output data
  // buffers
  unsigned int getSize() const;

  // Collect pointer values referred by this argument
  void collectPointers(std::set<target_ulong> &set_pointers) const;

  // Find data pointer closest to the specified address
  SyscallArg *findClosestPointer(target_ulong targetaddr);

  // Check if this argument has a pointer to the specified address
  bool hasPointer(target_ulong addr) const;

  // Add a repeated memory access
  void addRepeatedAccess(target_ulong addr, target_ulong value, int size,
			 SyscallDirection direction,
			 const std::vector<target_ulong> call_stack);

  // String conversion
  const std::string to_string(int argno, int indent) const;

#ifdef CONFIG_QTRACE_TAINT
  // Taint labels used (in) and defined (out) by this argument
  std::set<int> taint_labels_in, taint_labels_out;
#endif
};

// A Syscall object represents a single system call. The object has the
// following fields:
// - id:        unique system call identifier.
// - sysno:     syscall number.
// - stack:     value of the stack pointer just before the transition to ring-0.
// - cr3:       identifier of the process that issues this syscall (CR3 value).
// - pid:       ID of the process that issues this syscall.
// - tid:       ID of the thread that issues this syscall.
// - name:      ASCII name of the process that issues this syscall.
// - retval     system call return value; this field is valid only after system
//              call termination (e.g., at sysexit).
// - is_active: set to "true" if the system call is active.
// - args:      system call arguments.
// - candidates:   candidate data pointers.
// - rep_accesses: repeated memory accesses.
//
// The "candidates" field stores candidate data pointer, identified as part of
// a specific system call argument. These pointers are just "candidates": we
// speculate these data values represent valid memory addresses, but this
// hypothesis must still be confirmed by observing whether the system accesses
// these memory locations.

class Syscall {
 private:
  // Track if OS-dependent initialization has been performed
  bool is_os_initialized;

  // Find a candidate syscall/foreign data pointer, given its value (memory
  // address)
  SyscallPointer *findCandidate(target_ulong value) const;
  ForeignPointer *findForeignCandidate(target_ulong value) const;

  // Find candidate data pointer closest to the given target address
  std::shared_ptr<SyscallPointer> findClosestCandidate(target_ulong targetaddr);

  // Candidate syscall data pointers
  std::vector<std::shared_ptr<SyscallPointer> > candidates_;

  // Candidate foreign data pointers (i.e., *not* associated with syscall
  // arguments)
  std::vector<std::shared_ptr<ForeignPointer> > foreign_candidates_;

 public:
  explicit Syscall(unsigned int param_id, target_ulong param_sysno,
		   target_ulong param_stack, target_ulong param_cr3);
  ~Syscall();

  // Add a (first-level) syscall argument
  void addArgument(SyscallArg *arg) {
    args.push_back(arg);
  }

  // Check if OS-dependent fields have been already initialized
  inline bool isOSInitialized() const {
    return is_os_initialized;
  }

  // Perform the initialization of OS-dependent part of this syscall, using
  // information provided by the supplied RunningProcess object
  void tryOSInitialize(RunningProcess &rp);

  // Check if any of the arguments of this system call has a pointer to the
  // specified memory address
  bool hasPointer(target_ulong addr) const;

  // Check if a given address (@value) is already registered as a candidate
  // pointer
  bool hasCandidate(target_ulong value) const {
    return findCandidate(value) != NULL;
  }

  // Add a candidate data pointer. @arg is the parent argument and @offset is
  // the offset of the candidate pointer inside the parent data buffer
  void addCandidate(SyscallArg *arg, int offset);

  // Delete all the candidate pointers with the specified value
  void removeCandidate(target_ulong value);

  // Make a candidate data pointer concrete
  void actualizeCandidate(target_ulong value, target_ulong data, int datasize,
			  SyscallDirection direction);

  // Find argument closest to the given data address
  SyscallArg *findClosestArgument(target_ulong addr);

  // Check if @addr is a foreign data pointer
  bool hasForeignCandidate(target_ulong value) const {
    return findForeignCandidate(value) != NULL;
  }

  // Add the address of a foreign data pointer
  void addForeignCandidate(target_ulong addr, target_ulong value,
			   target_ulong pc);

  // Actualize the candidate foreign data pointer @addr
  void actualizeForeignCandidate(target_ulong value);

  // Remove argument data pointers from foreign data pointers
  void cleanupForeignPointers();

  // Syscall arguments
  std::vector<SyscallArg *> args;

  // Confirmed foreign data pointers
  std::vector<std::shared_ptr<ForeignPointer> > foreign_ptrs;

  const unsigned int id;
  const target_ulong sysno;
  const target_ulong stack;
  const target_ulong cr3;
  int missing_args;
  target_ulong retval;
  bool is_active;

  // OS-dependent attributes
  target_ulong pid;
  target_ulong tid;
  std::string  name;

#ifdef CONFIG_QTRACE_TAINT
  // Taint label associated with the syscall return value
  int taint_label_retval;
#endif

  // Convert a Syscall object to string, including its arguments
  const std::string to_string() const;
};

#endif  // SRC_QTRACE_TRACE_PLUGIN_SYSTRACE_SYSCALL_H_
