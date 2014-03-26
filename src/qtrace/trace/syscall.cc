//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/trace/syscall.h"

#include <algorithm>
#include <sstream>

#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cassert>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"

Syscall::Syscall(unsigned int param_id, target_ulong param_sysno,
                 target_ulong param_stack, target_ulong param_cr3) :
  is_os_initialized(false), id(param_id), sysno(param_sysno),
  stack(param_stack), cr3(param_cr3), missing_args(-1), is_active(false) { ; }

Syscall::~Syscall() {
  // Delete arguments
  for (auto it = args.begin(); it != args.end(); it++) {
    delete *it;
  }
}

void Syscall::tryOSInitialize(RunningProcess &rp) {
  if (rp.canInitialize()) {
    assert(!is_os_initialized);
    pid = rp.getPid();
    tid = rp.getTid();
    name = rp.getName();
    is_os_initialized = true;
  }
}

void Syscall::addCandidate(SyscallArg *arg, int offset) {
  // Ensure the container argument is large enough to host the pointer
  assert(arg->getSize() >= sizeof(target_ulong));

  target_ulong addr = arg->addr + offset;

  // Avoid duplicated arguments
  if (arg->hasPointer(addr)) {
    return;
  }

  target_ulong value;
  int r = arg->indata.read(offset, sizeof(target_ulong),
                           reinterpret_cast<unsigned char*>(&value));
  if (r != 0) {
    TRACE("Can't read at offset %d from argument @%.8x", offset, arg->addr);
    return;
  }

  TRACE("Adding candidate %.8x (closest %.8x, offset %d, buffer %.8x)",
        addr, arg->addr, offset, value);

  if (!hasCandidate(value)) {
    SyscallPointer *ptr = new SyscallPointer();

    ptr->addr = value;
    ptr->parent = arg;
    ptr->offset = offset;

    candidates_.push_back(std::shared_ptr<SyscallPointer>(ptr));
  }
}

void Syscall::removeCandidate(target_ulong value) {
  std::vector<int> deadptrs;

  // First search for the candidate pointers with the specified value. We store
  // the indices of all these, so we can remove them later
  int i = 0;
  for (auto it = candidates_.begin(); it != candidates_.end(); it++) {
    if ((*it)->addr == value) {
      deadptrs.push_back(i);
    }
    i += 1;
  }

  if (deadptrs.size() > 0) {
    // Start removing the one with the higher index
    for (auto it = deadptrs.rbegin(); it != deadptrs.rend(); it++) {
      candidates_.erase(candidates_.begin() + (*it));
    }
  }
}

void Syscall::actualizeCandidate(target_ulong value, target_ulong data,
                                 int datasize, SyscallDirection direction) {
  // We actualize all the candidate pointers that point to the specified memory
  // location
  for (auto it = candidates_.begin(); it != candidates_.end(); it++) {
    if (it->get()->addr != value) {
      continue;
    }

    SyscallArg *arg = it->get()->parent;
    assert(arg != NULL);

    // Create a new SyscallArg for the new pointer
    SyscallArg *newarg = new SyscallArg();
    assert(newarg != NULL);

    // Initialize the new SyscallArg structure
    newarg->addr = it->get()->addr;
    newarg->offset = it->get()->offset;
    newarg->parent = arg;
    newarg->direction = direction;

    if (datasize > 0) {
      // Add the current data interval to the input intervals set
      std::string datastring(reinterpret_cast<char*>(&data), datasize);
      DataInterval di(0, datasize - 1, datastring);
      newarg->indata.add(di, false);
    }

    // Store the new argument structure inside the parent
    TRACE("Adding a new pointer for arg @%.8x: addr %.8x, offset %d",
          arg->addr, newarg->addr, newarg->offset);
    arg->ptrs.push_back(newarg);
  }

  // Delete all the candidate pointers with the specified value
  removeCandidate(value);
}

SyscallPointer *Syscall::findCandidate(target_ulong value) const {
  for (auto it = candidates_.begin(); it != candidates_.end(); it++) {
    if ((*it)->addr == value) {
      return it->get();
    }
  }
  return NULL;
}

ForeignPointer *Syscall::findForeignCandidate(target_ulong value) const {
  for (auto it = foreign_candidates_.begin();
       it != foreign_candidates_.end(); it++) {
    if (it->get()->value == value) {
      return it->get();
    }
  }
  return NULL;
}

void Syscall::addForeignCandidate(target_ulong addr, target_ulong value,
                                  target_ulong pc) {
  ForeignPointer *ptr = new ForeignPointer(pc, addr, value);
  foreign_candidates_.push_back(std::shared_ptr<ForeignPointer>(ptr));
}

void Syscall::actualizeForeignCandidate(target_ulong value) {
  std::vector<int> to_remove;
  int position = 0;
  for (auto it = foreign_candidates_.begin();
       it != foreign_candidates_.end(); it++, position++) {
    if (it->get()->value != value) {
      continue;
    }

    to_remove.push_back(position);
    foreign_ptrs.push_back(*it);
  }

  for (auto it = to_remove.rbegin(); it != to_remove.rend(); it++) {
    assert(foreign_candidates_[*it]->value == value);
    foreign_candidates_.erase(foreign_candidates_.begin() + (*it));
  }
}

void Syscall::cleanupForeignPointers() {
  std::set<target_ulong> arg_pointers;
  for (auto it = args.begin(); it != args.end(); it++) {
    (*it)->collectPointers(arg_pointers);
  }

  std::set<target_ulong> dead_foreign;
  for (auto itptr = arg_pointers.begin();
       itptr != arg_pointers.end(); itptr++) {
    target_ulong ptraddr = *itptr;
    int position = 0;
    for (auto itforeign = foreign_ptrs.begin();
         itforeign != foreign_ptrs.end();
         itforeign++, position++) {
      if ((*itforeign)->addr == ptraddr) {
        dead_foreign.insert(position);
      }
    }
  }

  for (auto it = dead_foreign.rbegin(); it != dead_foreign.rend(); it++) {
    foreign_ptrs.erase(foreign_ptrs.begin() + (*it));
  }
}

SyscallArg::~SyscallArg() {
  // Free children arguments (TODO: replace with smart pointers)
  for (auto it = ptrs.begin(); it != ptrs.end(); it++) {
    if (*it) {
      delete *it;
      *it = NULL;
    }
  }
}

const char *SyscallArg::directionToString(const SyscallDirection direction) {
  const char *r;

  switch (direction) {
  case DirectionIn:
    r = "IN";
    break;
  case DirectionOut:
    r = "OUT";
    break;
  case DirectionInOut:
    r = "IN/OUT";
    break;
  default:
    r = "UNKNOWN";
    break;
  }

  return r;
}

unsigned int SyscallArg::getSize() const {
  return std::max(indata.getMaxLength(), outdata.getMaxLength());
}

void SyscallArg::collectPointers(std::set<target_ulong> &set_pointers) const {
  // The address where the value of this data pointer is stored should be
  // computer as the address of the parent argument (if any), plus the offset
  // of the current argument within the parent
  if (parent) {
    set_pointers.insert(parent->addr + offset);
  }

  for (auto it = ptrs.begin(); it != ptrs.end(); it++) {
    (*it)->collectPointers(set_pointers);
  }
}

std::shared_ptr<SyscallPointer>
Syscall::findClosestCandidate(target_ulong targetaddr) {
  std::shared_ptr<SyscallPointer> closest_candidate;
  target_ulong min_candidate = 0;

  for (auto it = candidates_.begin(); it != candidates_.end(); it++) {
    if (targetaddr >= (*it)->addr) {
      target_ulong distance = targetaddr - (*it)->addr;
      if (!closest_candidate ||
          (distance < min_candidate && distance < MAX_ARGUMENT_OFFSET)) {
        min_candidate = distance;
        closest_candidate = *it;
      }
    }
  }

  return closest_candidate;
}

SyscallArg* Syscall::findClosestArgument(target_ulong targetaddr) {
  // Start searching closest data pointer first...
  std::shared_ptr<SyscallPointer> closest_candidate =
    findClosestCandidate(targetaddr);

  // ...now search closest syscall argument
  SyscallArg *closest_arg = NULL;
  target_ulong min_distance = 0;

  for (auto itarg = args.begin(); itarg != args.end(); itarg++) {
    SyscallArg *arg = *itarg;

    for (auto itptr = arg->ptrs.begin(); itptr != arg->ptrs.end(); itptr++) {
      SyscallArg *tmp = (*itptr)->findClosestPointer(targetaddr);
      if (tmp == NULL) {
        continue;
      }
      target_ulong distance = targetaddr - tmp->addr;

      TRACE("Checking level-N ptr %.8x against target %.8x (distance %d)",
            tmp->addr, targetaddr, distance);
      if (
          closest_arg == NULL ||
          (tmp->addr <= targetaddr && distance < min_distance)
          ) {
        closest_arg = tmp;
        min_distance = distance;
      }
    }
  }

  // Pick the best (i.e., closest) between candidates and real arguments
  if (closest_candidate &&
      (targetaddr - closest_candidate->addr) < min_distance) {
    target_ulong candidate_addr = closest_candidate->addr;
    TRACE("Candidate %.8x is closer than other arguments (%d vs %d), "
          "actualizing", candidate_addr, targetaddr - closest_candidate->addr,
          min_distance);
    assert(hasCandidate(candidate_addr));
    actualizeCandidate(candidate_addr, 0, 0, DirectionIn);

    assert(closest_candidate->parent != NULL);
    closest_arg = closest_candidate->parent->findClosestPointer(targetaddr);

    assert(closest_arg != NULL);
  }

  // As a last resort, check also level-0 argument values (e.g., data
  // structures directly passed from userspace by reference)
  if (closest_arg == NULL) {
    target_ulong candidate_addr;
    SyscallArg *candidate_parent = NULL;

    for (auto itarg = args.begin(); itarg != args.end(); itarg++) {
      // Skip OUT and IN/OUT arguments and arguments with incorrect size
      if (
          ((*itarg)->direction != DirectionIn) ||
          ((*itarg)->getSize() != sizeof(target_ulong))
          ) {
        continue;
      }

      target_ulong value;
      int r = (*itarg)->indata.read(0, sizeof(target_ulong),
                                    reinterpret_cast<unsigned char*>(&value));
      if (r != 0) {
        continue;
      }

      TRACE("Checking level-0 arg (addr %.8x, value %.8x) against target %.8x",
            (*itarg)->addr, value, targetaddr);

      if (value <= targetaddr) {
        target_ulong distance = targetaddr - value;

        // First check is required to avoid creating spurious arguments in the
        // next "if"
        if (
            (distance < MAX_ARGUMENT_OFFSET)
            &&
            ((candidate_parent == NULL) ||
             (value <= targetaddr && distance < min_distance))
            ) {
          candidate_parent = *itarg;
          candidate_addr = value;
          min_distance = distance;
        }
      }
    }

    // If we found a valid pointer inside a level-0 argument, we must create
    // the corresponding SyscallArgument object by actualizing the candidate
    if (candidate_parent != NULL) {
      assert(hasCandidate(candidate_addr));
      actualizeCandidate(candidate_addr, 0, 0, DirectionIn);
      closest_arg = candidate_parent->findClosestPointer(targetaddr);
    }
  }

  return closest_arg;
}

SyscallArg *SyscallArg::findClosestPointer(target_ulong targetaddr) {
  SyscallArg *closest;
  target_ulong min_distance;

  if (addr <= targetaddr) {
    // Start assuming the closest argument is the current one...
    closest = this;
    min_distance = targetaddr - addr;
  } else {
    closest = NULL;
    min_distance = 0;
  }

  // ...recurse with child pointers
  for (auto it = ptrs.begin(); it != ptrs.end(); it++) {
    SyscallArg *tmp = (*it)->findClosestPointer(targetaddr);

    if (tmp == NULL) {
      continue;
    }

    // Check if the closest child is closer than ourselves
    target_ulong distance = targetaddr - tmp->addr;

    TRACE("Checking level-N2 ptr %.8x against target %.8x (distance %d)",
          tmp->addr, targetaddr, distance);

    if (closest == NULL ||
        (tmp->addr <= targetaddr && distance < min_distance)) {
      closest = tmp;
      min_distance = distance;
    }
  }

  return closest;
}

bool SyscallArg::hasPointer(target_ulong targetaddr) const {
  // Check current argument
  if (parent && ((parent->addr + offset) == targetaddr)) {
    return true;
  }

  // Check child arguments
  bool exists = false;
  for (auto it = ptrs.begin(); it != ptrs.end(); it++) {
    if ((*it)->hasPointer(targetaddr)) {
      exists = true;
      break;
    }
  }

  return exists;
}

bool Syscall::hasPointer(target_ulong targetaddr) const {
  bool exists = false;
  for (auto it = args.begin(); it != args.end(); it++) {
    if ((*it)->hasPointer(targetaddr)) {
      exists = true;
      break;
    }
  }
  return exists;
}

const std::string SyscallArg::to_string(int argno, int indent) const {
  std::ostringstream oss;

  for (int i = 0; i < indent; i++) {
    oss << ' ';
  }

  oss << "[arg #" << argno << "] addr: " << std::hex << addr << std::dec
      << ", direction? " << SyscallArg::directionToString(direction)
      << ", offset: " << offset << ", size: " << getSize()
      << ", ptrs: " << ptrs.size()
      << ", labels: " << taint_labels.size();

  int i = 0;
  for (auto it = ptrs.begin(); it != ptrs.end(); it++) {
    oss << std::endl << (*it)->to_string(i, indent + 1);
    i += 1;
  }

  return oss.str();
}

const std::string Syscall::to_string() const {
  std::ostringstream oss;

  oss << "Syscall " << gbl_context.windows->getSyscallName(sysno)
      << "(0x" << std::hex << sysno << "), "
      << "proc " << cr3 << " retval " << retval
      << ", " << std::dec << args.size() << " arguments";

  int i = 0;
  for (auto it = args.begin(); it != args.end(); it++) {
    oss << std::endl << (*it)->to_string(i, 1);
    i += 1;
  }

  return oss.str();
}
