//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/taint/shadow.h"

#include <algorithm>
#include <cassert>

void ShadowRegister::set(const ShadowRegister &other) {
  for (int i = 0; i < std::min(size_, other.size_); i++) {
    reg_[i].set(other.reg_[i]);
  }
}

void ShadowRegister::combine(const ShadowRegister &other) {
  for (int i = 0; i < std::min(size_, other.size_); i++) {
    reg_[i].combine(other.reg_[i]);
  }
}

void ShadowRegister::combine(const TaintLocation *loc, int offset) {
  assert(offset < size_);
  reg_[offset].combine(*loc);
}

void ShadowRegister::set(const TaintLocation *loc, int offset) {
  assert(offset < size_);
  reg_[offset].set(*loc);
}

bool ShadowRegister::isTainted() const {
  for (int i = 0; i < size_; i++) {
    if (reg_[i].isTainted()) {
      return true;
    }
  }

  return false;
}

bool ShadowRegister::isTaintedByte(unsigned int offset) const {
  assert(offset < size_);
  return reg_[offset].isTainted();
}

bool ShadowRegister::hasLabel(int label) const {
  for (int i = 0; i < size_; i++) {
    if (reg_[i].hasLabel(label)) {
      return true;
    }
  }
  return false;
}

void ShadowMemory::set(const TaintLocation *loc, target_ulong addr) {
  if (mem_.find(addr) == mem_.end()) {
    mem_[addr] = std::shared_ptr<TaintLocation>(new TaintLocation);
  }

  mem_[addr]->set(*loc);
}

void ShadowMemory::clear(target_ulong addr, unsigned int size) {
  for (unsigned int i = 0; i < size; i++) {
    if (mem_.find(addr+i) != mem_.end()) {
      mem_.erase(addr+i);
    }
  }
}

void ShadowMemory::combine(const TaintLocation *loc, target_ulong addr) {
  if (mem_.find(addr) == mem_.end()) {
    mem_[addr] = std::shared_ptr<TaintLocation>(new TaintLocation);
  }

  mem_[addr]->combine(*loc);
}
