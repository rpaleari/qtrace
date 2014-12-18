//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TAINT_SHADOW_H_
#define SRC_QTRACE_TAINT_SHADOW_H_

#include <algorithm>
#include <memory>
#include <set>
#include <string>
#include <unordered_map>

#include "qtrace/common.h"

//
// An instance of the TaintLocation class represents a tainted memory location
// or CPU register.
//
// Each instance of this class represents a single tainted byte. Tainted
// locations are characterized with one or more "taint labels", usually
// associated with specific input (or "source") bytes.
//
class TaintLocation {
 public:
  explicit TaintLocation() {}

  // Assign (move) two tainted locations
  void set(const TaintLocation &src) {
    labels_ = src.labels_;
  }

  // Combine two tainted locations
  void combine(const TaintLocation &src) {
    labels_.insert(src.labels_.begin(), src.labels_.end());
  }

  // Copy taint labels to an output set
  void copy(std::set<int> &out) const {
    out.insert(labels_.begin(), labels_.end());
  }

  // Add a taint label to this tainted location
  inline void addLabel(int label) {
    labels_.insert(label);
  }

  // Check if this location has a specific taint label
  inline bool hasLabel(int label) const {
    return labels_.find(label) != labels_.end();
  }

  // Check if this location is tainted
  inline bool isTainted() const {
    return labels_.size() > 0;
  }

  // Remove all taint labels
  inline void clear() {
    labels_.clear();
  }

 private:
  std::set<int> labels_;
};


//
// ShadowMemory class is used to represent the taint status for the emulated
// memory.
//
typedef std::unordered_map<target_ulong,
                           std::shared_ptr<TaintLocation> > shadowmemory_t;
class ShadowMemory {
 public:
  explicit ShadowMemory() {}

  // Add a taint label to at the specified memory address
  void addLabel(target_ulong addr, int label) {
    if (mem_.find(addr) == mem_.end()) {
      mem_[addr] = std::shared_ptr<TaintLocation>(new TaintLocation);
    }

    mem_[addr]->addLabel(label);
  }

  // Taint propagation primitives
  void set(const TaintLocation *loc, target_ulong addr);
  void clear(target_ulong addr, unsigned int size = 1);

  // Check if a memory address is tainted
  inline bool isTaintedAddress(target_ulong addr) const {
    return mem_.find(addr) != mem_.end() && mem_.at(addr)->isTainted();
  }

  // Check if a memory address has a taint label
  inline bool hasLabel(target_ulong addr, int label) const {
    return mem_.find(addr) != mem_.end() && mem_.at(addr)->hasLabel(label);
  }

  void combine(const TaintLocation *loc, target_ulong addr);

  // Get the taint status of a (tainted) memory address
  inline TaintLocation* getTaintLocation(target_ulong addr) const {
    return mem_.at(addr).get();
  }

 private:
  shadowmemory_t mem_;
};


//
// The ShadowRegister class represents the tainted status of a CPU register.
//
class ShadowRegister {
 public:
  // Initialize a tainted register, given its size (in bytes)
  explicit ShadowRegister(unsigned int size = sizeof(target_ulong))
    : size_(size) {
    reg_  = new TaintLocation[size];
  }

  ~ShadowRegister() {
    delete[] reg_;
  }

  // Assign a shadow register, copying the taint information from the source to
  // the destination (this) operand
  void set(const ShadowRegister &other);
  void set(const TaintLocation *loc, int offset);

  // Add a taint label
  inline void set(unsigned int label, unsigned int start = 0,
                  int size = -1) {
    if (size == -1) {
      size = size_;
    }

    for (unsigned int i = start; i < (start + size); i++) {
      reg_[i].addLabel(label);
    }
  }

  // Copy taint information
  inline void set(const TaintLocation* loc, unsigned int offset = 0) {
    reg_[offset].set(*loc);
  }

  // Clear taint information
  void clear(unsigned int offset = 0, int size = -1) {
    if (size == -1) {
      size = size_ - offset;
    }

    for (unsigned int i = offset; i < (offset + size); i++) {
      reg_[i].clear();
    }
  }

  // Combine taint information from the source and the destination (this)
  // operand
  void combine(const ShadowRegister &other);
  void combine(const TaintLocation *loc, int offset);

  // Get the size of this register
  inline int getSize() const {
    return size_;
  }

  // Check if this register is tainted
  bool isTainted() const;
  bool isTaintedByte(unsigned int offset) const;

  // Get the taint status of a (tainted) CPU register
  inline TaintLocation* getTaintLocation(unsigned int offset)
    const {
    return &reg_[offset];
  }

  // Check if this shadow register has the specified taint label
  bool hasLabel(int label) const;

  // Set register name
  void setName(const std::string newname) {
    name_ = newname;
  }

  // Get register name
  const std::string getName() const {
    return name_;
  }

 private:
  int size_;
  TaintLocation *reg_;
  std::string name_;
};

#endif  // SRC_QTRACE_TAINT_SHADOW_H_
