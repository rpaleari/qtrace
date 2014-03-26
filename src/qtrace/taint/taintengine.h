//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_TAINT_TAINTENGINE_H_
#define SRC_QTRACE_TAINT_TAINTENGINE_H_

#include <cassert>
#include <bitset>
#include <set>
#include <memory>

#include "qtrace/taint/shadow.h"

const int NUM_CPU_REGS = 16;
const int NUM_TMP_REGS = 512;

//
// The TaintEngine class implements the logic of the taint engine.
//
// The TaintEngine basically wraps a ShadowMemory object and multiple
// ShadowRegister instances, exposing APIs to set, clear and propagate taint
// information.
//
class TaintEngine {
 public:
  explicit TaintEngine() : taint_user_enabled_(true) {}

  // Enable/disable the taint propagation engine
  void setEnabled(bool status);

  // Set the "global" status of the taint propagation engine. This is different
  // from setEnabled(): the former is used to selectively enable/disable
  // taint-tracking during execution (e.g., enable only in ring-0), while the
  // latter lets the user to permanently disable the taint-tracking module
  void setUserEnabled(bool status);

  // Retrieve the current status of the taint propagation engine, as set by the
  // user
  bool isUserEnabled();

  // Registers names
  void setRegisterName(target_ulong reg, const char *name);
  const char* getRegisterName(target_ulong regno);
  bool getRegisterIdByName(const char *name, target_ulong &regno) const;

  // Add taint labels
  void setTaintedMemory(int label, target_ulong addr, unsigned int size);
  void setTaintedRegister(int label, bool istmp, target_ulong reg);

  // Copy taint labels to the provided set
  void copyMemoryLabels(std::set<int> &labels,
                        target_ulong addr, unsigned int size = 1) const;

  // Check taintedness
  bool isTaintedMemory(target_ulong addr, unsigned int size = 1) const;
  bool isTaintedRegister(bool tmp, target_ulong regno, unsigned int offset,
                         int size = -1);

  inline bool isTaintedRegister(bool istmp, target_ulong regno) const {
    return istmp ? regcache_tmp_[regno] : regcache_cpu_[regno];
  }

  inline bool hasRegisterLabel(bool tmp, target_ulong reg, int label) {
    return getRegister(tmp, reg)->hasLabel(label);
  }

  inline bool hasMemoryLabel(target_ulong addr, int label) {
    return mem_.hasLabel(addr, label);
  }

  // Clear temporary registers (e.g., at the end of a BB)
  void clearTempRegisters();

  // Untaint register (e.g., for immediate assignment operations)
  void clearRegister(bool tmp, target_ulong reg);

  // Clear a memory region
  void clearMemory(target_ulong addr, int size = 1);

  // Register and memory assignment (move) operations
  void moveR2R(bool srctmp, target_ulong src, bool dsttmp, target_ulong dst);
  void moveR2M(bool regtmp, target_ulong reg, target_ulong addr, int size);
  void moveM2R(target_ulong addr, int size, bool regtmp, target_ulong reg);

  // Register assignment, with offset (e.g., mov dl, ah)
  void moveR2R(bool srctmp, target_ulong src, unsigned int srcoff,
               bool dsttmp, target_ulong dst, unsigned int dstoff,
               int size);

  // Register and memory combinations (OR) operations
  void combineR2R(bool srctmp, target_ulong src,
                  bool dsttmp, target_ulong dst);
  void combineR2M(bool regtmp, target_ulong reg, target_ulong addr, int size);
  void combineM2R(target_ulong addr, int size, bool regtmp, target_ulong reg);

 private:
  // Caches used to efficiently check if a register is tainted
  std::bitset<NUM_CPU_REGS> regcache_cpu_;
  std::bitset<NUM_TMP_REGS> regcache_tmp_;

  // User-controlled status
  bool taint_user_enabled_;

  // Shadow registers and memory
  ShadowRegister cpuregs_[NUM_CPU_REGS];
  ShadowRegister tmpregs_[NUM_TMP_REGS];
  ShadowMemory mem_;

  ShadowRegister* getRegister(bool istmp, target_ulong reg);

  inline void _updateRegisterCache(bool istmp, target_ulong regno,
                                   bool tainted) {
    if (istmp) {
      regcache_tmp_[regno] = tainted;
    } else {
      regcache_cpu_[regno] = tainted;
    }
  }
};

#endif  // SRC_QTRACE_TAINT_TAINTENGINE_H_
