//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/taint/taintengine.h"

#include <algorithm>

#include "qtrace/context.h"
#include "qtrace/logging.h"

#define REGCHR(x)    ((x) ? 't' : 'c')
#define REGNAME(obj) \
  ((obj)->getName().length() > 0 ? (obj)->getName().c_str() : "noname")
#define REGTAINT(obj) \
  ((obj)->isTainted() ? 'T' : 'C')

bool qtrace_taint_enabled = false;
bool qtrace_instrument = false;

void TaintEngine::setEnabled(bool status) {
  qtrace_taint_enabled = status;
}

void TaintEngine::setUserEnabled(bool status) {
  taint_user_enabled_ = status;
  if (!status) {
    setEnabled(false);
  }
}

bool TaintEngine::isUserEnabled() {
  return taint_user_enabled_;
}

void TaintEngine::setRegisterName(target_ulong regno, const char *name) {
  ShadowRegister *reg = getRegister(false, regno);
  assert(reg);
  assert(reg->getName().length() == 0);
  reg->setName(name);
}

const char* TaintEngine::getRegisterName(target_ulong regno) {
  ShadowRegister *reg = getRegister(false, regno);
  return REGNAME(reg);
}

bool TaintEngine::getRegisterIdByName(const char *name,
                                      target_ulong &regno) const {
  for (int i = 0; i < NUM_CPU_REGS; i++) {
    if (cpuregs_[i].getName() == name) {
      regno = i;
      return true;
    }
  }
  return false;
}

ShadowRegister* TaintEngine::getRegister(bool istmp, target_ulong reg) {
  assert((istmp && reg < NUM_TMP_REGS) || reg < NUM_CPU_REGS);
  return istmp ? &tmpregs_[reg] : &cpuregs_[reg];
}

void TaintEngine::setTaintedRegister(int label, bool istmp,
                                     target_ulong regno) {
  ShadowRegister *reg = getRegister(istmp, regno);

  TRACE("Tainting register R%c(%.2x %s) with label %.8x",
        REGCHR(istmp), regno, REGNAME(reg), label);

  reg->set(label);
  _updateRegisterCache(istmp, regno, true);
}

bool TaintEngine::isTaintedRegister(bool tmp, target_ulong regno,
                                    unsigned int offset, int size) {
  // Try the fast path first
  if (!isTaintedRegister(tmp, regno)) {
    return false;
  }

  // Fallback on the slow path
  const ShadowRegister *reg = getRegister(tmp, regno);

  if (size == -1) {
    size = reg->getSize();
  }

  for (unsigned int i = offset; i < offset+size; i++) {
    if (reg->isTaintedByte(i)) {
      return true;
    }
  }
  return false;
}

void TaintEngine::setTaintedMemory(int label, target_ulong addr,
                                   unsigned int size) {
  TRACE("Tainting %d bytes at %.8x with label %.8x", size, addr, label);
  for (unsigned int i = 0; i < size; i++) {
    mem_.addLabel(addr+i, label);
  }
}

bool TaintEngine::isTaintedMemory(target_ulong addr, unsigned int size) const {
  for (target_ulong a = addr; a < addr + size; a++) {
    if (mem_.isTaintedAddress(a)) {
      return true;
    }
  }
  return false;
}

void TaintEngine::clearRegister(bool tmp, target_ulong regno) {
  if (!isTaintedRegister(tmp, regno)) {
    // Nothing to do
    return;
  }

  ShadowRegister *reg = getRegister(tmp, regno);
  TRACE("Clearing R%c(%.2x %s)", REGCHR(tmp), regno, REGNAME(reg));
  reg->clear();
  _updateRegisterCache(tmp, regno, false);
}

void TaintEngine::clearMemory(target_ulong addr, int size) {
  mem_.clear(addr, size);
}

void TaintEngine::moveR2R(bool srctmp, target_ulong src,
                          bool dsttmp, target_ulong dst) {
  if (!isTaintedRegister(srctmp, src) && !isTaintedRegister(dsttmp, dst)) {
    // Nothing to do
    return;
  }

  ShadowRegister *dstreg = getRegister(dsttmp, dst);
  ShadowRegister *srcreg = getRegister(srctmp, src);

  TRACE("Taint moving R%c(%.2x %s %c) -> R%c(%.2x %s %c)",
        REGCHR(srctmp), src, REGNAME(srcreg), REGTAINT(srcreg),
        REGCHR(dsttmp), dst, REGNAME(dstreg), REGTAINT(dstreg));

  dstreg->set(*srcreg);
  _updateRegisterCache(dsttmp, dst, dstreg->isTainted());
}

void TaintEngine::moveR2R(bool srctmp, target_ulong src, unsigned int srcoff,
                          bool dsttmp, target_ulong dst, unsigned int dstoff,
                          int size) {
  if (!isTaintedRegister(srctmp, src) && !isTaintedRegister(dsttmp, dst)) {
    // Nothing to do
    return;
  }

  ShadowRegister *dstreg = getRegister(dsttmp, dst);
  ShadowRegister *srcreg = getRegister(srctmp, src);

  for (int i = 0; i < size; i++) {
    TRACE("Taint moving 1 byte R%c(%.2x %s %c @%d) -> R%c(%.2x %s %c @%d)",
          REGCHR(srctmp), src, REGNAME(srcreg), srcoff+i, REGTAINT(srcreg),
          REGCHR(dsttmp), dst, REGNAME(dstreg), dstoff+i, REGTAINT(dstreg));
    dstreg->set(srcreg->getTaintLocation(srcoff + i),
                dstoff + i);
  }

  _updateRegisterCache(dsttmp, dst, dstreg->isTainted());
}

void TaintEngine::combineR2R(bool srctmp, target_ulong src,
                             bool dsttmp, target_ulong dst) {
  if (!isTaintedRegister(srctmp, src)) {
    // Nothing to do
    return;
  }

  ShadowRegister *dstreg = getRegister(dsttmp, dst);
  ShadowRegister *srcreg = getRegister(srctmp, src);

  TRACE("Taint combining R%c(%.2x %s %c) -> R%c(%.2x %s %c)",
        REGCHR(srctmp), src, REGNAME(srcreg), REGTAINT(srcreg),
        REGCHR(dsttmp), dst, REGNAME(dstreg), REGTAINT(dstreg));

  dstreg->combine(*srcreg);
  _updateRegisterCache(dsttmp, dst, dstreg->isTainted());
}

void TaintEngine::moveM2R(target_ulong addr, int size,
                          bool regtmp, target_ulong reg) {
  ShadowRegister *regobj = getRegister(regtmp, reg);

  for (int i = 0; i < std::min(size, regobj->getSize()); i++) {
    if (!mem_.isTaintedAddress(addr + i)) {
      if (regobj->isTaintedByte(i)) {
      TRACE("Clearing M(%.8x) -> R%c(%.2x %s)", addr + i,
            REGCHR(regtmp), reg, REGNAME(regobj));
      regobj->clear(i, 1);
      }
    } else {
      TRACE("Taint moving M(%.8x) -> R%c(%.2x %s)", addr + i,
            REGCHR(regtmp), reg, REGNAME(regobj));
      regobj->set(mem_.getTaintLocation(addr + i));
    }
  }
  _updateRegisterCache(regtmp, reg, regobj->isTainted());
}

void TaintEngine::combineM2R(target_ulong addr, int size,
                             bool regtmp, target_ulong reg) {
  ShadowRegister *regobj = getRegister(regtmp, reg);
  for (int i = 0; i < std::min(size, regobj->getSize()); i++) {
    if (mem_.isTaintedAddress(addr + i)) {
      regobj->combine(mem_.getTaintLocation(addr + i), i);
    }
  }
  _updateRegisterCache(regtmp, reg, regobj->isTainted());
}

void TaintEngine::moveR2M(bool regtmp, target_ulong reg,
                          target_ulong addr, int size) {
  ShadowRegister *regobj = getRegister(regtmp, reg);
  for (int i = 0; i < std::min(size, regobj->getSize()); i++) {
    if (!regobj->isTaintedByte(i)) {
      if (mem_.isTaintedAddress(addr + i)) {
        // Source is not tainted but destination is: clear
        TRACE("Clearing R%c(%.2x %s) -> M(%.8x)",
              REGCHR(regtmp), reg, REGNAME(regobj), addr + i);
        mem_.clear(addr+i);
      }
    } else {
      // Source is tainted: move
      TRACE("Taint moving R%c(%.2x %s) -> M(%.8x)",
              REGCHR(regtmp), reg, REGNAME(regobj), addr + i);
      mem_.set(regobj->getTaintLocation(i), addr+i);
    }
  }
}

void TaintEngine::combineR2M(bool regtmp, target_ulong reg,
                             target_ulong addr, int size) {
  ShadowRegister *regobj = getRegister(regtmp, reg);

  for (int i = 0; i < std::min(size, regobj->getSize()); i++) {
    if (regobj->isTaintedByte(i)) {
      mem_.combine(regobj->getTaintLocation(i), addr+i);
    }
  }
}

void TaintEngine::clearTempRegisters() {
  for (int regno = 0; regno < NUM_TMP_REGS; regno++) {
    if (regcache_tmp_[regno]) {
      tmpregs_[regno].clear();
    }
  }
  regcache_tmp_.reset();
}

void TaintEngine::copyMemoryLabels(std::set<int> &labels,
                                   target_ulong addr, unsigned int size) const {
  for (target_ulong a = addr; a < addr + size; a++) {
    if (mem_.isTaintedAddress(a)) {
      TaintLocation *loc = mem_.getTaintLocation(a);
      loc->copy(labels);
    }
  }
}
