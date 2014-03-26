//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include "qtrace/taint/notify_taint.h"

#include <cstring>
#include <cstdlib>
#include <cassert>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/taint/taintengine.h"

// Helper function to translate a virtual address into a physical address. We
// distinguish between user- and system emulation, as only the latter includes
// a TLB
static inline hwaddr notify_taint_va2phy(target_ulong addr, int size) {
  hwaddr phyaddr;
#ifndef CONFIG_USER_ONLY
  phyaddr = gbl_context.cb_va2phy(addr);
#else
  phyaddr = addr;
#endif

  return phyaddr;
}

static inline hwaddr notify_taint_isbadphy(hwaddr phyaddr) {
#ifndef CONFIG_USER_ONLY
  return phyaddr == static_cast<hwaddr>(-1);
#else
  return false;
#endif
}

void notify_taint_register(bool istmp, unsigned char regno, int label) {
  gbl_context.taint_engine->setTaintedRegister(label, istmp, regno);
}

void notify_taint_memory(target_ulong addr, unsigned int size, int label) {
  hwaddr phyaddr = notify_taint_va2phy(addr, size);
  if (notify_taint_isbadphy(phyaddr)) {
    WARNING("VA %.8x is invalid, can't taint it", addr);
    return;
  }
  gbl_context.taint_engine->setTaintedMemory(label, phyaddr, size);
}

bool notify_taint_check_memory(target_ulong addr, unsigned int size) {
  hwaddr phyaddr = notify_taint_va2phy(addr, size);
  if (notify_taint_isbadphy(phyaddr)) {
    return false;
  }
  return gbl_context.taint_engine->isTaintedMemory(phyaddr, size);
}

void notify_taint_moveM2R(target_ulong addr, int size,
                          bool istmp, target_ulong reg) {
  hwaddr phyaddr = notify_taint_va2phy(addr, size);
  if (notify_taint_isbadphy(phyaddr)) {
    WARNING("Invalid address (VA: %.8x, PHY: %.8x)", addr, phyaddr);
    return;
  }
  gbl_context.taint_engine->moveM2R(phyaddr, size, istmp, reg);
}

void notify_taint_moveR2M(bool istmp, target_ulong reg,
                          target_ulong addr, int size) {
  hwaddr phyaddr = notify_taint_va2phy(addr, size);
  if (notify_taint_isbadphy(phyaddr)) {
    WARNING("Invalid address (VA: %.8x, PHY: %.8x)", addr, phyaddr);
    return;
  }
  gbl_context.taint_engine->moveR2M(istmp, reg, phyaddr, size);
}

void notify_taint_moveR2R(bool srctmp, target_ulong src,
                          bool dsttmp, target_ulong dst) {
  gbl_context.taint_engine->moveR2R(srctmp, src, dsttmp, dst);
}

void notify_taint_moveR2R_offset(bool srctmp, target_ulong src,
                                 unsigned int srcoff,
                                 bool dsttmp, target_ulong dst,
                                 unsigned int dstoff,
                                 int size) {
  gbl_context.taint_engine->moveR2R(srctmp, src, srcoff,
                                    dsttmp, dst, dstoff,
                                    size);
}

void notify_taint_clearR(bool istmp, target_ulong reg) {
  gbl_context.taint_engine->clearRegister(istmp, reg);
}

void notify_taint_clearM(target_ulong addr, int size) {
  hwaddr phyaddr = notify_taint_va2phy(addr, size);
  if (notify_taint_isbadphy(phyaddr)) {
    return;
  }

  gbl_context.taint_engine->clearMemory(phyaddr, size);
}

void notify_taint_endtb() {
  gbl_context.taint_engine->clearTempRegisters();
}

void notify_taint_regalloc(target_ulong reg, const char *name) {
  gbl_context.taint_engine->setRegisterName(reg, name);
}

void notify_taint_combineR2R(bool srctmp, target_ulong src,
                             bool dsttmp, target_ulong dst) {
  gbl_context.taint_engine->combineR2R(srctmp, src, dsttmp, dst);
}

void notify_taint_assert(target_ulong reg, bool istrue) {
  WARNING("Asserting register %s(%d) IS%s tainted",
          gbl_context.taint_engine->getRegisterName(reg), reg,
          istrue ? "" : " NOT");

  bool b = gbl_context.taint_engine->isTaintedRegister(false, reg, 0);
  assert(istrue ? b : !b);
}

void notify_taint_cpl(target_ulong cr3, target_ulong newcpl) {
  if (!gbl_context.taint_engine->isUserEnabled()) {
    // Taint propagation has been disabled by user
    return;
  }

  if (newcpl == 0) {
    gbl_context.taint_engine->setEnabled(false);
  } else {
    gbl_context.taint_engine->setEnabled(true);
  }

  // Flush TB cache
  gbl_context.cb_tbflush();
}

void notify_taint_set_state(bool state) {
  gbl_context.taint_engine->setUserEnabled(state);
}

bool notify_taint_get_state(void) {
  return gbl_context.taint_engine->isUserEnabled();
}
