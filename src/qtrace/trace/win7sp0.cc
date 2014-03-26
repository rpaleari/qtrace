//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#include <cassert>
#include <cstring>
#include <memory>

#include "qtrace/context.h"
#include "qtrace/trace/win7sp0.h"
#include "qtrace/trace/win7sp0_symbols.h"
#include "qtrace/trace/win7sp0_syscalls.h"

Windows7SP0::Windows7SP0()
  : Windows(syscalls_Windows7SP0,
            sizeof(syscalls_Windows7SP0) / sizeof(char *)) {
}

bool Windows7SP0::isUserAddress(target_ulong addr) const {
  return (addr < MMUserProbeAddress);
}

#define CHECK(v)                                \
  if ((v) != 0) {                               \
    return (v);                                 \
  }

#define READADDR(name, addr)                                            \
  target_ulong name;                                                    \
  r = gbl_context.cb_peek((addr), reinterpret_cast<unsigned char *>(&name), \
                          sizeof(name));				\
  if (r != 0) { return r; }

int Windows7SP0::getProcessData(uint32_t &pid, uint32_t &tid,
                                std::string &name) {
  target_ulong kpcr = getKPCR();

  // Read the address of ETHREAD and EPROCESS kernel objects
  int r;

  READADDR(ethread,
           kpcr + OffsetKPCR_PRCBDATA + OffsetKPRCB_CURRENTTHREAD);
  READADDR(eprocess,
           ethread + OffsetETHREAD_TCB + OffsetKTHREAD_PROCESS);

  // PID
  r = gbl_context.cb_peek(ethread + OffsetETHREAD_CID + OffsetCLIENTID_PID,
                          reinterpret_cast<unsigned char *>(&pid), sizeof(pid));
  CHECK(r);

  // TID
  r = gbl_context.cb_peek(ethread + OffsetETHREAD_CID + OffsetCLIENTID_TID,
                          reinterpret_cast<unsigned char *>(&tid), sizeof(tid));
  CHECK(r);

  // Process name
  std::unique_ptr<char> imagename
    (new char[OffsetEPROCESS_IMAGEFILENAME_SZ + 1]);

  r = gbl_context.cb_peek(eprocess + OffsetEPROCESS_IMAGEFILENAME,
                          reinterpret_cast<unsigned char *>(imagename.get()),
                          OffsetEPROCESS_IMAGEFILENAME_SZ);
  CHECK(r);

  name = std::string(const_cast<const char*>(imagename.get()));
  return 0;
}

#undef CHECK
#undef READADDR
