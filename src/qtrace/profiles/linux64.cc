//
// Copyright 2014
//   Roberto Paleari <roberto@greyhats.it>
//   Aristide Fattori <aristidefattori@gmail.com>
//

#include "qtrace/profiles/linux64.h"

#include <cstdio>
#include <cassert>
#include <memory>
#include <vector>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/profiles/linux64_3_16_syscalls.h"
#include "qtrace/profiles/linux64_symbols.h"

#define MSR_GSBASE 0xc0000101
#define MSR_KERNELGSBASE 0xc0000102

// Constructor for concrete Linux profiles, for specific kernel versions
Linux64_3_2_0::Linux64_3_2_0() :
  Linux64(offsets_linux64_3_2_0, linux64_3_16_syscalls,
          sizeof(linux64_3_16_syscalls) / sizeof(char*)) {}

Linux64_3_14_0::Linux64_3_14_0() :
  Linux64(offsets_linux64_3_14_0, linux64_3_16_syscalls,
          sizeof(linux64_3_16_syscalls) / sizeof(char*)) {}

target_ulong Linux64::getCurrentTask(void) {
  target_ulong gs = gbl_context.cb_rdmsr(MSR_KERNELGSBASE);
  if (gs == 0) {
    // Try reading from GSBASE
    gs = gbl_context.cb_rdmsr(MSR_GSBASE);
    if (gs == 0 || isUserAddress(gs)) {
      return 0;
    }
  }

  target_ulong current_task;
  int r =
    gbl_context.cb_peek(gs + offsets_.GSCurrentTask,
                        reinterpret_cast<unsigned char *>(&current_task),
                        sizeof(current_task));
  assert(r == 0);
  TRACE("current_task: %016llx", current_task);

  assert(!isUserAddress(current_task));

  return current_task;
}

Linux64::Linux64(const struct LinuxOffsets &offsets, const char **names,
                 unsigned int names_size)
  : GuestOS(names, names_size), offsets_(offsets), current_(0) {
}

bool Linux64::isKernelReady() {
  // Check if we already cached the address of the current task
  if (current_ != 0) {
    return true;
  }

  target_ulong gs = context_reg_safe(RegisterGsBase);
  if (gs == 0 || isUserAddress(gs)) {
    // Try reading from MSR
    gs = gbl_context.cb_rdmsr(MSR_KERNELGSBASE);
    if (gs == 0 || isUserAddress(gs)) {
      return false;
    }
  }

  TRACE("Checking if Linux kernel is ready, %%gs 0x%llx", gs);
  // We must also check if the ptr to current has been initialized, otherwise
  // getCurrentTask() will fail
  target_ulong current_task;
  int r = gbl_context.cb_peek(gs + offsets_.GSCurrentTask,
                          reinterpret_cast<unsigned char *>(&current_task),
                          sizeof(current_task));
  assert(r == 0);

  if (current_task == 0 || isUserAddress(current_task)) {
    return false;
  }

  INFO("Kernel is ready: %016llx", current_task);
  current_ = current_task;

  return true;
}

int Linux64::getProcessData(uint32_t &pid, uint32_t &tid, std::string &name) {
  target_ulong current = getCurrentTask();

  // Process name
  std::unique_ptr<char> imagename
    (new char[offsets_.OffsetTaskStruct_Comm_sz + 1]);

  int r =
    gbl_context.cb_peek(current + offsets_.OffsetTaskStruct_Comm,
                          reinterpret_cast<unsigned char *>(imagename.get()),
                          offsets_.OffsetTaskStruct_Comm_sz);
  if (r != 0) {
    return r;
  }

  imagename.get()[offsets_.OffsetTaskStruct_Comm_sz] = '\0';
  name = std::string(const_cast<const char*>(imagename.get()));

  // Process PID
  pid = 0;
  r = gbl_context.cb_peek(current + offsets_.OffsetTaskStruct_pid,
                          reinterpret_cast<unsigned char *>(&pid),
                          offsets_.OffsetTaskStruct_pid_sz);
  if (r != 0) {
    return r;
  }

  // Process TID
  tid = 0;
  r = gbl_context.cb_peek(current + offsets_.OffsetTaskStruct_tgid,
                          reinterpret_cast<unsigned char *>(&tid),
                          offsets_.OffsetTaskStruct_tgid_sz);
  if (r != 0) {
    return r;
  }

  return 0;
}

void Linux64::getSyscallParamsRegister(std::vector<GuestRegisterParam> &params)
  const {
  params.push_back({context_reg_safe(RegisterRdi), "rdi"});
  params.push_back({context_reg_safe(RegisterRsi), "rsi"});
  params.push_back({context_reg_safe(RegisterRdx), "rdx"});
  params.push_back({context_reg_safe(RegisterR10), "r10"});
  params.push_back({context_reg_safe(RegisterR8), "r8"});
  params.push_back({context_reg_safe(RegisterR9), "r9"});
}

target_ulong Linux64::getSyscallParamsStack() const  {
  return context_reg_safe(RegisterRsp);
}
