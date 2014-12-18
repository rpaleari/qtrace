//
// Copyright 2014
//   Roberto Paleari <roberto@greyhats.it>
//   Aristide Fattori <aristidefattori@gmail.com>
//

#include "qtrace/profiles/osxmav.h"

#include <cstdio>
#include <cstring>
#include <cassert>
#include <algorithm>
#include <memory>
#include <vector>

#include "qtrace/common.h"
#include "qtrace/context.h"
#include "qtrace/logging.h"
#include "qtrace/profiles/osxmav_symbols.h"
#include "qtrace/profiles/osxmav_syscalls.h"

#define MAXCOMLEN 16
#define MSR_KERNELGSBASE 0xc0000102

target_ulong OSXMavericks::getCurrentTask(void) {
  if (current_ == 0) {
    // target_ulong gs = context_reg_safe(RegisterGsBase);
    target_ulong gs = gbl_context.cb_rdmsr(MSR_KERNELGSBASE);
    assert(!isUserAddress(gs));
    current_ = gs;
    INFO("Initialized current OSXMavericks task to %016lx", current_);
  }

  return current_;
}

bool OSXMavericks::isKernelReady() {
  if (ready_) {
    return true;
  }

  // target_ulong gs = context_reg_safe(RegisterGsBase);
  target_ulong gs = gbl_context.cb_rdmsr(MSR_KERNELGSBASE);

  // Do not even go on checking
  if (!isUserAddress(gs)) {
    INFO("Kernel is ready. Kernel gs @%016llx", gs);
    ready_ = true;
  }

  return ready_;
}

void OSXMavericks::setupTraps() {
  unsigned int traps_size = sizeof(mach_traps_10_9_4) / sizeof(char *);
  for (unsigned int i = 0; i < traps_size; i++) {
    mach_trap_names_.push_back(mach_traps_10_9_4[i]);
  }
}

OSXMavericks::OSXMavericks()
  : GuestOS(syscalls_osx_10_9_4, sizeof(syscalls_osx_10_9_4) / sizeof(char*)),
    current_(0), ready_(false) {
  setupTraps();
}


int OSXMavericks::getProcessData(uint32_t &pid, uint32_t &tid,
                                 std::string &name) {
  target_ulong current = getCurrentTask();

  // I don't know where to get the current tid yet
  tid = 0;
  // 1st step: Read CPU_ACTIVE_THREAD
  target_ulong cpu_active_thread;
  int r;
  r = gbl_context.cb_peek(current + CPU_ACTIVE_THREAD,
                          reinterpret_cast<unsigned char *>(&cpu_active_thread),
                          sizeof(cpu_active_thread));

  if (r != 0) {
    ERROR("Unable to read CPU_ACTIVE_THREAD @%016llx",
          current + CPU_ACTIVE_THREAD);
    return 1;
  }

  if (cpu_active_thread == 0) {
    return 2;
  }

  TRACE("cpu_active_thread: %016llx", cpu_active_thread);

  // 2nd step: read ACTIVE_THREAD_TASK
  target_ulong active_thread_task;
  r =
    gbl_context.cb_peek(cpu_active_thread + ACTIVE_THREAD_TASK,
                        reinterpret_cast<unsigned char *>(&active_thread_task),
                        sizeof(active_thread_task));

  if (r != 0) {
    ERROR("Unable to read ACTIVE_THREAD_TASK @%016llx",
          cpu_active_thread + ACTIVE_THREAD_TASK);
    return 3;
  }

  if (active_thread_task == 0) {
    return 4;
  }

  TRACE("active_thread_task: %016llx", active_thread_task);

  // 3rd step: read TASK_BSD_INFO
  target_ulong task_bsd_info;
  r = gbl_context.cb_peek(active_thread_task + TASK_BSD_INFO,
                          reinterpret_cast<unsigned char *>(&task_bsd_info),
                          sizeof(task_bsd_info));

  if (r != 0) {
    ERROR("Unable to read TASK_BSD_INFO @%016llx",
          active_thread_task + TASK_BSD_INFO);
    return 5;
  }

  if (task_bsd_info == 0) {
    return 6;
  }

  TRACE("task_bsd_info: %016llx", task_bsd_info);

  r = gbl_context.cb_peek(task_bsd_info + PROC_P_PID,
                          reinterpret_cast<unsigned char *>(&pid),
                          sizeof(pid));
  if (r != 0) {
    ERROR("Unable to read p_pid!");
    return 7;
  }

  DEBUG("task_bsd_info.p_pid: %016llx", pid);

  std::unique_ptr<char> comm(new char[MAXCOMLEN + 1]);
  r = gbl_context.cb_peek(task_bsd_info + PROC_P_COMM,
                          reinterpret_cast<unsigned char *>(comm.get()),
                          MAXCOMLEN);
  comm.get()[MAXCOMLEN] = 0;

  if (r != 0) {
    ERROR("Unable to read p_comm!");
    return 8;
  }

  name = std::string(const_cast<const char*>(comm.get()));

  DEBUG("task_bsd_info.p_comm: %s", comm.get());

  return 0;
}

void OSXMavericks::getSyscallParamsRegister(std::vector<GuestRegisterParam>
					    &params)
  const {
  params.push_back({context_reg_safe(RegisterRdi), "rdi"});
  params.push_back({context_reg_safe(RegisterRsi), "rsi"});
  params.push_back({context_reg_safe(RegisterRdx), "rdx"});
  params.push_back({context_reg_safe(RegisterR10), "r10"});
  params.push_back({context_reg_safe(RegisterR8), "r8"});
  params.push_back({context_reg_safe(RegisterR9), "r9"});
}

target_ulong OSXMavericks::getSyscallParamsStack() const  {
  return context_reg_safe(RegisterRsp);
}

std::vector<std::string> OSXMavericks::getSyscallTable(target_ulong sysno)
  const {
  DEBUG("Sysno: %x", sysno);

  // mach_trap?
  if ((sysno & 0x01000000) != 0) {
    DEBUG("Using mach traps");
    return mach_trap_names_;
  } else {
    // Both 64 and 32 bit syscalls have the same numbers (CHECK)
    DEBUG("Using bsd syscalls");
    return syscall_names_;
  }
}

// The two functions below override GuestOS one to take into consideration the
// BSD syscalls/mach traps distinction
const char *OSXMavericks::getSyscallName(target_ulong sysno) const {
  static char name[64];
  std::vector<std::string> target = getSyscallTable(sysno);
  // Independently from the chosen set, mask out upper bits
  sysno &= 0xffff;
  if (sysno > target.size()) {
    snprintf(name, sizeof(name), "unknown%ld", sysno);
  } else {
    strncpy(name, target[sysno].c_str(), sizeof(name));
  }

  return name;
}

int OSXMavericks::getSyscallNumber(const std::string &name) const {
  auto it1 = std::find(syscall_names_.begin(), syscall_names_.end(), name);
  if (it1 != syscall_names_.end()) {
    return 0x02000000 | (it1 - syscall_names_.begin());
  }        

  auto it2 = std::find(mach_trap_names_.begin(), mach_trap_names_.end(), name);
  if (it2 != mach_trap_names_.end()) {
    return 0x01000000 | (it2 - mach_trap_names_.begin());
  }

  return -1;
}

