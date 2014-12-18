//
// Copyright 2014
//   Roberto Paleari <roberto@greyhats.it>
//   Aristide Fattori <aristidefattori@gmail.com>
//

#ifndef SRC_QTRACE_PROFILES_LINUX64_H_
#define SRC_QTRACE_PROFILES_LINUX64_H_

#include <string>
#include <vector>

#include "qtrace/common.h"
#include "qtrace/profiles/guest_os.h"

struct LinuxOffsets {
  // Offset to current_thread in kernel %gs (see: thread_info
  // *current_thread_info)
  target_ulong GSCurrentTask;

  // Offsets inside task_struct
  target_ulong OffsetTaskStruct_Comm;
  target_ulong OffsetTaskStruct_Comm_sz;
  target_ulong OffsetTaskStruct_pid;
  target_ulong OffsetTaskStruct_pid_sz;
  target_ulong OffsetTaskStruct_tgid;
  target_ulong OffsetTaskStruct_tgid_sz;
};

class Linux64 : public GuestOS {
 private:
  struct LinuxOffsets offsets_;

 protected:
  target_ulong current_;

  explicit Linux64(const struct LinuxOffsets &offsets, const char **names,
		   unsigned int names_size);
  target_ulong getCurrentTask(void);

 public:
  ~Linux64() {}

  virtual bool isUserAddress(target_ulong addr) const {
    return (addr >> 47) == 0;
  }
  virtual int getProcessData(uint32_t &pid, uint32_t &tid, std::string &name);
  virtual bool isKernelReady();

  //
  // Parameter-passing ABI for Linux 64-bit syscalls. Linux uses the following
  // 64-bit registers for parameters:
  //  * rdi  arg0
  //  * rsi  arg1
  //  * rdx  arg2
  //  * r10  arg3
  //  * r8   arg4
  //  * r9   arg5
  //
  int getNumSyscallParamsRegister() const { return 6; }
  void getSyscallParamsRegister(std::vector<GuestRegisterParam> &params) const;
  target_ulong getSyscallParamsStack() const;
};

// Concrete Linux profiles

class Linux64_3_2_0 : public Linux64 {
 public:
  explicit Linux64_3_2_0();
  ~Linux64_3_2_0() {}
};

class Linux64_3_14_0 : public Linux64 {
 public:
  explicit Linux64_3_14_0();
  ~Linux64_3_14_0() {}
};

#endif  // SRC_QTRACE_PROFILES_LINUX64_H_
