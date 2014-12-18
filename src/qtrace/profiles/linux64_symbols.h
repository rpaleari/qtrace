//
// Copyright 2014
//   Roberto Paleari <roberto@greyhats.it>
//   Aristide Fattori <aristidefattori@gmail.com>
//

#ifndef SRC_QTRACE_PROFILES_LINUX64_SYMBOLS_H_
#define SRC_QTRACE_PROFILES_LINUX64_SYMBOLS_H_

const struct LinuxOffsets offsets_linux64_3_14_0 = {
  0xc880,			// GSCurrentTask
  0x4b0,			// OffsetTaskStruct_Comm
  15,				// OffsetTaskStruct_Comm_sz
  0x2fc,			// OffsetTaskStruct_pid
  4,				// OffsetTaskStruct_pid_sz
  0x300,			// OffsetTaskStruct_tgid
  4,				// OffsetTaskStruct_tgid_sz
};

const struct LinuxOffsets offsets_linux64_3_2_0 = {
  0xc700,			// GSCurrentTask
  0x398,			// OffsetTaskStruct_Comm
  15,				// OffsetTaskStruct_Comm_sz
  0x1e4,			// OffsetTaskStruct_pid
  4,				// OffsetTaskStruct_pid_sz
  0x1e8,			// OffsetTaskStruct_tgid
  4,				// OffsetTaskStruct_tgid_sz
};

#endif  // SRC_QTRACE_PROFILES_LINUX64_SYMBOLS_H_
