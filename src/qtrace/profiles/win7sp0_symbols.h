//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_PROFILES_WIN7SP0_SYMBOLS_H_
#define SRC_QTRACE_PROFILES_WIN7SP0_SYMBOLS_H_

// Start of kernel memory
const target_ulong MMUserProbeAddress = 0x7fff0000;

// CLIENT_ID
const target_ulong OffsetCLIENTID_PID = 0x000;
const target_ulong OffsetCLIENTID_TID = 0x004;

// EPROCESS
const target_ulong OffsetEPROCESS_PCB             = 0x000;
const target_ulong OffsetEPROCESS_UNIQUEPROCESSID = 0x0b4;
const target_ulong OffsetEPROCESS_IMAGEFILENAME   = 0x16c;
const target_ulong OffsetEPROCESS_IMAGEFILENAME_SZ = 16;

// {E,K}THREAD
const target_ulong OffsetETHREAD_TCB         = 0x000;  // KTHREAD
const target_ulong OffsetETHREAD_CID         = 0x22c;  // CLIENT_ID
const target_ulong OffsetKTHREAD_PROCESS     = 0x150;  // KPROCESS

// KPCR/KPRCB
const target_ulong OffsetKPCR_PRCBDATA       = 0x120;  // KPRCB
const target_ulong OffsetKPRCB_CURRENTTHREAD = 0x004;  // ETHREAD

#endif  // SRC_QTRACE_PROFILES_WIN7SP0_SYMBOLS_H_
