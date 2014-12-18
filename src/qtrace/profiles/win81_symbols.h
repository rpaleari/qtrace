//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_PROFILES_WIN81_SYMBOLS_H_
#define SRC_QTRACE_PROFILES_WIN81_SYMBOLS_H_

// CLIENT_ID
const target_ulong OffsetCLIENTID_PID = 0x000;
const target_ulong OffsetCLIENTID_TID = 0x008;

// EPROCESS
const target_ulong OffsetEPROCESS_PCB             = 0x000;
const target_ulong OffsetEPROCESS_UNIQUEPROCESSID = 0x2e0;
const target_ulong OffsetEPROCESS_IMAGEFILENAME   = 0x438;
const target_ulong OffsetEPROCESS_IMAGEFILENAME_SZ = 16;

// {E,K}THREAD
const target_ulong OffsetETHREAD_TCB         = 0x000;  // KTHREAD
const target_ulong OffsetETHREAD_CID         = 0x620;  // CLIENT_ID
const target_ulong OffsetKTHREAD_PROCESS     = 0x220;  // KPROCESS

// KPCR/KPRCB
const target_ulong OffsetKPCR_PRCBDATA       = 0x180;  // KPRCB
const target_ulong OffsetKPRCB_CURRENTTHREAD = 0x008;  // ETHREAD

#endif  // SRC_QTRACE_PROFILES_WIN81_SYMBOLS_H_
