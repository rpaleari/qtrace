//
// Copyright 2013, Roberto Paleari <roberto@greyhats.it>
//

#ifndef SRC_QTRACE_WINXPSP3_SYMBOLS_H_
#define SRC_QTRACE_WINXPSP3_SYMBOLS_H_

// Start of kernel memory
const target_ulong MMUserProbeAddress = 0x7fff0000;

// CLIENT_ID
const target_ulong OffsetCLIENTID_PID = 0x000;
const target_ulong OffsetCLIENTID_TID = 0x004;

// EPROCESS
const target_ulong OffsetEPROCESS_PCB             = 0x000;
const target_ulong OffsetEPROCESS_UNIQUEPROCESSID = 0x084;
const target_ulong OffsetEPROCESS_IMAGEFILENAME   = 0x174;
const target_ulong OffsetEPROCESS_IMAGEFILENAME_SZ = 16;

// {E,K}THREAD
const target_ulong OffsetETHREAD_CID            = 0x1ec; // CLIENT_ID
const target_ulong OffsetETHREAD_THREADSPROCESS = 0x220; // EPROCESS

// KPCR/KPRCB
const target_ulong OffsetKPCR_PRCBDATA       = 0x120;  // KPRCB
const target_ulong OffsetKPRCB_CURRENTTHREAD = 0x004;  // ETHREAD

#endif  // SRC_QTRACE_WINXPSP3_SYMBOLS_H_
