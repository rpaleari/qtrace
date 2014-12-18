// Copyright 2014, Roberto Paleari (@rpaleari)

#include <windows.h>
#include <stdio.h>
#include <assert.h>

// extern int DoSyscall1(int sysno, int nargs, DWORD *args);
extern int DoSyscall(int sysno, DWORD *args);
FARPROC KiFastSystemCall;

int WINAPI syscall(int sysno, ...) {
  DWORD *dwArgs = &sysno + 1;
  return DoSyscall(sysno, dwArgs);
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
  switch(fdwReason) {
  case DLL_PROCESS_ATTACH: {
    DWORD status;
    HANDLE hFile;

    KiFastSystemCall = GetProcAddress(LoadLibrary("ntdll.dll"),
                                      "KiFastSystemCall");
    assert(KiFastSystemCall != NULL);
    break;
  }
  case DLL_THREAD_ATTACH:
    break;
  case DLL_THREAD_DETACH:
    break;
  case DLL_PROCESS_DETACH:
    break;
  }

  return TRUE;
}
