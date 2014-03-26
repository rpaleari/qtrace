"""
Copyright 2014, Roberto Paleari (@rpaleari)
"""

import ctypes
import sys

SYSCALL_ZWCLOSE = 50

FILE_SHARE_READ = 0x00000001
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 128
GENERIC_READ = 0x80000000

LIBRARY_PATH = "bin\\i386\\syscall.dll"
winsyscall = ctypes.CDLL(LIBRARY_PATH).syscall

kernel32 = ctypes.windll.kernel32
hFile = kernel32.CreateFileA(
    "c:\\windows\\notepad.exe",
    GENERIC_READ,
    FILE_SHARE_READ,
    0,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    0
)

print "Handle:", hFile
sys.stdin.readline()

r = winsyscall(SYSCALL_ZWCLOSE, hFile)
print "Retval:", hex(r)
