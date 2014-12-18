"""
Copyright 2014, Roberto Paleari (@rpaleari)
"""

import ctypes
import os

WINSYSCALL_FUNC = None
LIBRARY_PATH = "c:\\tmp\\winsyscall.dll"

def execute_syscall(num, *params):
    global WINSYSCALL_FUNC, LIBRARY_PATH

    if WINSYSCALL_FUNC is None:
        assert os.path.isfile(LIBRARY_PATH), "Invalid library path"
        WINSYSCALL_FUNC = ctypes.CDLL(LIBRARY_PATH).syscall
        assert WINSYSCALL_FUNC is not None, "Invalid function"
        WINSYSCALL_FUNC.restype = ctypes.c_uint

    retval = WINSYSCALL_FUNC(num, *params)

    return retval
