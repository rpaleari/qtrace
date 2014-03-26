"""
Copyright 2014, Roberto Paleari (@rpaleari)
"""

import ctypes
import os

WINSYSCALL_FUNC = None
LIBRARY_PATH = "c:\\temp\\winsyscall.dll"

def execute_syscall(num, *params):
    global WINSYSCALL_FUNC, LIBRARY_PATH

    if WINSYSCALL_FUNC is None:
        assert os.path.isfile(LIBRARY_PATH)
        WINSYSCALL_FUNC = ctypes.CDLL(LIBRARY_PATH).syscall
        assert WINSYSCALL_FUNC is not None

    retval = WINSYSCALL_FUNC(num, *params)
    return retval
