"""
Copyright 2014, Roberto Paleari (@rpaleari)
"""

import ctypes
import os

def execute_syscall(num, *params):
    LINSYSCALL_FUNC = ctypes.cdll.LoadLibrary("libc.so.6").syscall
    assert LINSYSCALL_FUNC is not None

    retval = LINSYSCALL_FUNC(num, *params)
    return retval
