"""
Copyright 2014, Aristide Fattori (@joystick)
"""

import ctypes
import os

def execute_syscall(num, *params):
    MACSYSCALL_FUNC = ctypes.cdll.LoadLibrary("libc.dylib").syscall
    assert MACSYSCALL_FUNC is not None

    retval = MACSYSCALL_FUNC(num, *params)
    return retval
