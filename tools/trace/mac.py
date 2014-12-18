"""
Copyright 2014, Roberto Paleari (@rpaleari)

Common utility functions.
"""

import os

def read_syscall_names(filename):
    """Read syscall names from the specified file."""

    assert os.path.isfile(filename)

    k = "const char *syscalls_"
    j = "const char *mach_"
    start_syscall = False
    start_traps = False
    names = {}
    i = 0

    with open(filename) as f:
        for l in f.readlines():
            l = l.strip()

            if not start_syscall and l.startswith(k):
                i = 0
                start_syscall = True
                start_traps = False
                continue
            elif not start_traps and l.startswith(j):
                i = 0
                start_syscall = False
                start_traps = True
                continue

            l = l.strip('","')
            if start_syscall:
                key = i | 0x02000000
            elif start_traps:
                key = i | 0x01000000
            else:
                key = i

            names[key] = l
            i += 1

    return names
