"""
Copyright 2014, Roberto Paleari (@rpaleari)

Common utility functions.
"""

import os

def read_syscall_names(filename):
    """Read syscall names from the specified file."""

    assert os.path.isfile(filename)

    k = "const char *"
    start = False
    names = {}
    i = 0
    with open(filename) as f:
        for l in f.readlines():
            l = l.strip()

            if not start:
                if l.startswith(k):
                    start = True
                continue

            if l.startswith("};"):
                break

            l = l.strip('","')
            names[i] = l
            i += 1

    return names

def chunks(li, size):
    total = len(li)
    chunks = total/size
    rem = total%size
    i = 0
    while i <= chunks:
        if i == chunks and rem == 0:
            return
        elif i == chunks and rem != 0:
            yield li[i*size:i*size+rem] + "\x00"*(size-rem)
        else:
            yield li[i*size:(i+1)*size]

        i += 1
