"""
Copyright 2014, Roberto Paleari (@rpaleari)

Common utility functions.
"""

import os

def read_syscall_names(filename):
    assert os.path.isfile(filename)

    k = "const char *syscalls_"
    start = False
    names = []

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
	    names.append(l)

    return names

