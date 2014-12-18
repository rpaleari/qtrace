"""
Copyright 2014, Roberto Paleari (@rpaleari)

Generate C header files, defining system calls names for a given Linux kernel
release.
"""

import argparse
import logging
import platform
import urllib

from gensyscalls_win import generatefiledata

TBL_URL = "http://lxr.missinglinkelectronics.com/linux+v%s/+save=arch/x86/syscalls/syscall_%d.tbl"
UNISTD_URL = "http://lxr.missinglinkelectronics.com/linux+v%s/+save=arch/x86/include/asm/unistd_%d.h"

def parse_unistd(data):
    syscalls = {}
    prefix = "__NR_"

    for line in data.split("\n"):
        line = line.strip()
        if (len(line) == 0 or prefix not in line or
            not line.startswith("#define")):
            continue
            
        line = line.split()
        if len(line) != 3:
            continue

        pragma, name, number = line
        number = int(number)
        assert number not in syscalls
        syscalls[number] = name.replace(prefix, "").strip()
    return syscalls

def parse_tbl(data):
    syscalls = {}
    for line in data.split("\n"):
        line = line.strip()
        if len(line) == 0 or line.startswith("#"):
            continue

        line = line.split()

        number, abi, name = line[:3]
        number = int(number)
        syscall_name = name

        if len(line) > 3:
            entry = line[3]
            syscall_name = entry

        if len(line) > 4:
            compat = line[4]

        syscalls[int(number)] = syscall_name
    return syscalls


def main():
    # Parse command-line options
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-a", "--arch", help="architecture",
                        choices=["i686", "x86_64"],
                        default=platform.machine())
    parser.add_argument("-k", "--kernel", help="kernel version",
                        default=platform.release().split("-")[0])
    parser.add_argument("-v", "--loglevel", help="set log level", 
                        default = "INFO",
                        choices = ["CRITICAL", "DEBUG", "ERROR", 
                                   "WARNING", "INFO"])
    args = parser.parse_args()

    # Initialize logging
    numeric_loglevel = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(format='[%(asctime)s] %(levelname)s : %(message)s', 
                        level=numeric_loglevel)

    # Build the base URL
    if args.arch == "i686":
        bits = 32
    elif args.arch == "x86_64":
        bits = 64
    else:
        assert False, "Unknown architecture '%s'" % args.arch

    url = TBL_URL % (args.kernel, bits)
    logging.debug("Fetching syscall data from %s", url)

    data = urllib.urlopen(url).read()
    if "Internal Server Error" not in data:
        syscalls = parse_tbl(data)
    else:
        # Fallback on plain unistd*.h files
        url = UNISTD_URL % (args.kernel, bits)
        logging.debug("Fallback on URL %s", url)
        data = urllib.urlopen(url).read()
        syscalls = parse_unistd(data)

    target = "linux%d_%s" % (bits, args.kernel.replace(".", "_"))
    r = generatefiledata(target, syscalls)
    print r

if __name__ == "__main__":
    main()


