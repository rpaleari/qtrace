"""
Copyright 2014, Roberto Paleari (@rpaleari)

Generate C header files, defining system calls names for a given OSx XNU kernel
release.
"""

import argparse
import logging
import urllib
import urlparse

from gensyscalls_win import generatefiledata

OSX_URL = "http://www.opensource.apple.com/release/os-x-%d/"
XNU_URL = "http://www.opensource.apple.com/source/xnu/xnu-%s/bsd/kern/syscalls.master?txt"
MACH_URL = "http://www.opensource.apple.com/source/xnu/xnu-%s/osfmk/kern/syscall_sw.c?txt"

def build_syscalls(data):
    syscalls = {}
    for line in data.split("\n"):
        line = line.strip()
        if len(line) == 0 or line.startswith(";") or line.startswith("#"):
            continue

        line = line.split()
        number = int(line[0])
        if number in syscalls:
            continue

        tmp = " ".join(line[line.index("{")+1:line.index("}")])

        name = tmp.split()[1]
        name = name.split("(")[0]
        
        if name == "nosys":
            name = "nosys_%d" % number

        syscalls[number] = name

    return syscalls

def build_traps(data):
    traps = {}
    start = False
    i = 0
    for line in data.split("\n"):
        line = line.strip()
        if start or line.startswith("const char * mach_syscall_name_table"):
            start = True
        else:
            continue

        if len(line) == 0 or (line[0:2] == "/*" and line[-2:] == "*/"):
            continue

        if line == "};":
            break

            
        t = filter(lambda x: x != "", line.split("\t"))
        if len(t) != 2:
            continue
        traps[i] = t[1].replace('"', "").replace(",", "")
        
        i += 1
    return traps

def main():
    # Parse command-line options
    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-r", "--release", help="OSX version",
                        default="10.9.4")
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

    # Fetch XNU version
    url = OSX_URL % int(args.release.replace(".", ""))
    logging.debug("Fetching XNU version from %s", url)
    data = urllib.urlopen(url).read()

    k = "/source/xnu/xnu-"
    xnu_ver = data[data.find(k)+len(k):]
    xnu_ver = xnu_ver[:xnu_ver.find('"')-1]

    # Fetch syscalls.master file for this XNU version
    url = XNU_URL % xnu_ver
    logging.debug("Fetching syscalls list from %s", url)
    data = urllib.urlopen(url).read()

    syscalls = build_syscalls(data)

    url = MACH_URL % xnu_ver
    logging.debug("Fetching traps list from %s", url)
    data = urllib.urlopen(url).read()
    traps = build_traps(data)
    

    
    target = "osx_%s" % args.release.replace(".", "_")
    r = generatefiledata(target, syscalls)
    r += """
/* Extracted from: osfmk/kern/syscall_sw.c */
const char *mach_traps_10_9_4[] = {
    """
    r += ',\n'.join(['  "%s"' % v for k,v in sorted(traps.items(), key=lambda x: x[0])])
    r += "\n};"
    print r

if __name__ == "__main__":
    main()


