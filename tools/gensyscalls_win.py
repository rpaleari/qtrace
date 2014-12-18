"""
Copyright 2014, Roberto Paleari (@rpaleari)

Generate C header files, defining system calls names for various Windows
versions. Data is fetched from j00ru web site.
"""

import argparse
import logging
import os
import sys
import urllib
from BeautifulSoup import BeautifulSoup

URL_NTAPI_32 = "http://j00ru.vexillium.org/ntapi/"
URL_NTAPI_64 = "http://j00ru.vexillium.org/ntapi_64/"
URL_WIN32K   = "http://j00ru.vexillium.org/win32k_syscalls/"

SYSOPS_32 = {
    ("os_0", 1): "Windows NT SP3",
    ("os_0", 2): "Windows NT SP4",
    ("os_0", 3): "Windows NT SP5",
    ("os_0", 4): "Windows NT SP6",
    ("os_1", 1): "Windows 2000 SP0",
    ("os_1", 2): "Windows 2000 SP1",
    ("os_1", 3): "Windows 2000 SP2",
    ("os_1", 4): "Windows 2000 SP3",
    ("os_1", 5): "Windows 2000 SP4",
    ("os_2", 1): "Windows XP SP0",
    ("os_2", 2): "Windows XP SP1",
    ("os_2", 3): "Windows XP SP2",
    ("os_2", 4): "Windows XP SP3",
    ("os_3", 1): "Windows 2003 Server SP0",
    ("os_3", 2): "Windows 2003 Server SP1",
    ("os_3", 3): "Windows 2003 Server SP2",
    ("os_4", 1): "Windows Vista SP0",
    ("os_4", 2): "Windows Vista SP1",
    ("os_4", 3): "Windows Vista SP2",
    ("os_5", 1): "Windows 2008 Server SP0",
    ("os_5", 2): "Windows 2008 Server SP1",
    ("os_5", 3): "Windows 2008 Server SP2",
    ("os_6", 1): "Windows 7 SP0",
    ("os_6", 2): "Windows 7 SP1",
    ("os_7", 1): "Windows 8.0",
    ("os_7", 2): "Windows 8.1",
}

SYSOPS_64 = {
    ("os_0", 1): "Windows XP SP0",
    ("os_0", 2): "Windows XP SP1",
    ("os_0", 3): "Windows XP SP2",
    ("os_1", 1): "Windows Server 2003 SP0",
    ("os_1", 2): "Windows Server 2003 SP1",
    ("os_1", 3): "Windows Server 2003 SP2",
    ("os_2", 1): "Windows Vista SP0",
    ("os_2", 2): "Windows Vista SP1",
    ("os_2", 3): "Windows Vista SP2",
    ("os_3", 1): "Windows Server 2008 SP0",
    ("os_3", 2): "Windows Server 2008 SP1",
    ("os_3", 3): "Windows Server 2008 SP2",
    ("os_4", 1): "Windows 7 SP0",
    ("os_4", 2): "Windows 7 SP1",
    ("os_5", 1): "Windows Server 2012 SP0",
    ("os_6", 1): "Windows 8.0",
    ("os_6", 2): "Windows 8.1",
}

def fetchsyscalls_nt(data, sysops_arch):
    html = BeautifulSoup(data, convertEntities = BeautifulSoup.HTML_ENTITIES)
    sysopkeys = sysops_arch.keys()
    sysopkeys.sort()

    sysops = {}
    for k, sysopname in sysops_arch.iteritems():
        assert sysopname not in sysops
        sysops[sysopname] = {}

    for tr in html.findAll("tr"):
        columns = tr.findAll("td")

        if len(columns) != len(sysops_arch) + 1:
            continue

        syscallname = columns[0].text.encode("ascii").strip()
        if syscallname == "System Call Symbol":
            continue

        for i in range(len(sysopkeys)):
            sysopkey = sysopkeys[i]
            syscallnum = columns[i+1]["text"].strip()
            if len(syscallnum) > 0:
                syscallnum = int(syscallnum, 16)
                syscalls = sysops[sysops_arch[sysopkey]]
                syscalls[syscallnum] = syscallname

    return sysops

def fetchsyscalls_win32k(data, sysops_arch):
    html = BeautifulSoup(data, convertEntities = BeautifulSoup.HTML_ENTITIES)
    sysopkeys = sysops_arch.keys()
    sysopkeys.sort()

    sysops = {}
    for k, sysopname in sysops_arch.iteritems():
        assert sysopname not in sysops
        sysops[sysopname] = {}

    for tr in html.findAll("tr"):
        columns = tr.findAll("td")
        if len(columns) == 0 or not columns[0].has_key("class"):
            continue

        if not columns[0]["class"].startswith("sym_name"):
            continue

        syscallname = columns[0].text.encode("ascii").strip()
        for c in columns[1:]:
            sysopid, syscallnum = c["id"].split("_")
            assert sysopid.isdigit()
            sysopkey = sysopkeys[int(sysopid)]

            if syscallnum == "xx":
                continue

            syscallnum = int(syscallnum, 16)
            syscalls = sysops[sysops_arch[sysopkey]]
            syscalls[syscallnum] = syscallname

    return sysops

def generatefiledata(target, syscalls):
    varname = target.replace(" ", "").replace(".", "_") + "_syscalls"

    data = """\
//
// Copyright 2014, Roberto Paleari <roberto@greyhats.it>
//
// This file is generated automatically using %s. Do not edit!
//

const char *%s[] = {
""" % (os.path.basename(sys.argv[0]), varname)
    for sysno in range(max(syscalls.keys())):
        if sysno in syscalls:
            name = syscalls[sysno]
        else:
            name = "unknown%d" % sysno
        data += "  \"%s\",\n" % name
    data += "};\n"
    return data


def main():
    global URL_NTAPI_32, URL_NTAPI_64, URL_WIN32K

    # Parse command-line options
    sysop_names = set(SYSOPS_32.values() + SYSOPS_64.values())
    sysop_names = sorted(list(sysop_names))

    parser = argparse.ArgumentParser(
        formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-b", "--bits", type=int, default=32,
                        choices=(32, 64),
                        help="32-bit or 64-bit architecture")
    parser.add_argument("-o", "--outdir", required=True,
                        help="output directory")
    parser.add_argument("-f", "--filename",
                        help="read data from file", default=None)
    parser.add_argument("-s", "--sysop",
                        help="process only a specific OS",
                        choices=sysop_names, default=None)
    parser.add_argument("-v", "--loglevel", help="set log level",
                        default="INFO",
                        choices=["CRITICAL", "DEBUG", "ERROR",
                                 "WARNING", "INFO"])
    args = parser.parse_args()

    # Initialize logging subsystem
    numeric_loglevel = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(format = '[%(asctime)s] %(levelname)s : %(message)s',
                        level=numeric_loglevel)

    # Sanity checks
    assert os.path.isdir(args.outdir)

    # Select 32- or 64-bit syscalls
    if args.bits == 32:
        ntapi_url = URL_NTAPI_32
        sysops_arch = SYSOPS_32
    else:
        ntapi_url = URL_NTAPI_64
        sysops_arch = SYSOPS_64

    # Determine which operating systems to process
    if args.sysop is not None:
        if args.sysop not in sysops_arch.values():
            logging.error("OS %s not available for the %d-bit architecture", args.sysop, args.bits)
            exit(0)
        targets = [args.sysop, ]
    else:
        targets = sysops_arch.values()
    targets.sort()

    # Fetch system calls
    if args.filename is not None:
        data = open(args.filename).read()
        if "WIN32K.SYS" in data:
            sysops = fetchsyscalls_win32k(data, SYSOPS_32)
        else:
            sysops = fetchsyscalls_nt(data, sysops_arch)
    else:
        data = urllib.urlopen(ntapi_url).read()
        sysops = fetchsyscalls_nt(data, sysops_arch)

        data = urllib.urlopen(URL_WIN32K).read()
        sysops_win32k = fetchsyscalls_win32k(data, SYSOPS_32)

        for target, values in sysops.iteritems():
            if target in sysops_win32k:
                values.update(sysops_win32k[target])

    for target in targets:
        syscalls = sysops[target]
        filename = target.lower().replace("windows", "win").split()
        filename = "".join(filename) + "_syscalls.h"
        filename = os.path.join(args.outdir, filename)

        if len(syscalls) == 0:
            logging.warning("No data for %s", target)
            continue

        data = generatefiledata(target, syscalls)

        logging.info("Writing %s syscalls to file %s", target, filename)

        # Write output file
        outfile = open(filename, "w")
        outfile.write(data)
        outfile.close()


if __name__ == "__main__":
    main()
