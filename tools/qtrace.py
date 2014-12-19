"""
Copyright 2014, Roberto Paleari (@rpaleari)

QTrace Python interface for parsing syscall trace files and generating some
output formats.
"""

import argparse
import collections
import imp
import logging
import os

import output.dot
import output.html
import trace.common
import trace.reader

import taint

def main():
    # Parse command-line arguments
    parser = argparse.ArgumentParser(formatter_class=
                                     argparse.ArgumentDefaultsHelpFormatter)
    parser.add_argument("-d", "--dump", action="store_true", default=False,
                        help="dump system calls")
    parser.add_argument("-e", "--execute", action="store_true", default=False,
                        help="execute (ALPHA, work in progress)")
    parser.add_argument("-f", "--dereference", action="store_true",
                        default=False,
                        help="dump syscalls with dereferenced non-arg " \
                        "addresses")
    parser.add_argument("-g", "--taintgraph", default=None,
                        help="create syscall dependencies graph file")
    parser.add_argument("-o", "--output", default=None,
                        help="generate output file")
    parser.add_argument("-p", "--plugin", default=None,
                        help="load a plugin")
    parser.add_argument("-r", "--extrefs", action="store_true", default=False,
                        help="dump system calls with external memory refs")
    parser.add_argument("-s", "--sysnames", default=None,
                        help="file with syscall names")
    parser.add_argument("-t", "--tainttrack", action="store_true",
                        default=False,
                        help="dump taint tracking information")
    parser.add_argument("-v", "--loglevel", default="INFO",
                        help="log level",
                        choices=["CRITICAL", "DEBUG", "ERROR", "WARNING",
                                 "INFO"])

    parser.add_argument('filename', help="QTrace trace file")
    args = parser.parse_args()

    # Initialize logging subsystem
    numeric_loglevel = getattr(logging, args.loglevel.upper(), None)
    if not isinstance(numeric_loglevel, int):
        raise ValueError('Invalid log level: %s' % args.loglevel)
    logging.basicConfig(format='[%(asctime)s] %(levelname)s : %(message)s',
                        level=numeric_loglevel)

    if args.sysnames is not None:
        if not os.path.isfile(args.sysnames):
            logging.error("Invalid syscall names file '%s'", args.sysnames)
            exit(1)
        logging.info("Reading syscall names from '%s'", args.sysnames)
        names = trace.common.read_syscall_names(args.sysnames)
        logging.debug("Read %d syscall names", len(names))
    else:
        names = []

    logging.debug("Reading trace file '%s'", args.filename)

    # Get file size
    statinfo = os.stat(args.filename)
    filesize = statinfo.st_size

    # Read syscalls and dump them to string
    syscalls = collections.OrderedDict()
    with open(args.filename, "rb") as tracefile:
        reader = trace.reader.TraceReader(tracefile, filesize, names)
        if args.dump:
            print reader.header

        for syscall in reader:
            idz = syscall.idz
            assert idz not in syscalls, "Duplicated syscall ID #%d" % idz
            syscalls[idz] = syscall

            # Dump system calls
            if args.dump or \
               (args.extrefs and len(syscall.extrefs) > 0):
                print syscall.dump()

            # Dump dereferenced ring-3 addresses
            if args.dereference and len(syscall.extrefs) > 0:
                extvals = set([x.value for x in syscall.extrefs])
                extaddrs = set([x.addr for x in syscall.extrefs])
                if len(extvals & extaddrs) > 0:
                    print "Dereferenced ring-3 addresses: %s" % \
                        ", ".join(hex(x) for x in extvals & extaddrs)
                    print syscall.dump()
                    print

    logging.info("Read %d system calls", len(syscalls))

    # Check availability of taint-tracking information
    if (args.tainttrack or args.taintgraph) and not reader.header.hastaint:
        logging.error("Syscall trace does not include taint information")
        exit(1)

    # Dump taint-tracking information
    if args.tainttrack:
        taintengine = taint.TaintEngine(syscalls)
        logging.info("Dumping syscall dependencies based on taint information")
        taintengine.dump(sanitychecks=True)

    # Generate output file
    if args.output is not None:
        _, ext = os.path.splitext(args.output)
        if ext in (".html", ".htm"):
            # Generate HTML file
            outclass = output.html.HTMLOutputGenerator
        elif ext in (".dot", ):
            # Generate GraphViz file
            outclass = output.dot.DotOutputGenerator
        else:
            logging.warning("Unsupported output extension '%s', assuming HTML",
                            ext)
            outclass = output.html.HTMLOutputGenerator

        outfile = open(args.output, "w")
        out = outclass(outfile)
        out.visit(reader.header)
        for syscall in syscalls.values():
            out.visit(syscall)
        del out
        outfile.close()
        logging.info("Output file written to '%s'", args.output)

    # Load additional syscall processors
    if args.plugin is not None:
        assert os.path.isfile(args.plugin)
        plugin = imp.load_source("plugin", args.plugin)
        plugin.process(syscalls)

    # Execute
    if args.execute:
        logging.info("==== Testing syscall execution ====")
        logging.info("Executing system call #%d", syscall.sysno)
        retval = syscall.execute()
        logging.info("Execution completed, return value: 0x%.8x", retval)


if __name__ == "__main__":
    main()
