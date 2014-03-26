"""
Copyright 2014, Roberto Paleari (@rpaleari)
"""

import logging

class TaintEngine(object):
    def __init__(self, trace):
        self.__trace = trace

    def __sanity_check(self, syscall):
        # Sanity check for matching header values, according to taint
        # dependencies
        for arg in syscall.arguments:
            if len(arg.taintlabels) == 0 or arg.getSize() != 4:
                continue
            if len(arg.taintlabels) > 1:
                print "Too many taint labels: %s" % arg.taintlabels
                continue

            idz = list(arg.taintlabels)[0]
            for defarg in self.__trace[idz].arguments:
                if len(defarg.pointers) == 1 and \
                   defarg.pointers[0].getDirectionName() == "OUT":
                    import struct
                    hin = struct.unpack("I", arg.indata)[0]
                    hout = struct.unpack("I", defarg.pointers[0].outdata)[0]

                    hin = hin  & 0xfffffffc
                    hout = hout & 0xfffffffc

                    print "Sanity checking %.8x vs %.8x:" % (hin, hout),
                    if hin == hout:
                        print "SUCCESS"
                    else:
                        print "FAILED"

    def dump(self, sanitychecks=False):
        for sysid, syscall in self.__trace.iteritems():
            labels = syscall.getTaintLabels()
            if len(labels) == 0:
                continue

            print "Data dependency between syscall %d [USE] and %s [DEF(s)]" % \
                (sysid, ", ".join([str(x) for x in labels]))
            if not all([sysid > x for x in labels]):
                logging.warning("Incoherent dependency for syscall #%d", sysid)

            for defid in labels:
                print self.__trace[defid].dump()
            print syscall.dump()

            if sanitychecks:
                self.__sanity_check(syscall)

            print
