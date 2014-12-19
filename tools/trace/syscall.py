"""
Copyright 2014, Roberto Paleari (@rpaleari)

Syscall and SyscallArgument classes.
"""

import ctypes
import platform
import string
import struct
import runtime.winsyscall

import trace.syscall_pb2

def collapse_intervals(intervals, fillchar='\xdc'):
    data = ""

    intervals = [i for i in intervals]
    intervals.sort(cmp=lambda a, b: cmp(a.offset, b.offset))

    for interval in intervals:
        data += fillchar * (interval.offset - len(data))
        data += interval.data

    return data

class Syscall(object):
    STATUS_SUCCESS = 0x00000000

    def __init__(self, obj, name):
        self.idz = obj.id
        self.name = name
        self.sysno = obj.sysno
        self.retval = obj.retval

        self.process_name = obj.process.name
        self.process_pid = obj.process.pid
        self.process_tid = obj.process.tid

        self.taintlabel_retval = obj.taintlabel_retval

        # Arguments
        self.arguments = []
        for argobj in obj.arg:
            arg = SyscallArgument(argobj)
            self.arguments.append(arg)

        # External references
        self.extrefs = []
        for refobj in obj.ref:
            self.extrefs.append(refobj)

        # Sort arguments according to their offset
        self.arguments.sort(lambda a, b: cmp(a.offset, b.offset))

    def isSuccess(self):
        """
        Check if this syscall was successful.
        """
        v = ctypes.c_int32(self.retval)
        return v >= 0

    def isGUI(self):
        """
        Check if this is a GUI (i.e., win32k.sys) system call.
        """
        return self.sysno > 4095

    def dump(self):
        """
        Return a string representing this system call object.
        """
        s = "==== Syscall no. %d (0x%.8x, %s) ====\n" % \
             (self.idz, self.sysno, self.name)
        s += "  process: pid = 0x%.8x, tid = 0x%.8x, name = %s\n" % \
             (self.process_pid, self.process_tid, self.process_name)
        s += "  return value: 0x%.8x\n" % self.retval
        s += "  external references (%d):\n" % len(self.extrefs)
        for i in range(len(self.extrefs)):
            extref = self.extrefs[i]
            s += "   ref #%d: pc %.8x, addr %.8x, value %.8x\n" % \
                 (i, extref.pc, extref.addr, extref.value)

        for i in range(len(self.arguments)):
            s += self.arguments[i].dump(i)
        return s

    def getTaintUses(self):
        """
        Return a sorted list of taint labels _used_ by this system call.
        """
        labels = set()
        for i in range(len(self.arguments)):
            labels |= self.arguments[i].getTaintUses()
        labels = list(labels)
        labels.sort()
        return labels

    def getTaintDefs(self):
        """
        Return a sorted list of taint labels _defined_ by this system call.
        """
        labels = set([self.taintlabel_retval, ])
        for i in range(len(self.arguments)):
            labels |= self.arguments[i].getTaintDefs()
        labels = list(labels)
        labels.sort()
        return labels

    def execute(self):
        """
        Replay this system call on current system.
        """
        assert platform.system() == "Windows", \
            "Cannot replay this system call on current OS"

        params = []
        for i in range(len(self.arguments)):
            arg = self.arguments[i]
            argbuf = arg.allocate()
            # print arg.dump(i, dumpallocation = True),

            assert ctypes.sizeof(argbuf) == ctypes.sizeof(ctypes.c_voidp)

            addr = ctypes.cast(argbuf, ctypes.POINTER(ctypes.c_uint))[0]
            params.append(ctypes.cast(addr, ctypes.POINTER(ctypes.c_uint)))

        retval = runtime.winsyscall.execute_syscall(self.sysno, *params)
        return retval & 0xffffffff

class SyscallArgument(object):
    def __init__(self, obj):
        self.allocation = None
        self.addr = obj.addr
        self.offset = obj.offset

        self.taintlabels_in = None
        self.taintlabels_out = None

        if len(obj.taintlabels_in) > 0:
            self.taintlabels_in = set(obj.taintlabels_in)

        if len(obj.taintlabels_out) > 0:
            self.taintlabels_out = set(obj.taintlabels_out)

        self.direction = obj.direction

        self.pointers = []
        for ptrobj in obj.ptr:
            ptr = SyscallArgument(ptrobj)
            self.pointers.append(ptr)

        # Sort pointers according to their offset
        self.pointers.sort(lambda a, b: cmp(a.offset, b.offset))

        # Collapse input/output data intervals
        self.indata = collapse_intervals(obj.indata)
        self.outdata = collapse_intervals(obj.outdata)


    def allocate(self):
        """
        Allocates a system call argument, returning its memory address. This
        method also takes care of allocating sub-arguments.
        """

        # Force re-allocation
        # if self.allocation is None:
        if True:
            data = self.indata

            intsize = struct.calcsize("I")
            # Allocate sub-arguments and fixup data pointers
            for ptr in self.pointers:
                argbuf = ptr.allocate()
                addr = ctypes.addressof(argbuf)
                offset = ptr.offset

                # Sanity check
                oldvalue = struct.unpack("I", data[offset:offset+intsize])[0]
                assert ptr.addr == oldvalue

                # Update the parameter address
                newvalue = struct.pack("I", addr)
                data = data[:offset] + newvalue + data[offset + intsize:]

            self.allocation = ctypes.c_buffer(data, len(data))

        return self.allocation

    @staticmethod
    def stringifyData(data):
        # Try to guess data type
        if len(data) > 1 and (len(data) % 2) == 0:
            values = set([data[i+1] for i in \
                          range(0, len(data), 2)])
        else:
            values = set()

        if len(data) > 4 and len(values) == 1 and values.pop() == "\x00":
            # Raw data
            unicodedata = "".join([data[i] for i in \
                                   range(0, len(data), 2)])
        else:
            unicodedata = ""

        # Consider as unicode only printable strings, with length > 0
        if len(unicodedata) > 0 and \
           len([c for c in unicodedata if c not in string.printable]) == 0:
            r = 'unicode(%s)' % repr(unicodedata)
        else:
            # Unicode string
            r = data.encode("hex")

        return r

    def getTaintUses(self):
        """
        Return a set of taint labels _used_ by this syscall argument.
        """
        if self.taintlabels_in is None:
            return set()

        labels = set(self.taintlabels_in)
        for i in range(len(self.pointers)):
            labels |= self.pointers[i].getTaintUses()
        return labels

    def getTaintDefs(self):
        """
        Return a set of taint labels _defined_ by this syscall argument.
        """
        if self.taintlabels_out is None:
            return set()

        labels = set(self.taintlabels_out)
        for i in range(len(self.pointers)):
            labels |= self.pointers[i].getTaintDefs()
        return labels

    def getDirectionName(self):
        if self.direction == trace.syscall_pb2.SyscallArg.IN:
            name = "IN"
        elif self.direction == trace.syscall_pb2.SyscallArg.OUT:
            name = "OUT"
        elif self.direction == trace.syscall_pb2.SyscallArg.INOUT:
            name = "IN/OUT"
        else:
            assert False, "Unknown direction"
        return name

    def getSize(self):
        return max(len(self.indata), len(self.outdata))

    def dump(self, num, indent=0, dumpallocation=False):
        indata = SyscallArgument.stringifyData(self.indata)
        outdata = SyscallArgument.stringifyData(self.outdata)

        inout = self.getDirectionName()

        if not dumpallocation:
            s = "arg #%d @0x%.8x (%s), off %d, size %d, " \
                "indata %s, outdata %s" % \
                (num, self.addr, inout, self.offset, self.getSize(),
                 indata, outdata)
        else:
            if self.allocation is None:
                self.allocate()

            s = "arg #%d @0x%.8x (%s), off %d, size %d, " \
                "data %s" % \
                (num, ctypes.addressof(self.allocation), inout, self.offset,
                 self.getSize(), self.allocation.raw.encode("hex"))

        # Add taint labels
        if self.taintlabels_out is not None and len(self.taintlabels_out) > 0:
            labels = list(self.taintlabels_out)
            labels.sort()
            s += ", def %s" % labels

        if self.taintlabels_in is not None and len(self.taintlabels_in) > 0:
            labels = list(self.taintlabels_in)
            labels.sort()
            s += ", use %s" % labels

        # Add indentation and EOL
        s = "%s%s\n" % (" "*((indent+1)*2), s)

        for i in range(len(self.pointers)):
            s += self.pointers[i].dump(i, indent + 1,
                                       dumpallocation=dumpallocation)

        return s
