"""
Copyright 2014, Roberto Paleari (@rpaleari)

Syscall and SyscallArgument classes.
"""

import ctypes
import copy
import logging
import platform
import string
import struct

import runtime.winsyscall
import trace.syscall_pb2
import trace.common

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
        self.obj = obj
        self.name = name

        # Arguments
        self.arguments = []
        for argobj in self.obj.arg:
            arg = SyscallArgument(argobj)
            self.arguments.append(arg)

        # External references
        self.extrefs = []
        for refobj in self.obj.ref:
            self.extrefs.append(refobj)

        # Sort arguments according to their offset
        self.arguments.sort(lambda a, b: cmp(a.obj.offset, b.obj.offset))

    def isSuccess(self):
        """Check if this syscall was successful."""
        v = ctypes.c_int32(self.obj.retval)
        return v >= 0

    def isGUI(self):
        """Check if this is a GUI (i.e., win32k.sys) system call."""
        return self.obj.sysno > 4095

    def dump(self, dumpallocation=False):
        """Return a string representing this system call object."""
        s = ("==== Syscall no. %d (0x%.8x, %s) ====\n" %
             (self.obj.id, self.obj.sysno, self.name))
        s += ("  process: pid = 0x%.8x, tid = 0x%.8x, name = %s\n"  %
              (self.obj.process.pid, self.obj.process.tid,
               self.obj.process.name))
        s += "  return value: 0x%.8x (def [%d])\n" % (
            self.obj.retval, self.obj.taintlabel_retval)
        s += "  external references (%d):\n" % len(self.extrefs)
        for i in range(len(self.extrefs)):
            extref = self.extrefs[i]
            s += ("   ref #%d: pc %.8x, addr %.8x, value %.8x\n" %
                  (i, extref.pc, extref.addr, extref.value))

        for i in range(len(self.arguments)):
            s += self.arguments[i].dump(i, dumpallocation=dumpallocation)
        return s

    def getTaintUses(self):
        """Return a sorted list of taint labels _used_ by this system call."""
        labels = set()
        for i in range(len(self.arguments)):
            labels |= self.arguments[i].getTaintUses()
        labels = list(labels)
        labels.sort()
        return labels

    def getTaintDefs(self):
        """Return a sorted list of taint labels defined by this system call."""
        labels = set([self.obj.taintlabel_retval])
        for i in range(len(self.arguments)):
            labels |= self.arguments[i].getTaintDefs()
        labels = list(labels)
        labels.sort()
        return labels

    def execute(self, defs=None):
        """
        Replay this system call on current system.

        Arguments:
        defs -- an optional dict that maps taint labels to their current value
        """
        if platform.system() == "Windows":
            executor = runtime.winsyscall
        elif platform.system() == "Linux":
            executor = runtime.linsyscall
        else:
            raise Exception("No runtime for platform %s" % platform.system())

        params = []
        for i in range(len(self.arguments)):
            arg = self.arguments[i]
            argbuf = arg.allocate()

            if defs is not None:
                if len(arg.getTaintUses() & set(defs.keys())) > 0:
                    worklist = [arg, ]
                    while len(worklist) > 0:
                        x = worklist.pop()

                        for label in x.taintlabels_in:
                            if label not in defs:
                                continue

                            value_old, value_new = defs[label]
                            assert len(value_old) == len(value_new)

                            # Patch the argument value

                            # FIXME: at the moment, we don't keep track of the
                            # "taint offset" for this label. Thus, we must
                            # guess which value in the input buffer is actually
                            # tainted.
                            assert x.allocation is not None

                            if x.allocation.raw.count(value_old) != 1:
                                logging.warning(
                                    "Argument has %d occurrences "
                                    "of tainted value '%s'",
                                    x.allocation.raw.count(value_old),
                                    value_old.encode("hex"))
                                continue

                            # Apply the patch
                            offset = x.allocation.raw.find(value_old)
                            for i in range(len(value_new)):
                                x.allocation[offset+i] = value_new[i]

                        for ptr in x.pointers:
                            worklist.append(ptr)

            addr = ctypes.cast(argbuf, ctypes.POINTER(ctypes.c_uint))[0]
            param = ctypes.cast(addr, ctypes.POINTER(ctypes.c_uint))
            params.append(param)

        retval = executor.execute_syscall(self.obj.sysno, *params)
        return retval & 0xffffffff

    def visitArguments(self, callback, root=None, idz=0):
        """
        Visit syscall arguments, invoking a callback for each of them.

        This method implements a post-order traversal.
        """
        if root is None:
            subargs = self.arguments
        else:
            subargs = root.pointers

        for arg in subargs:
            idz = self.visitArguments(callback, arg, idz)

        if root is not None:
            callback(root, idz)
            idz += 1

        return idz

    def findArgument(self, needle, root=None, idz=0):
        """Find an argument, given its post-order traversal ID."""
        if root is None:
            subargs = self.arguments
        else:
            subargs = root.pointers

        for arg in subargs:
            r, idz = self.findArgument(needle, arg, idz)
            if r is not None:
                return r, idz

        if root is not None:
            if idz == needle:
                return root, idz
            idz += 1

        return None, idz

class SyscallArgument(object):
    """A system call argument."""
    def __init__(self, obj):
        self.obj = obj
        self.allocation = None

        self.pointers = []
        for ptrobj in self.obj.ptr:
            ptr = SyscallArgument(ptrobj)
            self.pointers.append(ptr)

        # Sort pointers according to their offset
        self.pointers.sort(lambda a, b: cmp(a.obj.offset, b.obj.offset))

        # Collapse input/output data intervals
        self.indata = collapse_intervals(self.obj.indata)
        self.outdata = collapse_intervals(self.obj.outdata)

        # Process taint labels
        self.taintlabels_in = set(self.obj.taintlabels_in)
        self.taintlabels_out = set(self.obj.taintlabels_out)

    def allocate(self):

        """
        Allocate a system call argument, returning its memory address.

        This method also takes care of allocating sub-arguments.
        """

        # Force re-allocation
        # if self.allocation is None:
        if True:
            data = self.indata

            intsize = struct.calcsize("P")
            # Allocate sub-arguments and fixup data pointers
            for ptr in self.pointers:
                argbuf = ptr.allocate()
                addr = ctypes.addressof(argbuf)
                offset = ptr.obj.offset

                # Sanity check
                oldvalue = struct.unpack("P", data[offset:offset+intsize])[0]
                assert ptr.obj.addr == oldvalue

                # Update the parameter address
                newvalue = struct.pack("P", addr)
                data = data[:offset] + newvalue + data[offset+intsize:]

            # If needed, allocate some more space where the syscall can write to
            # when it is executed
            size = max(len(self.outdata), len(data))
            self.allocation = ctypes.c_buffer(data, size)

        return self.allocation

    @staticmethod
    def stringifyData(data):
        """Stringify argument data, trying to guess the correct data type."""
        # Ascii
        if (len(data) > 1 and all([0 < ord(x) < 128 for x in data[:-1]])):
            r = 'ascii(%s)' % repr(data)
            return r

        # Unicode
        if len(data) > 1 and (len(data) % 2) == 0:
            values = set([data[i+1] for i in
                          range(0, len(data), 2)])
        else:
            values = set()

        if len(data) > 4 and len(values) == 1 and values.pop() == "\x00":
            # Raw data
            unicodedata = "".join([data[i] for i in
                                   range(0, len(data), 2)])
        else:
            unicodedata = ""

        # Consider as unicode only printable strings, with length > 0
        if (len(unicodedata) > 0 and
            len([c for c in unicodedata if c not in string.printable]) == 0):
            r = 'unicode(%s)' % repr(unicodedata)
        else:
            # Unicode string
            r = data.encode("hex")

        return r

    def getTaintUses(self):
        """Return a set of taint labels _used_ by this syscall argument."""
        labels = set(self.taintlabels_in)
        for i in range(len(self.pointers)):
            labels |= self.pointers[i].getTaintUses()
        return labels

    def getTaintDefs(self):
        """Return a set of taint labels _defined_ by this syscall argument."""
        labels = set(self.taintlabels_out)
        for i in range(len(self.pointers)):
            labels |= self.pointers[i].getTaintDefs()
        return labels

    def getDirectionName(self):
        """Return a string representing the direction of this argument."""

        if self.obj.direction == trace.syscall_pb2.SyscallArg.IN:
            name = "IN"
        elif self.obj.direction == trace.syscall_pb2.SyscallArg.OUT:
            name = "OUT"
        elif self.obj.direction == trace.syscall_pb2.SyscallArg.INOUT:
            name = "IN/OUT"
        else:
            assert False, "Unknown direction"

        return name

    def getSize(self):
        """Return the size of this argument."""
        return max(len(self.indata), len(self.outdata))

    def dump(self, num, indent=0, dumpallocation=False):
        """
        Return a string representation for this argument.

        This method should not be called directly: it should only be invoked by
        Syscall.dump().

        Arguments:
        num -- ordinal number of this argument
        indent -- number of indentation spaces
        dumpallocation -- whether we should also dump allocated buffers (debug)
        """

        arg = self.obj

        indata = SyscallArgument.stringifyData(self.indata)
        outdata = SyscallArgument.stringifyData(self.outdata)

        inout = self.getDirectionName()

        if not dumpallocation:
            s = ("arg #%d @0x%.8x (%s), off %d, size %d, indata %s, "
                 "outdata %s" %
                 (num, arg.addr, inout, arg.offset, self.getSize(),
                  indata, outdata))
        else:
            if self.allocation is None:
                self.allocate()

            s = ("arg #%d @0x%.8x (%s), off %d, size %d, "
                 "data %s" %
                 (num, ctypes.addressof(self.allocation), inout, arg.offset,
                  self.getSize(), self.allocation.raw.encode("hex")))

        # Add taint labels
        if len(self.taintlabels_out) > 0:
            labels = list(self.taintlabels_out)
            labels.sort()
            s += ", def %s" % labels

        if len(self.taintlabels_in) > 0:
            labels = list(self.taintlabels_in)
            labels.sort()
            s += ", use %s" % labels

        # Add repeated accesses
        if len(self.obj.rep_read) > 0:
            t = ""
            for read in self.obj.rep_read:
                if read.addr == 0x4:
                    continue
                rep_str = ", ".join(["%x" % x for x in read.pc])
                t += " 0x%x (sz %d, [%s])" % (read.addr, read.size, rep_str)
            if t != "":
                s += ", rep" + t


        # Add indentation and EOL
        s = "%s%s\n" % (" "*((indent+1)*2), s)

        for i in range(len(self.pointers)):
            s += self.pointers[i].dump(i, indent + 1,
                                       dumpallocation=dumpallocation)

        return s
