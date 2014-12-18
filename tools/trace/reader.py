"""
Copyright 2014, Roberto Paleari (@rpaleari)

Reader for QTrace trace files.
"""

import datetime
import struct

import trace.syscall_pb2
from trace.syscall import Syscall

class TraceHeader(object):
    PROFILE_MAP = {
        # Windows
        trace.syscall_pb2.TraceHeader.ProfileWindowsXPSP0: "Windows XP SP0",
        trace.syscall_pb2.TraceHeader.ProfileWindowsXPSP1: "Windows XP SP1",
        trace.syscall_pb2.TraceHeader.ProfileWindowsXPSP2: "Windows XP SP2",
        trace.syscall_pb2.TraceHeader.ProfileWindowsXPSP3: "Windows XP SP3",
        trace.syscall_pb2.TraceHeader.ProfileWindows7SP0:  "Windows 7 SP0",

        # Linux
        trace.syscall_pb2.TraceHeader.ProfileLinux64_3_2_0:  "Linux 64-bit (3.2.0)",
        trace.syscall_pb2.TraceHeader.ProfileLinux64_3_14_0: "Linux 64-bit (3.14.0)",

        # OSx
        trace.syscall_pb2.TraceHeader.ProfileOSXMavericks: "MacOSX Mavericks (10.9.4)",
    }

    def __init__(self, obj):
        self.magic = obj.magic
        self.timestamp = datetime.datetime.fromtimestamp(obj.timestamp)
        self.profile = obj.targetos
        self.hastaint = obj.hastaint
        self.targetos = obj.targetos

    def getProfileName(self):
        return TraceHeader.PROFILE_MAP.get(self.profile, "Unknown")

    def __str__(self):
        s  = "==== Trace header ====\n"
        s += "  magic:   %.8x\n" % self.magic
        s += "  date:    %s\n" % self.timestamp
        s += "  profile: %s\n" % self.getProfileName()
        s += "  taint?   %s\n" % self.hastaint
        return s

class TraceReader(object):
    """
    A class to read syscall traces from input streams (e.g., from file).
    """

    def __init__(self, stream, streamlen):
        self.stream    = stream
        self.streamlen = streamlen
        self.names     = []

        # Read the trace header
        obj = trace.syscall_pb2.TraceHeader()
        data = self.stream.read(struct.calcsize("I"))
        self.headersize = struct.unpack("I", data)[0]
        data = self.stream.read(self.headersize)
        obj.ParseFromString(data)
        assert obj.magic == trace.syscall_pb2.TraceHeader.TRACE_MAGIC
        self.header = TraceHeader(obj)

    def __check_os_mask(self, m):
        return (self.header.targetos & m) == m

    def is_linux(self):
        return self.__check_os_mask(
            trace.syscall_pb2.TraceHeader.ProfileLinuxMask)

    def is_osx(self):
        return self.__check_os_mask(
            trace.syscall_pb2.TraceHeader.ProfileOSXMask)

    def set_syscall_names(self, names):
        self.names = names

    def __iter__(self):
        """
        Generate a sequence of Syscall objects from an input stream.
        """
        intsize = struct.calcsize("I")
        offset = self.headersize + intsize

        while offset < self.streamlen:
            data = self.stream.read(intsize)
            size = struct.unpack("I", data)[0]

            data = self.stream.read(size)
            offset += size + intsize

            obj = trace.syscall_pb2.Syscall()
            obj.ParseFromString(data)

            if obj.sysno in self.names:
                name = self.names[obj.sysno]
            else:
                name = None

            syscall = Syscall(obj, name)
            yield syscall
