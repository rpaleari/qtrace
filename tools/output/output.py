"""
Copyright 2014, Roberto Paleari (@rpaleari)

Abstract class for QTrace output modules.
"""

import abc

import trace.reader
import trace.syscall

class OutputGenerator(object):
    __metaclass__ = abc.ABCMeta

    def __init__(self, stream):
        self.__stream = stream
        self.__stream.write(self._prologue())

        # Taint label to system call object map
        self.__taintmap = {}

    def __del__(self):
        self.__stream.write(self._epilogue())

    @abc.abstractmethod
    def _visitHeader(self, obj):
        pass

    @abc.abstractmethod
    def _visitSyscall(self, obj):
        pass

    @abc.abstractmethod
    def _visitArgument(self, argno, obj):
        pass

    @abc.abstractmethod
    def _prologue(self):
        pass

    @abc.abstractmethod
    def _epilogue(self):
        pass

    def getSyscallFromLabel(self, label):
        """
        Return the system call object that defines taint label "label", or None if
        not found.
        """
        return self.__taintmap.get(label, None)

    def __updateTaintMap(self, sysobj):
        """
        Update the taint labels map, associating labels defined by system call
        object "sysobj" with the object itself.
        """
        outlabels = [sysobj.taintlabel_retval, ]
        outlabels.extend(sysobj.getTaintDefs())
        for label in outlabels:
            defobj = self.__taintmap.get(label, None)
            assert defobj is None or defobj.idz == sysobj.idz
            self.__taintmap[label] = sysobj

    def visit(self, obj):
        t = type(obj)
        if t == trace.reader.TraceHeader:
            s = self._visitHeader(obj)
        elif t == trace.syscall.Syscall:
            self.__updateTaintMap(obj)
            s = self._visitSyscall(obj)
        else:
            assert False, "Unexpected object: %s" % t
        self.__stream.write(s)
