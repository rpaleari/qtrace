"""
Copyright 2014, Roberto Paleari (@rpaleari)

Customizations to Python XMLRPC library.
"""

import syscall_pb2

def dump_qtrace_object(self, name, value, write):
    write("<value><%s>" % name)
    write(value.SerializeToString().encode("hex"))
    write("</%s></value>\n" % name)

def load_qtrace_object(self, objclass, data):
    data = data.decode("hex")
    obj = objclass()
    obj.ParseFromString(data)
    self.append(obj)
    self._value = 0

def dump_qtrace_syscall(self, value, write):
    dump_qtrace_object(self, "syscall", value, write)

def dump_qtrace_syscallarg(self, value, write):
    dump_qtrace_object(self, "syscallarg", value, write)

def load_qtrace_syscall(self, data):
    load_qtrace_object(self, syscall_pb2.Syscall, data)

def load_qtrace_syscallarg(self, data):
    load_qtrace_object(self, syscall_pb2.SyscallArg, data)

def customize(lib):
    lib.Marshaller.dispatch[syscall_pb2.Syscall]    = dump_qtrace_syscall
    lib.Marshaller.dispatch[syscall_pb2.SyscallArg] = dump_qtrace_syscallarg
    lib.Unmarshaller.dispatch["syscall"]    = load_qtrace_syscall
    lib.Unmarshaller.dispatch["syscallarg"] = load_qtrace_syscallarg
