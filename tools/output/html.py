"""
Copyright 2014, Roberto Paleari (@rpaleari)

HTML output module for displaying syscall traces.
"""

import os
import output
import trace.syscall

class HTMLOutputGenerator(output.OutputGenerator):
    HTML_CSSFILE = "htmloutput.css"
    HTML_JSFILE = "htmloutput.js"

    def __init__(self, stream):
        output.OutputGenerator.__init__(self, stream)

    def __getCopyright(self):
        s = """\
<p class="copyright">
  Copyright&copy; 2014, Roberto Paleari (<a target="#" href="http://twitter.com/rpaleari">@rpaleari</a>),
  Made in Italy <img alt="italy" src="data:image/svg+xml;base64,PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSIxNSIgaGVpZ2h0PSIxMCIgdmlld0JveD0iMCAwIDMgMiI+PHJlY3Qgd2lkdGg9IjEiIGhlaWdodD0iMiIgZmlsbD0iIzAwOTI0NiIvPjxyZWN0IHdpZHRoPSIxIiBoZWlnaHQ9IjIiIHg9IjEiIGZpbGw9IiNmZmYiLz48cmVjdCB3aWR0aD0iMSIgaGVpZ2h0PSIyIiB4PSIyIiBmaWxsPSIjY2UyYjM3Ii8+PC9zdmc+Cg==" />
</p>
"""
        return s

    def _prologue(self):
        p = os.path.dirname(os.path.realpath(__file__))
        cssdata = open(os.path.join(p, HTMLOutputGenerator.HTML_CSSFILE)).read()
        jsdata = open(os.path.join(p, HTMLOutputGenerator.HTML_JSFILE)).read()

        s = """\
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html>
  <head>
    <title>QTrace syscall trace</title>
    <script type="text/javascript">
%s
    </script>
    <style>
%s
    </style>
  </head>
  <body>
    %s
    <h1>QTrace trace file</h1>
""" % (jsdata, cssdata, self.__getCopyright())

        return s

    def _epilogue(self):
        s = """\
  </body>
</html>
"""
        return s

    def _visitHeader(self, header):
        s = """\
    <h2>Trace header</h2>
    <table id="header">
"""

        for name, value in (
                ("Magic",   "%.08x" % header.magic),
                ("Date",    header.timestamp),
                ("Profile", header.getProfileName()),
                ("Taint since boot?", header.hastaint),
        ):
            s += " "*6 + "<tr><th>%s</th><td>%s</td></tr>\n" % (name, value)

        s += """\
    </table>
    <h2>System calls</h2>
"""
        return s

    def __generateFlags(self, s):
        ff = []
        if s.isSuccess():
            ff.append('<span title="Success" class="flagSuccess">S</span>')
        else:
            ff.append('<span title="Failed" class="flagFail">F</span>')

        if len(s.getTaintLabels()) > 0:
            ff.append('<span title="Tainted" class="flagTaint">T</span>')
        else:
            ff.append('<span class="flagEmpty">X</span>')

        if s.obj.sysno > 4095:
            # win32k system call
            ff.append('<span title="GUI" class="flagGUI">G</span>')
        else:
            ff.append('<span class="flagEmpty">X</span>')

        return " ".join(ff)

    def _visitSyscall(self, s):
        # Compute HTML flags for this system call
        htmlflags = self.__generateFlags(s)

        h = '<div id="sys%d" class="syscall">\n' % s.obj.id

        h += """\
<div>
  <span class="comment">[%05d]</span>&nbsp;
  <span class="syshead" onclick="javascript:showSyscallBody(%d)">%s %s</span>&nbsp;
  <span class="comment">(sysid: 0x%.4x, arguments: %d)</span>
</div>
""" % (s.obj.id, s.obj.id, htmlflags, s.name, s.obj.sysno, len(s.arguments))

        h += """\
<div class="sysbody">
  <table class="syssummary">
    <tr><th>Process</th><td>PID 0x%04x, TID 0x%04x, name %s</td></tr>
    <tr><th>Retval</th><td>0x%08x</td></tr>
  </table>
"""  % (s.obj.process.pid, s.obj.process.tid, s.obj.process.name,
        s.obj.retval)

        h += """\
<table class="sysargs">
<tr><th>#</th><th>Address</th><th>Direction</th><th>Size</th><th>Offset</th><th>Taint</th><th>Input</th><th>Output</th></tr>
"""

        for i in range(len(s.arguments)):
            arg = s.arguments[i]
            argpath = (i, )
            h += self._visitArgument(s.obj.sysno, argpath, arg)

        h += "</table>\n"
        h += "</div>\n"
        h += "</div>\n"
        return h

    def _visitArgument(self, sysno, argpath, arg):
        tainthtml = []
        labels = list(arg.taintlabels)
        labels.sort()
        for label in labels:
            t = '<span class="taint" onclick="javascript:gotoSyscall(%d);">%d</span>' % \
                (label, label)
            tainthtml.append(t)
        tainthtml = ", ".join(tainthtml)

        indata  = trace.syscall.SyscallArgument.stringifyData(arg.indata)
        outdata = trace.syscall.SyscallArgument.stringifyData(arg.outdata)
        argno = ".".join(["%d" % x for x in argpath])

        s = """<tr id="arg%d_%s"><td style="text-align: left;">%s</td><td>0x%08x</td><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td><td>%s</td></tr>\n""" % \
            (sysno, argno.replace(".", "_"),
             argno, arg.obj.addr, arg.getDirectionName(),
             arg.getSize(), arg.obj.offset, tainthtml,
             indata, outdata)

        for i in range(len(arg.pointers)):
            subarg = arg.pointers[i]
            subpath = argpath + (i, )
            s += self._visitArgument(sysno, subpath, subarg)

        return s
