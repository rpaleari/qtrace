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

    def __generateFlags(self, sysobj):
        ff = []
        if sysobj.isSuccess():
            ff.append('<span title="Success" class="flagSuccess">S</span>')
        else:
            ff.append('<span title="Failed" class="flagFail">F</span>')

        if len(sysobj.getTaintUses()) > 0:
            ff.append('<span title="Tainted" class="flagTaint">T</span>')
        else:
            ff.append('<span class="flagEmpty">X</span>')

        if sysobj.sysno > 4095:
            # win32k system call
            ff.append('<span title="GUI" class="flagGUI">G</span>')
        else:
            ff.append('<span class="flagEmpty">X</span>')

        return " ".join(ff)

    def _visitSyscall(self, s):
        # Compute HTML flags for this system call
        htmlflags = self.__generateFlags(s)

        h = '<div id="sys%d" class="syscall">\n' % s.idz

        h += """\
<div>
  <span class="comment">[%05d]</span>&nbsp;
  <span class="syshead" onclick="javascript:showSyscallBody(%d)">%s %s</span>&nbsp;
  <span class="comment">(sysid: 0x%.4x, arguments: %d)</span>
</div>
""" % (s.idz, s.idz, htmlflags, s.name, s.sysno, len(s.arguments))

        h += """\
<div class="sysbody">
  <table class="syssummary">
    <tr>
        <th>Process</th><td>PID 0x%04x, TID 0x%04x, name %s</td>
    </tr>
    <tr>
        <th>Retval</th>
        <td>0x%08x <span class="comment">(taint label %d)</span></td>
    </tr>
  </table>
"""  % (s.process_pid, s.process_tid, s.process_name,
        s.retval, s.taintlabel_retval)

        h += '<table class="sysargs">\n'

        # Write table header
        h += '<tr>'
        for colname in ("#", "Address", "Direction", "Size", "Offset",
                        "Uses", "Defs", "Input", "Output"):
            h += "<th>%s</th>" % colname
        h += '</tr>'

        # Recursively visit sub-arguments
        for i in range(len(s.arguments)):
            arg = s.arguments[i]
            argpath = (i, )
            h += self._visitArgument(s.sysno, argpath, arg)

        h += "</table>\n"
        h += "</div>\n"
        h += "</div>\n"
        return h

    def _visitArgument(self, sysno, argpath, arg):
        indata = self.__generateData(arg.indata)
        outdata = self.__generateData(arg.outdata)
        argno = ".".join(["%d" % x for x in argpath])

        s = '<tr id="arg%d_%s">' % (sysno, argno.replace(".", "_"))

        # Argument number
        s += '<td style="text-align:left;">%s</td>' % argno

        # Address
        s += '<td>0x%08x</td>' % arg.addr

        # Direction, size & offset
        s += '<td>%s</td><td>%d</td><td>%d</td>' % (arg.getDirectionName(),
                                                    arg.getSize(), arg.offset)

        # Taint labels (uses and defs)
        s += "<td>%s</td><td>%s</td>" % (self.__generateTaintUses(arg),
                                         self.__generateTaintDefs(arg))

        # Input and output data
        s += "<td>%s</td><td>%s</td>" % (indata, outdata)

        s += "</tr>\n"

        for i in range(len(arg.pointers)):
            subarg = arg.pointers[i]
            subpath = argpath + (i, )
            s += self._visitArgument(sysno, subpath, subarg)

        return s

    def __generateTaintUses(self, arg):
        """
        Generate HTML code to represent the taint labels _used_ by system call
        argument "arg".
        """

        tainthtml = []
        for label in arg.getTaintUses():
            # Get the system call that defined this label
            defobj = self.getSyscallFromLabel(label)
            assert defobj is not None

            data = '<span class="taint" title="Goto syscall #%d" ' \
                   'onclick="javascript:gotoSyscall(%d);">%d</span>' % \
                (defobj.idz, defobj.idz, label)
            tainthtml.append(data)
        return ", ".join(tainthtml)

    def __generateTaintDefs(self, arg):
        """
        Generate HTML code to represent the taint labels _defined_ by system call
        argument "arg".
        """

        tainthtml = []
        for label in arg.getTaintDefs():
            data = '<span class="taint">%d</span>' % label
            tainthtml.append(data)
        return ", ".join(tainthtml)

    def __generateData(self, data):
        """
        Translate a syscall argument data buffer to an HTML string.
        """
        htmldata = trace.syscall.SyscallArgument.stringifyData(data)
        if len(htmldata) > 128:
            htmldata = htmldata[:128] + "..."
        return htmldata
