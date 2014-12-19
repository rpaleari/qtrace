"""
Copyright 2014, Roberto Paleari (@rpaleari)

GraphViz output module for generating syscall dependency graphs.
"""

import os
import graph
import output

class DotOutputGenerator(output.OutputGenerator):
    def __init__(self, stream):
        output.OutputGenerator.__init__(self, stream)

        # Dependency graph
        self.__graph = graph.Graph()

        # Trace nodes by execution ID
        self.__nodes = {}

    def _prologue(self):
        currentdir = os.path.dirname(os.path.realpath(__file__))
        imgfile = os.path.join(currentdir, "italy.png")
        if os.path.isfile(imgfile):
            img = '<TR><TD WIDTH="25" HEIGHT="17" FIXEDSIZE="true">'
            img += '<IMG SRC="%s"/>' % imgfile
            img += '</TD></TR>'
        else:
            img = ""

        s = """\
digraph "qtrace" {
labelloc="t";
label=<
  <TABLE BORDER="0" CELLPADDING="0">
    <TR><TD><FONT POINT-SIZE="30">QTrace syscall dependency graph</FONT></TD></TR>
    <TR><TD>Author: @rpaleari</TD></TR>
    <TR><TD>Made in Italy</TD></TR>
    %s
  </TABLE>
>;
rankdir=LR;
ranksep=2;
ratio=auto;
""" % img
        return s

    def _epilogue(self):
        s = ""

        # Create nodes
        for node in self.__graph:
            if not node.hasSuccessors() and not node.hasPredecessors():
                continue
            s += self.__generateNode(node)

        # Add links
        for pre in self.__graph:
            for suc in pre.getSuccessors():
                label = self.__graph.getEdgeLabel(pre, suc)
                if label is not None:
                    label = ' [label="%s"]' % label
                else:
                    label = ""

                s += '"%s" -> "%s"%s;\n' % \
                     (self.__getNodeName(suc), self.__getNodeName(pre), label)

        s += "}"
        return s

    def _visitHeader(self, header):
        return ""

    def _visitArgument(self, sysno, argpath, arg):
        pass

    def _visitSyscall(self, s):
        name = s.name
        if name is None:
            name == hex(s.sysno)

        n = self.__graph.getNodeByID(s.sysno)
        if n is None:
            n = graph.Node(name, s.sysno)
            if s.isGUI():
                color = "#b3cde3"
            else:
                color = "white"
            n.setAttribute("color", color)
            n.setAttribute("count", 1)
            self.__graph.addNode(n)
        else:
            count = n.getAttribute("count")
            n.setAttribute("count", count + 1)

        assert s.idz not in self.__nodes
        self.__nodes[s.idz] = n

        for taintlabel in set(s.getTaintUses()):
            defobj = self.getSyscallFromLabel(taintlabel)
            assert defobj is not None

            d = self.__nodes[defobj.idz]
            if d is not None:
                edgelabel = self.__graph.getEdgeLabel(d, n)
                if edgelabel is None:
                    edgelabel = 1
                else:
                    edgelabel += 1

                self.__graph.link(d, n, edgelabel)

        # Nothing to write at the moment
        return ""

    def __generateNode(self, node):
        label = "%s | count: %d" % (node.getValue(), node.getAttribute("count"))

        s = '"%s" [label="%s", shape=record, style=filled, ' \
            'fillcolor="%s"];\n' % \
            (self.__getNodeName(node), label, node.getAttribute("color"))

        return s

    def __getNodeName(self, node):
        return "n%s" % node.getID()
