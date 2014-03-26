"""
Copyright 2014, Roberto Paleari (@rpaleari)

Classes for representing directed graphs.
"""

class Graph(object):
    def __init__(self):
        self.__nodes = {}
        self.__labels = {}

    def __len__(self):
        return len(self.__nodes)

    def __iter__(self):
        for node in self.__nodes.itervalues():
            yield node

    def link(self, pre, suc, label=None):
        pre.addSuccessor(suc)
        suc.addPredecessor(pre)
        if label is not None:
            self.__labels[(pre.getID(), suc.getID())] = label

    def getEdgeLabel(self, pre, suc):
        """
        Return the label of graph edge that connects nodes (pre, suc), if any.
        """
        key = (pre.getID(), suc.getID())
        return self.__labels.get(key, None)

    def addNode(self, node):
        assert isinstance(node, Node)
        idz = node.getID()
        if idz not in self.__nodes:
            self.__nodes[idz] = node

    def hasNode(self, node):
        return node.getID() in self.__nodes

    def getNodeByID(self, idz):
        return self.__nodes.get(idz, None)

class Node(object):
    def __init__(self, value, idz):
        self.__value = value
        self.__idz = idz
        self.__suc = set()
        self.__pre = set()
        self.__attr = {}

    def __str__(self):
        s = "Node %d, label '%s', %d successors, %d predecessors" % \
            (self.__idz, self.__value, len(self.__suc), len(self.__pre))
        return s

    def __eq__(self, other):
        return hash(self.__idz) == hash(other.getID())

    def __hash__(self):
        return hash(self.__idz)

    def addSuccessor(self, node):
        if node not in self.__suc:
            self.__suc.add(node)

    def addPredecessor(self, node):
        if node not in self.__pre:
            self.__pre.add(node)

    def hasSuccessors(self):
        return len(self.__suc) > 0

    def hasPredecessors(self):
        return len(self.__pre) > 0

    def getSuccessors(self):
        for node in self.__suc:
            yield node

    def getPredecessors(self):
        for node in self.__pre:
            yield node

    def getValue(self):
        return self.__value

    def getID(self):
        return self.__idz

    def setAttribute(self, name, value):
        self.__attr[name] = value

    def getAttribute(self, name):
        return self.__attr.get(name)
