# topo.py
#
# Copyright (c) 2025 Computer Networks Group @ UPB
#
class Edge:
    def __init__(self):
        self.lnode = None
        self.rnode = None

class Node:
    def __init__(self, id, type):
        self.edges = []
        self.id = id
        self.type = type

    def add_edge(self, node):
        edge = Edge()
        edge.lnode = self
        edge.rnode = node
        self.edges.append(edge)
        node.edges.append(edge)
        return edge

class Fattree:
    def __init__(self, num_ports):
        self.servers = []
        self.switches = []
        self.generate(num_ports)
        print(f"[topo] Generated fat-tree: k={num_ports}, "
              f"{len(self.servers)} hosts, {len(self.switches)} switches")

    def generate(self, num_ports):
        if num_ports % 2 != 0:
            raise ValueError("k must be even for fat-tree.")
        k = num_ports
        # Core
        core = [Node(f"cs_{i}_{j}", "core")
                for i in range(k//2) for j in range(k//2)]
        self.switches.extend(core)
        # Pods
        for p in range(k):
            aggs = [Node(f"as_{p}_{i}", "aggregation") for i in range(k//2)]
            edges = [Node(f"es_{p}_{i}", "edge")       for i in range(k//2)]
            self.switches.extend(aggs + edges)
            # edge↔agg
            for e in edges:
                for a in aggs:
                    e.add_edge(a)
            # edge↔hosts
            for ei, e in enumerate(edges):
                for h in range(k//2):
                    hn = Node(f"h_{p}_{ei}_{h}", "host")
                    self.servers.append(hn)
                    e.add_edge(hn)
            # agg↔core
            for ai, a in enumerate(aggs):
                for ci in range(k//2):
                    idx = ai*(k//2) + ci
                    a.add_edge(core[idx])
