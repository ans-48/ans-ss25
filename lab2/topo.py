"""
 Copyright (c) 2025 Computer Networks Group @ UPB

 Permission is hereby granted, free of charge, to any person obtaining a copy of
 this software and associated documentation files (the "Software"), to deal in
 the Software without restriction, including without limitation the rights to
 use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of
 the Software, and to permit persons to whom the Software is furnished to do so,
 subject to the following conditions:

 The above copyright notice and this permission notice shall be included in all
 copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

# Class for an edge in the graph
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

def test_node_counts(k):
    ft = Fattree(k)
    expected_hosts = (k ** 3) // 4
    expected_core = (k // 2) ** 2
    expected_edge = k * (k // 2)
    expected_agg = k * (k // 2)

    print(f"Hosts: {len(ft.servers)} / expected {expected_hosts}")
    print(f"Switches: {len(ft.switches)} / expected {expected_core + expected_edge + expected_agg}")

def test_node_degrees(k):
    ft = Fattree(k)
    for host in ft.servers:
        print(f"{host.id} degree: {len(host.edges)} (should be 1)")
    for switch in ft.switches:
        print(f"{switch.id} degree: {len(switch.edges)} (should be {k})")

test_node_counts(4)
test_node_degrees(4)
