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
	
	def remove(self):
		self.lnode.edges.remove(self)
		self.rnode.edges.remove(self)
		self.lnode = None
		self.rnode = None

# Class for a node in the graph
class Node:
	def __init__(self, id, type):
		self.edges = []
		self.id = id
		self.type = type

	# Add an edge connected to another node
	def add_edge(self, node):
		edge = Edge()
		edge.lnode = self
		edge.rnode = node
		self.edges.append(edge)
		node.edges.append(edge)
		return edge

	# Remove an edge from the node
	def remove_edge(self, edge):
		self.edges.remove(edge)

	# Decide if another node is a neighbor
	def is_neighbor(self, node):
		for edge in self.edges:
			if edge.lnode == node or edge.rnode == node:
				return True
		return False


class Fattree:

	def __init__(self, num_ports):
		self.servers = []
		self.switches = []
		self.generate(num_ports)

	def generate(self, num_ports):

		# TODO: code for generating the fat-tree topology
		if num_ports % 2 != 0: raise ValueError("number of ports (k) must be even for fat-tree topology.")

		self.core_switches = []
		self.aggregation_switches = [[] for _ in range(num_ports)]
		self.edge_switches = [[] for _ in range(num_ports)]
		self.switches = []
		self.servers = []

		def node_id(prefix, *indices): return f"{prefix}{''.join(map(str, indices))}"

		# create core switches
		for i in range(num_ports // 2):
			for j in range(num_ports // 2):
				switch = Node(id=node_id("cs", i, j), type="core")
				self.core_switches.append(switch)
				self.switches.append(switch)

		# create aggregation and edge switches per pod
		for pod in range(num_ports):
			agg_switches = []; edge_switches = []

			for i in range(num_ports // 2):
				switch = Node(id=node_id("as", pod, i), type="aggregation")
				agg_switches.append(switch)
				self.switches.append(switch)

			for i in range(num_ports // 2):
				switch = Node(id=node_id("es", pod, i), type="edge")
				edge_switches.append(switch)
				self.switches.append(switch)

			self.aggregation_switches[pod] = agg_switches
			self.edge_switches[pod] = edge_switches

		# create servers to edge switches
		for pod in range(num_ports):
			for edge_idx, edge_switch in enumerate(self.edge_switches[pod]):
				for i in range(num_ports // 2):
					server = Node(id=node_id("h", pod, edge_idx, i), type="host")
					self.servers.append(server)
					edge_switch.add_edge(server)

		# connect edge switches to aggregation switches within the same pod
		for pod in range(num_ports):
			for edge_switch in self.edge_switches[pod]:
				for agg_switch in self.aggregation_switches[pod]:
					edge_switch.add_edge(agg_switch)

		# connect aggregation switches to core switches
		for pod in range(num_ports):
			for agg_index, agg_switch in enumerate(self.aggregation_switches[pod]):
				for group in range(num_ports // 2):
					core_index = group * (num_ports // 2) + agg_index
					agg_switch.add_edge(self.core_switches[core_index])


def test_basic_structure(fat_tree, k):
	expected_core = (k // 2) ** 2
	expected_agg = k * (k // 2)
	expected_edge = k * (k // 2)
	expected_hosts = k * (k // 2) * (k // 2)

	actual_core = len(fat_tree.core_switches)
	actual_agg = sum(len(pod) for pod in fat_tree.aggregation_switches)
	actual_edge = sum(len(pod) for pod in fat_tree.edge_switches)
	actual_hosts = len(fat_tree.servers)

	assert actual_core == expected_core, f"core switches count mismatch: expected {expected_core}, got {actual_core}"
	assert actual_agg == expected_agg, f"aggregation switches count mismatch: expected {expected_agg}, got {actual_agg}"
	assert actual_edge == expected_edge, f"edge switches count mismatch: expected {expected_edge}, got {actual_edge}"
	assert actual_hosts == expected_hosts, f"hosts count mismatch: expected {expected_hosts}, got {actual_hosts}"

	print("basic structure test passed!")

def test_core_connections(fat_tree, k):
	for _, core in enumerate(fat_tree.core_switches):
		connected_agg_switches = [n for edge in core.edges for n in [edge.lnode, edge.rnode] if n != core]
		assert len(connected_agg_switches) == k, f"core switch {core.id} has {len(connected_agg_switches)} connections, expected {k}"

	print("core switch connection test passed!")

def test_aggregation_connections(fat_tree, k):
	for pod in range(k):
		for agg in fat_tree.aggregation_switches[pod]:
			connected_nodes = [n for edge in agg.edges for n in [edge.lnode, edge.rnode] if n != agg]
			assert len(connected_nodes) == k, f"aggregation switch {agg.id} has {len(connected_nodes)} connections, expected {k}"

			edge_neighbors = [n for n in connected_nodes if n.type == "edge"]
			core_neighbors = [n for n in connected_nodes if n.type == "core"]

			assert len(edge_neighbors) == k // 2, f"{agg.id} has {len(edge_neighbors)} edge neighbors, expected {k//2}"
			assert len(core_neighbors) == k // 2, f"{agg.id} has {len(core_neighbors)} core neighbors, expected {k//2}"

	print("aggregation switch connection test passed!")

def test_edge_switch_connections(fat_tree, k):
	for pod in range(k):
		for edge in fat_tree.edge_switches[pod]:
			connected_nodes = [n for edge_obj in edge.edges for n in [edge_obj.lnode, edge_obj.rnode] if n != edge]
			assert len(connected_nodes) == k, f"edge switch {edge.id} has {len(connected_nodes)} connections, expected {k}"

			host_neighbors = [n for n in connected_nodes if n.type == "host"]
			assert len(host_neighbors) == k // 2, f"{edge.id} has {len(host_neighbors)} host neighbors, expected {k//2}"

			agg_neighbors = [n for n in connected_nodes if n.type == "aggregation"]
			assert len(agg_neighbors) == k // 2, f"{edge.id} has {len(agg_neighbors)} aggregation neighbors, expected {k//2}"

	print("edge switch connection test passed!")

def test_host_connection(fat_tree):
	for host in fat_tree.servers:
		assert len(host.edges) == 1, f"host {host.id} has {len(host.edges)} connections, expected 1"

		connected_switch = host.edges[0].lnode if host.edges[0].rnode == host else host.edges[0].rnode
		assert connected_switch.type == "edge", f"host {host.id} is not connected to an edge switch, connected to {connected_switch.type}"

	print("host connection test passed!")

def test_pod_structure(fat_tree, k):
	for pod in range(k):
		agg_switches = fat_tree.aggregation_switches[pod]
		edge_switches = fat_tree.edge_switches[pod]

		# check edge switch connections
		for edge in edge_switches:
			for edge_conn in edge.edges:
				other = edge_conn.lnode if edge_conn.rnode == edge else edge_conn.rnode
				if other.type == "host":
					assert other.id.startswith(f"h{pod}_"), f"host {other.id} connected to edge switch {edge.id} in wrong pod"
				elif other.type == "aggregation":
					assert other in agg_switches, f"edge switch {edge.id} connected to aggregation switch {other.id} from another pod"
				else:
					assert False, f"edge switch {edge.id} connected to invalid type {other.type}"

		# check aggregation switch connections
		for agg in agg_switches:
			for agg_conn in agg.edges:
				other = agg_conn.lnode if agg_conn.rnode == agg else agg_conn.rnode
				if other.type == "edge":
					assert other in edge_switches, f"aggregation switch {agg.id} connected to edge switch {other.id} from another pod"
				elif other.type == "core":
					pass
				else:
					assert False, f"aggregation switch {agg.id} connected to invalid type {other.type}"

	print("pod structure test passed!")

def test_edge_symmetry_and_host_connections(fat_tree):
	# check symmetric edges
	for node in fat_tree.servers + fat_tree.switches:
		for edge in node.edges:
			other = edge.lnode if edge.rnode == node else edge.rnode
			assert edge in other.edges, f"edge inconsistency: {node.id} has edge to {other.id}, but not vice versa"

	# check host connection rules
	for host in fat_tree.servers:
		assert len(host.edges) == 1, f"host {host.id} has {len(host.edges)} connections, expected 1"
		switch = host.edges[0].lnode if host.edges[0].rnode == host else host.edges[0].rnode
		assert switch.type == "edge", f"host {host.id} is connected to {switch.type} {switch.id}, should be edge switch"

	print("edge symmetry and host connection tests passed!")

# k = 4
# fat_tree = Fattree(k)
# test_basic_structure(fat_tree, k)
# test_core_connections(fat_tree, k)
# test_aggregation_connections(fat_tree, k)
# test_edge_switch_connections(fat_tree, k)
# test_host_connection(fat_tree)
# test_pod_structure(fat_tree, k)
# test_edge_symmetry_and_host_connections(fat_tree)
