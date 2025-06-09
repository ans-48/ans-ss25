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

#!/usr/bin/env python3

import os
import subprocess
import time

import mininet
import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import lg, info
from mininet.link import TCLink
from mininet.node import Node, OVSKernelSwitch, RemoteController
from mininet.topo import Topo
from mininet.util import waitListening, custom

from topo import Fattree


class FattreeNet(Topo):
    """
    Create a fat-tree network in Mininet
    """

    def __init__(self, ft_topo):

        Topo.__init__(self)

        # TODO: please complete the network generation logic here
        self.node_map = {}

        for node in ft_topo.servers:
            parts = node.id[1:].split('_')
            if len(parts) != 3:
                raise ValueError(f"invalid host ID format: {node.id}")

            pod = int(parts[0]); edge = int(parts[1]); host = int(parts[2])
            mn_name = f"h{pod}{edge}{host}"
            self.node_map[node.id] = mn_name

            ip_addr = f"10.{pod}.{edge}.{host+2}"
            print(f"{mn_name} -> {ip_addr}")
            self.addHost(mn_name, ip=ip_addr)

        for node in ft_topo.switches:
            parts = node.id[2:].split('_')
            if len(parts) != 2:
                raise ValueError(f"invalid switch ID format: {node.id}")
            mn_name = f"{node.id[0:2]}{parts[0]}{parts[1]}"
            self.node_map[node.id] = mn_name
            self.addSwitch(mn_name)

        processed_edges = set()

        for node in ft_topo.switches + ft_topo.servers:
            for edge in node.edges:
                if edge in processed_edges:
                    continue
                processed_edges.add(edge)

                node1 = self.node_map[edge.lnode.id]
                node2 = self.node_map[edge.rnode.id]
                self.addLink(node1, node2, bw=15, delay='5ms')

def make_mininet_instance(graph_topo):

    net_topo = FattreeNet(graph_topo)
    net = Mininet(topo=net_topo, controller=None, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip="127.0.0.1", port=6653)
    return net


def run(graph_topo):

    # Run the Mininet CLI with a given topology
    lg.setLogLevel('info')
    mininet.clean.cleanup()
    net = make_mininet_instance(graph_topo)

    info('*** Starting network ***\n')
    net.start()
    info('*** Running CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()


if __name__ == '__main__':
    ft_topo = Fattree(4)
    run(ft_topo)
