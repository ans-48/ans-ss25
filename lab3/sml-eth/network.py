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

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 """

from lib import config # do not import anything before this
from p4app import P4Mininet
from mininet.topo import Topo
from mininet.cli import CLI
import os

NUM_WORKERS = 2

class SMLTopo(Topo):
    def __init__(self, num_workers, **opts):
        Topo.__init__(self, **opts)
        
        switch = self.addSwitch('s1')

        for i in range(num_workers):
            mac = f'00:00:00:00:00:{i+1:02x}'
            host = self.addHost(f'w{i}', mac=mac)
            self.addLink(host, switch, port2=i)

def RunWorkers(net):
    """
    Starts the workers and waits for their completion.
    """
    worker = lambda rank: "w%i" % rank
    log_file = lambda rank: os.path.join(os.environ['APP_LOGS'], "%s.log" % worker(rank))
    
    for i in range(NUM_WORKERS):
        cmd = f'python worker.py {i} > {log_file(i)} 2>&1'
        net.get(worker(i)).sendCmd(cmd)
    
    for i in range(NUM_WORKERS):
        net.get(worker(i)).waitOutput()

def RunControlPlane(net):
    """
    One-time control plane configuration.
    Here, we set up the multicast group for broadcasting results.
    """
    sw_controller = net.get('s1')
    worker_ports = list(range(NUM_WORKERS))
    mc_group_id = 1

    # CORRECTED: The multicast group ID is the first positional argument,
    # and the ports are passed via the 'ports' keyword argument.
    sw_controller.addMulticastGroup(mc_group_id, ports=worker_ports)
    
    print(f"Configured multicast group {mc_group_id} on s1 with ports: {worker_ports}")


topo = SMLTopo(num_workers=NUM_WORKERS)
net = P4Mininet(program="p4/main.p4", topo=topo)
net.run_control_plane = lambda: RunControlPlane(net)
net.run_workers = lambda: RunWorkers(net)
net.start()
net.run_control_plane()
CLI(net)
net.stop()