# fat-tree.py
#!/usr/bin/env python3

import mininet.clean
from mininet.net import Mininet
from mininet.cli import CLI
from mininet.log import info, setLogLevel
from mininet.node import RemoteController
from mininet.topo import Topo
from mininet.link import TCLink

from topo import Fattree

class FattreeNet(Topo):
    def __init__(self, ft):
        super(FattreeNet, self).__init__()
        self.node_map = {}
        dpidc  = 1

        # hosts
        for srv in ft.servers:
            parts = srv.id[1:].split('_')
            if len(parts) != 4:
                raise ValueError(f"invalid host ID format: {srv.id}")

            pod = int(parts[1]); edge = int(parts[2]); host = int(parts[3])
            name = srv.id.replace('_','')
            ip   = f"10.{pod}.{edge}.{host+2}"
            self.node_map[srv.id] = self.addHost(name, ip=ip)
            print(f"{name} -> {ip}")

        # switches
        for sw in ft.switches:
            name = sw.id.replace('_','')
            dpid = f"{dpidc:016x}"
            self.node_map[sw.id] = self.addSwitch(name, dpid=dpid)
            dpidc += 1

        # links
        seen = set()
        for n in ft.switches + ft.servers:
            for e in n.edges:
                if e in seen:
                    continue
                seen.add(e)
                n1 = self.node_map[e.lnode.id]
                n2 = self.node_map[e.rnode.id]
                self.addLink(n1, n2, bw=15, delay='5ms')

def run(ft):
    topo = FattreeNet(ft)
    net = Mininet(topo=topo,
                  controller=None,
                  autoSetMacs=True,
                  link=TCLink)
    net.addController('c0', RemoteController, ip="127.0.0.1", port=6653)
    info('*** Starting network ***\n')
    net.start()
    info('*** Starting CLI ***\n')
    CLI(net)
    info('*** Stopping network ***\n')
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    ft = Fattree(4)
    run(ft)
