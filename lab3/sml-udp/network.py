"""
 Copyright (c) 2025 Computer Networks Group @ UPB
 """

from lib import config # do not import anything before this
from p4app import P4Mininet
from mininet.topo import Topo
from mininet.cli import CLI
import os

NUM_WORKERS = 2

SWITCHML_IP = '10.0.0.255'
SWITCHML_MAC = '00:00:00:00:AA:BB'

class SMLTopo(Topo):
    def __init__(self, **opts):
        num_workers = opts.pop('num_workers', NUM_WORKERS)
        Topo.__init__(self, **opts)
        
        switch = self.addSwitch('s1')
        for i in range(num_workers):
            ip = f'10.0.0.{i+1}/24'
            mac = f'00:00:00:00:00:{i+1:02x}'
            host = self.addHost(f'w{i}', ip=ip, mac=mac)
            self.addLink(host, switch, port2=i)

def RunWorkers(net):
    worker = lambda rank: "w%i" % rank
    log_file = lambda rank: os.path.join(os.environ['APP_LOGS'], "%s.log" % worker(rank))
    for i in range(NUM_WORKERS):
        net.get(worker(i)).sendCmd(f'python worker.py {i} > {log_file(i)} 2>&1')
    for i in range(NUM_WORKERS):
        net.get(worker(i)).waitOutput()

def RunControlPlane(net):
    sw_controller = net.get('s1')
    worker_ports = list(range(NUM_WORKERS))
    mc_group_id = 1
    sw_controller.addMulticastGroup(mc_group_id, ports=worker_ports)
    sw_controller.insertTableEntry(
        table_name="TheIngress.arp_table",
        match_fields={"hdr.arp.dst_proto_addr": [SWITCHML_IP]},
        action_name="TheIngress.arp_reply",
        action_params={"mac_addr": SWITCHML_MAC}
    )

topo = SMLTopo(num_workers=NUM_WORKERS)
net = P4Mininet(program="p4/main.p4", topo=topo)
net.run_control_plane = lambda: RunControlPlane(net)
net.run_workers = lambda: RunWorkers(net)
net.start()
net.run_control_plane()

# --- THIS IS THE CRITICAL FIX ---
# Disable IPv6 on all host interfaces to prevent interference
print("Disabling IPv6 on worker interfaces...")
for i in range(NUM_WORKERS):
    host = net.get(f'w{i}')
    host.cmd(f'sysctl -w net.ipv6.conf.{host.intf().name}.disable_ipv6=1')

# Statically populate host ARP caches
print("Statically populating ARP caches on hosts...")
for i in range(NUM_WORKERS):
    host = net.get(f'w{i}')
    host.cmd(f'arp -s {SWITCHML_IP} {SWITCHML_MAC}')

CLI(net)
net.stop()