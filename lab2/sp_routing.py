import heapq
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.topology import event

class SPRouter(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SPRouter, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.adjacency = {}
        self.mac_to_port = {}
        self.ip_to_mac = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.adjacency.setdefault(dp.id, {})
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(
            dp.ofproto.OFPP_CONTROLLER, dp.ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, match, actions)
        self.logger.info("[%d] switch ready", dp.id)

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        l = ev.link
        # Ensure both ends of the link are in the adjacency map
        self.adjacency.setdefault(l.src.dpid, {})
        self.adjacency.setdefault(l.dst.dpid, {})
        self.adjacency[l.src.dpid][l.dst.dpid] = l.src.port_no
        self.adjacency[l.dst.dpid][l.src.dpid] = l.dst.port_no
        total = sum(len(v) for v in self.adjacency.values()) // 2
        self.logger.info("link %s<->%s ports %s<->%s total=%d",
                         l.src.dpid, l.dst.dpid, l.src.port_no, l.dst.port_no, total)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth or eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(msg, dp, in_port, eth, arp_pkt)
            return

        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self._handle_ipv4(msg, dp, in_port, eth, ipv4_pkt)
            return

    def _handle_arp(self, msg, dp, in_port, eth, arp_pkt):
        # Learn the host's location from any ARP packet
        uplinks = set(self.adjacency.get(dp.id, {}).values())
        if in_port not in uplinks:
            if eth.src not in self.mac_to_port or self.mac_to_port[eth.src] != (dp.id, in_port):
                self.mac_to_port[eth.src] = (dp.id, in_port)
                self.ip_to_mac[arp_pkt.src_ip] = eth.src
                self.logger.info("[%d] Learned HOST %s (%s) on port %d",
                                 dp.id, eth.src, arp_pkt.src_ip, in_port)
        
        # Process the ARP packet
        if arp_pkt.opcode == arp.ARP_REQUEST:
            if arp_pkt.dst_ip in self.ip_to_mac:
                # If we know the destination, send a unicast reply (Proxy ARP)
                self._send_arp_reply(eth, arp_pkt)
            else:
                # If destination is unknown, perform a controlled edge broadcast
                # only if the request came from a host.
                if in_port not in uplinks:
                    self._edge_broadcast_arp(msg)

        elif arp_pkt.opcode == arp.ARP_REPLY:
            if eth.dst in self.mac_to_port:
                # Forward known ARP replies to the correct host
                self._forward_unicast(msg, eth.dst)

    def _handle_ipv4(self, msg, dp, in_port, eth, ipv4_pkt):
        # Learn host location from IP packets as well
        uplinks = set(self.adjacency.get(dp.id, {}).values())
        if in_port not in uplinks:
            if eth.src not in self.mac_to_port or self.mac_to_port[eth.src] != (dp.id, in_port):
                self.mac_to_port[eth.src] = (dp.id, in_port)
                self.ip_to_mac[ipv4_pkt.src] = eth.src
                self.logger.info("[%d] Learned HOST %s (%s) on port %d",
                                 dp.id, eth.src, ipv4_pkt.src, in_port)
        
        # If we know the destination MAC, find a path and install flows
        if eth.dst in self.mac_to_port:
            src_dpid = dp.id
            dst_dpid, _ = self.mac_to_port[eth.dst]
            path = self._dijkstra(src_dpid, dst_dpid)

            if path:
                self.logger.info("path %s->%s = %s", src_dpid, dst_dpid, path)
                self._install_path(path, ipv4_pkt.dst)
                # Install reverse path as well
                self._install_path(list(reversed(path)), ipv4_pkt.src)
                # Send the buffered packet along the new path
                self._send_packet_out(self.datapaths[path[0]], msg, path)
            else:
                self.logger.warning("No path found from %d to %d", src_dpid, dst_dpid)
        else:
            # If destination MAC is unknown, treat like an unknown ARP
            # and send to all edge ports to trigger ARP from the destination.
            if in_port not in uplinks:
                 self._edge_broadcast_arp(msg)

    def _edge_broadcast_arp(self, orig_msg):
        """
        Sends an ARP request out of all host-facing ports on all edge switches,
        except for the port it originally came in on.
        """
        self.logger.info("Initiating controlled edge broadcast...")
        original_dp_id = orig_msg.datapath.id
        original_in_port = orig_msg.match['in_port']

        # Iterate through all known switches
        for dpid, dp in self.datapaths.items():
            # Get all ports on the switch and subtract the uplink ports
            all_ports_on_switch = set(dp.ports.keys())
            uplink_ports = set(self.adjacency.get(dpid, {}).values())
            host_ports = all_ports_on_switch - uplink_ports

            # Send the packet out of each host-facing port
            for port in host_ports:
                if dpid == original_dp_id and port == original_in_port:
                    continue # Don't send back to original sender

                actions = [dp.ofproto_parser.OFPActionOutput(port)]
                out = dp.ofproto_parser.OFPPacketOut(
                    datapath=dp,
                    buffer_id=0xffffffff,  # Do not use buffer
                    in_port=dp.ofproto.OFPP_CONTROLLER,
                    actions=actions,
                    data=orig_msg.data)
                dp.send_msg(out)

    def _forward_unicast(self, msg, dst_mac):
        """Forwards a message to a single, known destination port."""
        dpid, port = self.mac_to_port[dst_mac]
        dp = self.datapaths[dpid]
        actions = [dp.ofproto_parser.OFPActionOutput(port)]
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'], actions=actions, data=msg.data)
        dp.send_msg(out)

    def _send_arp_reply(self, eth, arp_pkt):
        req_mac = eth.src
        if req_mac not in self.mac_to_port: return
        
        dpid, port = self.mac_to_port[req_mac]
        dp = self.datapaths[dpid]
        src_mac = self.ip_to_mac[arp_pkt.dst_ip]
        
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dst=req_mac, src=src_mac, ethertype=ether_types.ETH_TYPE_ARP))
        pkt.add_protocol(arp.arp(opcode=arp.ARP_REPLY, src_mac=src_mac, src_ip=arp_pkt.dst_ip, dst_mac=req_mac, dst_ip=arp_pkt.src_ip))
        pkt.serialize()

        actions = [dp.ofproto_parser.OFPActionOutput(port)]
        out = dp.ofproto_parser.OFPPacketOut(
            datapath=dp, buffer_id=0xffffffff,
            in_port=dp.ofproto.OFPP_CONTROLLER, actions=actions, data=pkt.data)
        dp.send_msg(out)

    def _dijkstra(self, src, dst):
        if src not in self.datapaths or dst not in self.datapaths: return None
        dist = {d: float('inf') for d in self.datapaths}
        prev = {d: None for d in self.datapaths}
        dist[src] = 0
        pq = [(0, src)]
        while pq:
            d, u = heapq.heappop(pq)
            if u == dst: break
            if d > dist[u]: continue
            for v in self.adjacency.get(u, {}):
                if v not in self.datapaths: continue
                nd = d + 1
                if nd < dist[v]:
                    dist[v] = nd
                    prev[v] = u
                    heapq.heappush(pq, (nd, v))
        if dist.get(dst, float('inf')) == float('inf'): return None
        
        path = []
        curr = dst
        while curr is not None:
            path.insert(0, curr)
            curr = prev.get(curr)
        return path if path and path[0] == src else None

    def _install_path(self, path, ip_dst):
        if not path: return
        if ip_dst not in self.ip_to_mac: return
        
        dst_mac = self.ip_to_mac[ip_dst]
        if dst_mac not in self.mac_to_port: return

        for i, dpid in enumerate(path):
            dp = self.datapaths[dpid]
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_dst=ip_dst)
            
            if i < len(path) - 1:
                next_dpid = path[i+1]
                port = self.adjacency[dpid][next_dpid]
            else:
                _, port = self.mac_to_port[dst_mac]
            
            actions = [parser.OFPActionOutput(port)]
            self.add_flow(dp, 1, match, actions)

    def _send_packet_out(self, dp, msg, path):
        pkt = packet.Packet(msg.data)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if not ipv4_pkt or ipv4_pkt.dst not in self.ip_to_mac: return
        
        parser = dp.ofproto_parser
        if len(path) > 1:
            port = self.adjacency[path[0]][path[1]]
        else:
            dst_mac = self.ip_to_mac[ipv4_pkt.dst]
            _, port = self.mac_to_port[dst_mac]

        actions = [parser.OFPActionOutput(port)]
        out = parser.OFPPacketOut(
            datapath=dp, buffer_id=msg.buffer_id,
            in_port=msg.match['in_port'], actions=actions, data=msg.data)
        dp.send_msg(out)

    def add_flow(self, dp, priority, match, actions):
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=dp, priority=priority, match=match, instructions=inst)
        dp.send_msg(mod)
        