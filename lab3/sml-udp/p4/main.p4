/*
Copyright (c) 2025 Computer Networks Group @ UPB
*/
#include <core.p4>
#include <v1model.p4>

#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP  0x0806
#define IP_PROTOCOL_UDP 17
#define UDP_PORT_SML 12345

#define VIRTUAL_MAC 0x00000000AABB
#define VIRTUAL_IP  0x0a0000ff

#define NUM_WORKERS 2
#define CHUNK_SIZE  4
#define MAX_CHUNKS  1024

typedef bit<9>  sw_port_t;
typedef bit<48> mac_addr_t;
typedef bit<32> ip4_addr_t;

header ethernet_t {
  mac_addr_t dst_addr;
  mac_addr_t src_addr;
  bit<16>    ether_type;
}

header ipv4_t {
  bit<4>  version; bit<4>  ihl; bit<8>  diffserv; bit<16> totalLen;
  bit<16> identification; bit<3>  flags; bit<13> fragOffset;
  bit<8>  ttl; bit<8>  protocol; bit<16> hdrChecksum;
  ip4_addr_t srcAddr; ip4_addr_t dstAddr;
}

header udp_t {
  bit<16> srcPort; bit<16> dstPort; bit<16> length; bit<16> checksum;
}

header arp_t {
    bit<16> hw_type; bit<16> proto_type; bit<8>  hw_addr_len; bit<8>  proto_addr_len;
    bit<16> opcode; mac_addr_t src_hw_addr; ip4_addr_t  src_proto_addr;
    mac_addr_t dst_hw_addr; ip4_addr_t  dst_proto_addr;
}

header sml_t {
  bit<8>  rank; bit<16> chunk_id;
  bit<32> data_0; bit<32> data_1; bit<32> data_2; bit<32> data_3;
}

struct headers {
  ethernet_t eth; arp_t arp; ipv4_t ipv4; udp_t udp; sml_t sml;
}

struct metadata { }

register<bit<32>>(CHUNK_SIZE * MAX_CHUNKS) aggregation_reg;
register<bit<32>>(MAX_CHUNKS) counter_reg;

parser TheParser(packet_in packet, out headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    state start { packet.extract(hdr.eth); transition select(hdr.eth.ether_type) { ETHERTYPE_IPV4: parse_ipv4; ETHERTYPE_ARP: parse_arp; default: accept; } }
    state parse_arp { packet.extract(hdr.arp); transition accept; }
    state parse_ipv4 { packet.extract(hdr.ipv4); transition select(hdr.ipv4.protocol) { IP_PROTOCOL_UDP: parse_udp; default: accept; } }
    state parse_udp { packet.extract(hdr.udp); transition select(hdr.udp.dstPort) { UDP_PORT_SML: parse_sml; default: accept; } }
    state parse_sml { packet.extract(hdr.sml); transition accept; }
}

control TheIngress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {
    action process_locally() { }

    table l2_fwd_table {
        key = { hdr.eth.dst_addr: exact; }
        actions = { process_locally; }
        size = 1;
    }

    action arp_reply(mac_addr_t mac_addr) {
        hdr.eth.dst_addr = hdr.eth.src_addr; hdr.eth.src_addr = mac_addr;
        hdr.arp.opcode = 2; hdr.arp.dst_hw_addr = hdr.arp.src_hw_addr;
        hdr.arp.dst_proto_addr = hdr.arp.src_proto_addr; hdr.arp.src_hw_addr = mac_addr;
        hdr.arp.src_proto_addr = hdr.arp.dst_proto_addr;
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table arp_table {
        key = { hdr.arp.dst_proto_addr: exact; }
        actions = { arp_reply; }
        size = 1;
    }

    bit<32> current_sum_0; bit<32> current_sum_1; bit<32> current_sum_2; bit<32> current_sum_3;
    bit<32> current_count;

    apply {
        l2_fwd_table.apply();

        if (hdr.arp.isValid() && hdr.arp.opcode == 1) {
            arp_table.apply();
        }
        else if (hdr.sml.isValid()) {
    bit<32> chunk_index = (bit<32>) hdr.sml.chunk_id;
    bit<32> base_index = chunk_index * CHUNK_SIZE;

    @atomic {
        counter_reg.read(current_count, chunk_index);
        aggregation_reg.read(current_sum_0, base_index + 0);
        aggregation_reg.read(current_sum_1, base_index + 1);
        aggregation_reg.read(current_sum_2, base_index + 2);
        aggregation_reg.read(current_sum_3, base_index + 3);

        current_count = current_count + 1;
        current_sum_0 = current_sum_0 + hdr.sml.data_0;
        current_sum_1 = current_sum_1 + hdr.sml.data_1;
        current_sum_2 = current_sum_2 + hdr.sml.data_2;
        current_sum_3 = current_sum_3 + hdr.sml.data_3;

        if (current_count < NUM_WORKERS) {
            counter_reg.write(chunk_index, current_count);
            aggregation_reg.write(base_index + 0, current_sum_0);
            aggregation_reg.write(base_index + 1, current_sum_1);
            aggregation_reg.write(base_index + 2, current_sum_2);
            aggregation_reg.write(base_index + 3, current_sum_3);
            mark_to_drop(standard_metadata);
        } else {
            hdr.sml.data_0 = current_sum_0;
            hdr.sml.data_1 = current_sum_1;
            hdr.sml.data_2 = current_sum_2;
            hdr.sml.data_3 = current_sum_3;

            hdr.eth.dst_addr = 0xFFFFFFFFFFFF;
            hdr.eth.src_addr = VIRTUAL_MAC;
            standard_metadata.mcast_grp = 1;

            counter_reg.write(chunk_index, 0);
            aggregation_reg.write(base_index + 0, 0);
            aggregation_reg.write(base_index + 1, 0);
            aggregation_reg.write(base_index + 2, 0);
            aggregation_reg.write(base_index + 3, 0);
        }
    }
}

    }
}

control TheEgress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { apply {} }
control TheChecksumVerification(inout headers hdr, inout metadata meta) { apply {} }
control TheChecksumComputation(inout headers  hdr, inout metadata meta) { apply {} }
control TheDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        packet.emit(hdr.arp);
        packet.emit(hdr.ipv4);
        packet.emit(hdr.udp);
        packet.emit(hdr.sml);
    }
}

V1Switch(
    TheParser(),
    TheChecksumVerification(),
    TheIngress(),
    TheEgress(),
    TheChecksumComputation(),
    TheDeparser()
) main;
