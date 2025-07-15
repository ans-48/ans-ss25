/*
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
*/

#include <core.p4>
#include <v1model.p4>

// Define constants
#define CHUNK_SIZE 4
#define NUM_WORKERS 2
#define SML_UDP_PORT 9999
#define RESULT_PORT_BASE 8888
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806
#define IPPROTO_UDP 17

// ARP constants
#define ARP_HTYPE_ETHERNET 0x0001
#define ARP_PTYPE_IPV4 0x0800
#define ARP_HLEN_ETHERNET 6
#define ARP_PLEN_IPV4 4
#define ARP_OPER_REQUEST 1
#define ARP_OPER_REPLY 2

typedef bit<48> mac_addr_t;  /*< MAC address */
typedef bit<32> ip4_addr_t;  /*< IPv4 address */

header ethernet_t {
    mac_addr_t dstAddr;
    mac_addr_t srcAddr;
    bit<16>    etherType;
}

header ipv4_t {
    bit<4>     version;
    bit<4>     ihl;
    bit<8>     diffserv;
    bit<16>    totalLen;
    bit<16>    identification;
    bit<3>     flags;
    bit<13>    fragOffset;
    bit<8>     ttl;
    bit<8>     protocol;
    bit<16>    hdrChecksum;
    ip4_addr_t srcAddr;
    ip4_addr_t dstAddr;
}

header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length;
    bit<16> checksum;
}

header sml_t {
    bit<32> rank;
    bit<32> payload0;
    bit<32> payload1;
    bit<32> payload2;
    bit<32> payload3;
}

header arp_t {
    bit<16> htype;
    bit<16> ptype;
    bit<8>  hlen;
    bit<8>  plen;
    bit<16> oper;
    mac_addr_t sha;
    ip4_addr_t spa;
    mac_addr_t tha;
    ip4_addr_t tpa;
}

struct headers {
    ethernet_t eth;
    ipv4_t ipv4;
    udp_t udp;
    sml_t sml;
    arp_t arp;
}

struct metadata { 
    bit<32> packet_count; // Store counter value for completion check
}

parser TheParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    state start {
        transition parse_ethernet;
    }
    
    state parse_ethernet {
        packet.extract(hdr.eth);
        transition select(hdr.eth.etherType) {
            ETHERTYPE_IPV4: parse_ipv4;
            ETHERTYPE_ARP: parse_arp;
            default: accept;
        }
    }
    
    state parse_arp {
        packet.extract(hdr.arp);
        transition accept;
    }
    
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            IPPROTO_UDP: parse_udp;
            default: accept;
        }
    }
    
    state parse_udp {
        packet.extract(hdr.udp);
        transition select(hdr.udp.dstPort) {
            SML_UDP_PORT: parse_sml;
            default: accept;
        }
    }
    
    state parse_sml {
        packet.extract(hdr.sml);
        transition accept;
    }
}

// A control block to perform a single, atomic read-modify-write operation.
control AtomicAdd(register<bit<32>> reg,
                  in bit<32> index,
                  in bit<32> value_to_add) {
    apply {
        @atomic {
            // 1. Read the current value from the register at the given index.
            bit<32> current_val;
            reg.read(current_val, index);

            // 2. Write the new, modified value back to the same index in one operation.
            reg.write(index, current_val + value_to_add);
        }
    }
}

control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {
    
    // Instantiate the atomic control for thread-safe operations
    AtomicAdd() atomic_add_instance;
    
    // Registers for SwitchML aggregation
    register<bit<32>>(CHUNK_SIZE) aggregation_reg;  // Store aggregated sums for each payload
    register<bit<32>>(1) counter_reg;               // Count total packets received
    register<bit<32>>(NUM_WORKERS) worker_received; // Track which workers have sent data
    
    action drop() {
        mark_to_drop(standard_metadata);
    }

    action ipv4_forward(mac_addr_t dstAddr, bit<9> port) {
        // Set source MAC to previous destination
        hdr.eth.srcAddr = hdr.eth.dstAddr;
        // Set destination MAC from table match
        hdr.eth.dstAddr = dstAddr;
        // Set output port from table match
        standard_metadata.egress_spec = port;
        // Decrement TTL
        hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
    }

    action sml_process_new_worker() {
        // Mark this worker as having sent data
        bit<32> worker_rank = hdr.sml.rank;
        worker_received.write(worker_rank, 1);
    }
    
    action sml_send_result() {
        // Reset packet counter for next chunk
        counter_reg.write(0, 0);
        
        // Reset worker tracking for next chunk (unrolled for P4 compatibility)
        worker_received.write(0, 0);
        worker_received.write(1, 0);
        
        // Use multicast to send to all workers
        standard_metadata.mcast_grp = 1;
        
        // Set switch as source
        hdr.ipv4.srcAddr = 0x0a00000a;          // Switch IP (10.0.0.10)
        hdr.ipv4.dstAddr = 0x0a000001;          // Will be customized per worker in egress
        
        hdr.udp.srcPort = SML_UDP_PORT;
        hdr.udp.dstPort = 8888;                 // Will be customized per worker in egress
        
        // Set correct packet lengths
        hdr.udp.length = 28;                    // UDP header (8) + SML payload (20)
        hdr.udp.checksum = 0;                   // Disable UDP checksum
        hdr.ipv4.totalLen = 48;                 // IP header (20) + UDP (8) + SML (20)
    }
    
    action sml_process_duplicate() {
        drop();
    }

    action arp_reply() {
        // Reply to ARP request for switch IP (10.0.0.100)
        // Swap source and destination MAC addresses
        mac_addr_t tmp_mac = hdr.eth.srcAddr;
        hdr.eth.srcAddr = hdr.eth.dstAddr;
        hdr.eth.dstAddr = tmp_mac;
        
        // Save original requester's IP
        ip4_addr_t original_spa = hdr.arp.spa;
        
        // Set ARP reply fields
        hdr.arp.oper = ARP_OPER_REPLY;
        
        // Target becomes source (switch)
        hdr.arp.sha = 0x0000000001ff;  // Switch MAC
        hdr.arp.spa = 0x0a000064;      // Switch IP (10.0.0.100)
        
        // Source becomes target (requesting worker)
        hdr.arp.tha = tmp_mac;
        hdr.arp.tpa = original_spa;    // Original requester's IP becomes target
        
        // Send back to requesting port
        standard_metadata.egress_spec = standard_metadata.ingress_port;
    }

    table ipv4_lpm {
        key = {
            hdr.ipv4.dstAddr: lpm;
        }
        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }
        size = 1024;
        default_action = NoAction();
    }

    apply {
        if (hdr.arp.isValid()) {
            if (hdr.arp.oper == ARP_OPER_REQUEST && hdr.arp.tpa == 0x0a000064) {
                arp_reply();
            } else {
                drop();
            }
        } else if (hdr.sml.isValid()) {
            // Handle SML packets for in-network aggregation
            bit<32> worker_rank = hdr.sml.rank;
            bit<32> worker_already_sent;
            worker_received.read(worker_already_sent, worker_rank);
            
            if (worker_already_sent == 0) {
                // First packet from this worker - mark as received
                sml_process_new_worker();
                
                // Atomically add worker's data to aggregation for all 4 payload fields
                atomic_add_instance.apply(aggregation_reg, 0, hdr.sml.payload0);
                atomic_add_instance.apply(aggregation_reg, 1, hdr.sml.payload1);
                atomic_add_instance.apply(aggregation_reg, 2, hdr.sml.payload2);
                atomic_add_instance.apply(aggregation_reg, 3, hdr.sml.payload3);
                
                // Atomically increment packet counter and check completion
                @atomic {
                    bit<32> current_count;
                    counter_reg.read(current_count, 0);
                    counter_reg.write(0, current_count + 1);
                    meta.packet_count = current_count + 1;
                }
                
                if (meta.packet_count == NUM_WORKERS) {
                    // All workers have contributed - perform final aggregation
                    @atomic {
                        bit<32> current_val;
                        aggregation_reg.read(current_val, 0);
                        hdr.sml.payload0 = current_val;
                        aggregation_reg.write(0, 0);
                    }
                    @atomic {
                        bit<32> current_val;
                        aggregation_reg.read(current_val, 1);
                        hdr.sml.payload1 = current_val;
                        aggregation_reg.write(1, 0);
                    }
                    @atomic {
                        bit<32> current_val;
                        aggregation_reg.read(current_val, 2);
                        hdr.sml.payload2 = current_val;
                        aggregation_reg.write(2, 0);
                    }
                    @atomic {
                        bit<32> current_val;
                        aggregation_reg.read(current_val, 3);
                        hdr.sml.payload3 = current_val;
                        aggregation_reg.write(3, 0);
                    }
                    
                    // Send result to all workers
                    sml_send_result();
                } else {
                    // Still waiting for more workers
                    drop();
                }
            } else {
                // Duplicate packet from same worker
                sml_process_duplicate();
            }
        } else if (hdr.ipv4.isValid()) {
            ipv4_lpm.apply();
        }
    }
}

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply {
        // Customize multicast SML result packets for each worker
        if (hdr.sml.isValid()) {
            bit<32> worker_id = (bit<32>)standard_metadata.egress_port;
            
            // Calculate worker MAC: 00:00:00:00:00:0X where X = worker_id + 1
            bit<48> worker_mac = 0x000000000000 | (bit<48>)(worker_id + 1);
            
            // Calculate worker IP: 10.0.0.X where X = worker_id + 1  
            bit<32> worker_ip = 0x0a000000 | (worker_id + 1);
            
            // Calculate worker port: 8888 + worker_id
            bit<16> worker_port = (bit<16>)(8888 + worker_id);
            
            hdr.eth.srcAddr = 0x0000000001ff; // Switch MAC
            hdr.eth.dstAddr = worker_mac;
            hdr.ipv4.dstAddr = worker_ip;
            hdr.udp.dstPort = worker_port;
        }
    }
}

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
    apply { }
}

control TheChecksumComputation(inout headers hdr, inout metadata meta) {
    apply {
        update_checksum(
            hdr.ipv4.isValid(),
            { hdr.ipv4.version,
              hdr.ipv4.ihl,
              hdr.ipv4.diffserv,
              hdr.ipv4.totalLen,
              hdr.ipv4.identification,
              hdr.ipv4.flags,
              hdr.ipv4.fragOffset,
              hdr.ipv4.ttl,
              hdr.ipv4.protocol,
              hdr.ipv4.srcAddr,
              hdr.ipv4.dstAddr },
            hdr.ipv4.hdrChecksum,
            HashAlgorithm.csum16);
    }
}

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