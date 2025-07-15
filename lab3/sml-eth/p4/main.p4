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

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS
 FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR
 COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
 IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include <core.p4>
#include <v1model.p4>

#define NUM_WORKERS 2
#define CHUNK_SIZE  4
#define ETHERTYPE_SML 0x88B5

typedef bit<9>  sw_port_t;
typedef bit<48> mac_addr_t;

header ethernet_t {
    mac_addr_t dst_addr;
    mac_addr_t src_addr;
    bit<16>    ether_type;
}

header sml_t {
    bit<8>  rank;
    bit<16> chunk_id;
    bit<32> data_0;
    bit<32> data_1;
    bit<32> data_2;
    bit<32> data_3;
}

struct headers {
    ethernet_t eth;
    sml_t      sml;
}

struct metadata { /* empty */ }

register<bit<32>>(CHUNK_SIZE) aggregation_reg;
register<bit<32>>(1) counter_reg;

parser TheParser(packet_in packet,
                 out headers hdr,
                 inout metadata meta,
                 inout standard_metadata_t standard_metadata) {
    state start {
        packet.extract(hdr.eth);
        transition select(hdr.eth.ether_type) {
            ETHERTYPE_SML: parse_sml;
            default: accept;
        }
    }
    state parse_sml {
        packet.extract(hdr.sml);
        transition accept;
    }
}

control TheIngress(inout headers hdr,
                   inout metadata meta,
                   inout standard_metadata_t standard_metadata) {

    bit<32> current_sum_0;
    bit<32> current_sum_1;
    bit<32> current_sum_2;
    bit<32> current_sum_3;
    bit<32> current_count;

    apply {
        if (hdr.sml.isValid()) {
            @atomic {
                counter_reg.read(current_count, 0);
                aggregation_reg.read(current_sum_0, 0);
                aggregation_reg.read(current_sum_1, 1);
                aggregation_reg.read(current_sum_2, 2);
                aggregation_reg.read(current_sum_3, 3);

                current_count = current_count + 1;
                current_sum_0 = current_sum_0 + hdr.sml.data_0;
                current_sum_1 = current_sum_1 + hdr.sml.data_1;
                current_sum_2 = current_sum_2 + hdr.sml.data_2;
                current_sum_3 = current_sum_3 + hdr.sml.data_3;

                if (current_count < NUM_WORKERS) {
                    counter_reg.write(0, current_count);
                    aggregation_reg.write(0, current_sum_0);
                    aggregation_reg.write(1, current_sum_1);
                    aggregation_reg.write(2, current_sum_2);
                    aggregation_reg.write(3, current_sum_3);
                    mark_to_drop(standard_metadata);
                } else {
                    hdr.sml.data_0 = current_sum_0;
                    hdr.sml.data_1 = current_sum_1;
                    hdr.sml.data_2 = current_sum_2;
                    hdr.sml.data_3 = current_sum_3;

                    standard_metadata.mcast_grp = 1;

                    counter_reg.write(0, 0);
                    aggregation_reg.write(0, 0);
                    aggregation_reg.write(1, 0);
                    aggregation_reg.write(2, 0);
                    aggregation_reg.write(3, 0);
                }
            }
        }
    }
}

control TheEgress(inout headers hdr,
                  inout metadata meta,
                  inout standard_metadata_t standard_metadata) {
    apply {}
}

control TheChecksumVerification(inout headers hdr, inout metadata meta) {
    apply {}
}

control TheChecksumComputation(inout headers  hdr, inout metadata meta) {
    apply {}
}

control TheDeparser(packet_out packet, in headers hdr) {
    apply {
        packet.emit(hdr.eth);
        // CORRECTED: Removed the 'if' statement.
        // The V1Model architecture ensures that emit() on an invalid
        // header does nothing, so this is functionally equivalent and
        // satisfies the compiler.
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