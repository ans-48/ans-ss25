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

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
from scapy.all import Packet, Ether, srp1, bind_layers, ByteField, ShortField, IntField, FieldListField, get_if_hwaddr

NUM_ITER   = 1
CHUNK_SIZE = 4 # Each packet will carry 4 integers

# Define a constant for our custom EtherType
ETHERTYPE_SWITCHML = 0x88B5

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        ByteField("rank", 0),
        ShortField("chunk_id", 0),
        # A list of integers, the size of which is determined by CHUNK_SIZE
        FieldListField("data", None, IntField("value", 0), count_from=lambda pkt: CHUNK_SIZE)
    ]

# Bind our custom layer to the Ether layer using our custom EtherType
bind_layers(Ether, SwitchML, type=ETHERTYPE_SWITCHML)

def AllReduce(iface, rank, data, result):
    """
    Perform in-network all-reduce over ethernet

    :param str  iface: the ethernet interface used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector (this will be populated)

    This function is blocking, i.e. only returns with a result or error
    """
    mac = get_if_hwaddr(iface)
    num_elements = len(data)
    chunk_id_counter = 0

    for i in range(0, num_elements, CHUNK_SIZE):
        chunk_to_send = data[i : i + CHUNK_SIZE]

        # Craft the packet. The destination MAC is broadcast so the switch receives it.
        # The switch is the only device that should understand our custom EtherType.
        pkt = Ether(dst='ff:ff:ff:ff:ff:ff', src=mac, type=ETHERTYPE_SWITCHML) / \
              SwitchML(rank=rank, chunk_id=chunk_id_counter, data=chunk_to_send)

        # Send the packet and wait for a single response
        response = srp1(pkt, iface=iface, timeout=5, verbose=False)

        if response and response.haslayer(SwitchML):
            # Extract the aggregated data from the response packet
            aggregated_chunk = response[SwitchML].data
            # Place the aggregated result into the correct slice of the output vector
            result[i : i + CHUNK_SIZE] = aggregated_chunk
        else:
            Log(f"Error: No response received for chunk {chunk_id_counter}")
            # For Level 1, we can just error out. Level 3 will handle this.
            return

        chunk_id_counter += 1

def main():
    iface = 'eth0'
    rank = GetRankOrExit()
    Log("Started...")
    for i in range(NUM_ITER):
        # Generate a vector length that is a multiple of CHUNK_SIZE
        num_elem = GenMultipleOfInRange(CHUNK_SIZE, 2048, CHUNK_SIZE)
        data_out = GenInts(num_elem)
        data_in = [0] * num_elem # Initialize result vector with zeros
        CreateTestData("eth-iter-%d" % i, rank, data_out)
        AllReduce(iface, rank, data_out, data_in)
        RunIntTest("eth-iter-%d" % i, rank, data_in, True)
    Log("Done")

if __name__ == '__main__':
    main()