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
from scapy.all import Packet, IntField
from lib.comm import send, receive

import socket
import struct
import time

NUM_ITER   = 1
CHUNK_SIZE = 4
UDP_PORT = 9999
RESULT_PORT_BASE = 8888

class SwitchML(Packet):
    name = "SwitchMLPacket"
    fields_desc = [
        IntField("rank", 0),
        IntField("payload0", 0),
        IntField("payload1", 0),
        IntField("payload2", 0),
        IntField("payload3", 0)
    ]

def AllReduce(soc, rank, data, result):
    """
    Perform in-network all-reduce over UDP

    :param str    soc: the socket used for all-reduce
    :param int   rank: the worker's rank
    :param [int] data: the input vector for this worker
    :param [int]  res: the output vector
    """
    switch_ip = "10.0.0.100"
    
    chunks = [data[i:i + CHUNK_SIZE] for i in range(0, len(data), CHUNK_SIZE)]
    Log(f"Processing {len(chunks)} chunks ({len(data)} elements total)")
    
    MAX_RETRIES = 3
    
    for chunk_idx, chunk in enumerate(chunks):
        padded = chunk + [0] * (CHUNK_SIZE - len(chunk))
        
        sml_packet = SwitchML(
            rank=rank,
            payload0=padded[0],
            payload1=padded[1],
            payload2=padded[2],
            payload3=padded[3]
        )
        
        success = False
        for attempt in range(1, MAX_RETRIES + 1):
            sml_bytes = bytes(sml_packet)
            
            if chunk_idx == 0 or chunk_idx % 50 == 0:
                Log(f"Sending chunk {chunk_idx} (attempt {attempt}) to {switch_ip}: [{padded[0]}, {padded[1]}, {padded[2]}, {padded[3]}]")
            
            send(soc, sml_bytes, (switch_ip, UDP_PORT))
            
            try:
                soc.settimeout(3.0)
                data_recv, addr = receive(soc, 1024)
                
                if len(data_recv) >= 20:
                    sml_data = struct.unpack('>IIIII', data_recv[:20])
                    chunk_results = [sml_data[1], sml_data[2], sml_data[3], sml_data[4]]
                    
                    start_idx = chunk_idx * CHUNK_SIZE
                    for i in range(CHUNK_SIZE):
                        if start_idx + i < len(result):
                            result[start_idx + i] = chunk_results[i]
                    
                    if chunk_idx == 0 or chunk_idx % 50 == 0:
                        Log(f"Received chunk {chunk_idx}: [{chunk_results[0]}, {chunk_results[1]}, {chunk_results[2]}, {chunk_results[3]}]")
                    
                    success = True
                    break
                else:
                    Log(f"Error: Received packet too small ({len(data_recv)} bytes)")
                    
            except socket.timeout:
                if attempt < MAX_RETRIES:
                    Log(f"Timeout for chunk {chunk_idx} (attempt {attempt}), retrying...")
                    time.sleep(0.1)
                else:
                    Log(f"Error: Timeout for chunk {chunk_idx} after {MAX_RETRIES} attempts")
            except Exception as e:
                Log(f"Error receiving chunk {chunk_idx}: {e}")
        
        if not success:
            Log(f"FAIL: Could not process chunk {chunk_idx}")
            raise RuntimeError(f"AllReduce failed for chunk {chunk_idx}")
        
        time.sleep(0.01)
    
    Log(f"AllReduce complete: processed {len(chunks)} chunks successfully")

def main():
    rank = GetRankOrExit()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    
    my_ip = ip()
    my_port = RESULT_PORT_BASE + rank
    s.bind((my_ip, my_port))
    Log(f"Worker {rank} bound to {my_ip}:{my_port} for receiving results")

    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(2, 2048, 2 * CHUNK_SIZE)
        data_out = GenInts(num_elem)
        data_in = GenInts(num_elem, 0)
        CreateTestData("udp-iter-%d" % i, rank, data_out)
        AllReduce(s, rank, data_out, data_in)
        RunIntTest("udp-iter-%d" % i, rank, data_in, True)
    
    s.close()
    Log("Done")

if __name__ == '__main__':
    main()