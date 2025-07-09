"""
 Copyright (c) 2025 Computer Networks Group @ UPB
"""

from lib.gen import GenInts, GenMultipleOfInRange
from lib.test import CreateTestData, RunIntTest
from lib.worker import *
import socket
import struct
from lib.comm import send, receive

NUM_ITER   = 1
CHUNK_SIZE = 4

SWITCHML_IP = '10.0.0.255'
SWITCHML_PORT = 12345

def AllReduce(soc, rank, data, result):
    header_format = f"!BH{CHUNK_SIZE}I"
    num_elements = len(data)
    chunk_id_counter = 0

    for i in range(0, num_elements, CHUNK_SIZE):
        chunk_to_send = data[i : i + CHUNK_SIZE]
        payload = struct.pack(header_format, rank, chunk_id_counter, *chunk_to_send)

        # ✅ Fix: change argument order to match comm.py's send(soc, data, addr)
        send(soc, payload, (SWITCHML_IP, SWITCHML_PORT))

        response_payload, addr = receive(soc, 4096)  # make sure to pass buffer size

        if response_payload:
            response_tuple = struct.unpack(header_format, response_payload)
            aggregated_chunk = response_tuple[2:]
            result[i : i + CHUNK_SIZE] = aggregated_chunk
        else:
            Log(f"Error: No response received for chunk {chunk_id_counter}")
            return

        chunk_id_counter += 1

def main():
    rank = GetRankOrExit()

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.settimeout(2)  # Optional: prevent blocking forever
    s.bind(('0.0.0.0', SWITCHML_PORT))

    Log("Started...")
    for i in range(NUM_ITER):
        num_elem = GenMultipleOfInRange(CHUNK_SIZE, 2048, CHUNK_SIZE)
        data_out = GenInts(num_elem)
        data_in = [0] * num_elem
        CreateTestData("udp-iter-%d" % i, rank, data_out)
        AllReduce(s, rank, data_out, data_in)
        RunIntTest("udp-iter-%d" % i, rank, data_in, True)

    s.close()
    Log("Done")

if __name__ == '__main__':
    main()
