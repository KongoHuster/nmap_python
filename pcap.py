from scapy.all import *
from scapy.utils import PcapReader
import socket
import io
import struct


def analysis(pcap_path):
    file = open(pcap_path, 'rb')
    file_length = int(file.seek(0, io.SEEK_END))
    file.seek(24)
    header = 24
    tcp_stream = []
    while header < file_length:
        file.seek(8, io.SEEK_CUR)
        pkt_length = struct.unpack('I', file.read(4))[0]
        file.seek(4, io.SEEK_CUR)
        pkt_body = file.read(pkt_length)
        tcp_stream.append(pkt_body)
        header += pkt_body + 16


if __name__ == '__main__':
    analysis('pc.pcap')
