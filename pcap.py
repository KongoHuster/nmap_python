import dpkt
from scapy.all import *


def DecodePcapPackage(pcapFileName):
    pcaps = rdpcap(pcapFileName)
    for pcap in pcaps:
        print(pcap.show())
        print("\n\n\n")


def main():
    DecodePcapPackage("demo.pcap")


if __name__ == '__main__':
    main()
