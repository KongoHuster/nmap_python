from scapy.all import *
import socket

dpkt = sniff(filter='src dst 192.168.31.124', count=10)
wrpcap("demo.pcap", dpkt)
pcap_path = "demo.pcap"  # 用于解析文件的路径
pcap_saved = sniff(offline=pcap_path)  # 将保存下来的pcap再次实例化为python对象
