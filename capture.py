from scapy.all import *

dpkt = sniff(filter='src dst 192.168.9.254', count=10)
wrpcap("demo.pcap", dpkt)

pcap_path = "demo.pcap"  # 用于解析文件的路径
pcap_saved = sniff(offline=pcap_path)  # 将保存下来的pcap再次实例化为python对象

