#from scapy.layers.inet import IP, TCP, UDP, ICMP
#from scapy.sendrecv import sr
from scapy.all import *
import sys
import os
import getopt

opts, args = getopt.getopt(sys.argv[1:],"",["ip=", "port=", "proto=", "count=", "tcp_type="])

print (opts)

dst_ip = ""
dst_port = ""
proto = ""
count = ""
tcp_type = ""

for opt, arg in opts:
   if opt == "--ip":
      dst_ip = arg
   elif opt == "--port":
      dst_port = arg
   elif opt == "--proto":
      proto = arg
   elif opt == "--count":
      count = arg
   elif opt == "--tcp_type":
      tcp_type = arg

print("%s %s %s %s %s" % (dst_ip, dst_port, proto, count, tcp_type))

src_port = RandShort()

if proto.lower() not in ("tcp", "udp"):
   print("Protocol %s is not supported." % (proto))
   sys.exit()

for i in range(int(count)):
   if proto.lower() == "tcp": 
      if tcp_type == "syn":
         print("TCP SYN packet %s." % (i))
         send(IP(dst=dst_ip)/TCP(dport=int(dst_port), sport=src_port, flags='S', seq=1000), verbose = 0)
      else:
         print("Full TCP connection %s." % (i))
         os.system("echo hello | nc %s %s" % (dst_ip, dst_port))
   elif proto.lower() == "udp":
      send(IP(dst=dst_ip)/UDP(dport=int(dst_port), sport=src_port))
   else:
      print("Protocol %s is not supported." % (proto))

