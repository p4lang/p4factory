from scapy.all import *

sniff(iface = "veth6", prn = lambda x: hexdump(x))
