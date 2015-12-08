from scapy.all import *

p = Ether(dst="aa:bb:cc:dd:ee:ff") / IP(dst="10.0.1.10") / TCP() / "aaaaaaaaaaaaaaaaaaa"
# p.show()
hexdump(p)
sendp(p, iface = "veth0")
