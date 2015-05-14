switch.p4
=========

Behavioral model with PD library
--------------------------------

To build the softswitch with only the API auto-generated from P4 (PD API) in a thrift server,

make bm


Behavioral model with Semantic library
---------------------------------------

To build the softswitch with the semantic library APIs,

make bm-switchapi (this is the default)

When built with this option, there are two thrift servers (ports 9090 and 9091)
one for the auto-generated table APIs (PD APIs) and the other for the semantic library APIs

For details on the semantic library features please refer to the README.md file in the switchapi repository.

Below is the list of features supported by switch.p4
---------------------------------------------------------------

1. Basic L2 switching: VLAN flooding and STP support
2. Basic L3 Routing: IPv4 and IPv6 and VRF support
3. Support for LAG
4. Support for ECMP
5. Tunnels: Support for VXLAN and NVGRE (including L2/L3 Gateway), Geneve, and GRE 
6. Basic ACL: Support for MAC and IP ACLs
7. Unicast RPF check
8. MPLS support - LER, LSR, IPVPN, VPLS, L2VPN

Soon to follow
--------------

1. Support for Mirroring
2. Complete multicast support - IP, PIM-SM
3. NAT support
4. Counters/Statistics support
5. QoS support
6. Ingress Policers support
