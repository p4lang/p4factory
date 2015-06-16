switch.p4
=========

The switch.p4 program describes a data plane of an L2/L3 switch.

Supported Features
------------------
1. Basic L2 switching: VLAN flooding and STP
2. Basic L3 Routing: IPv4 and IPv6 and VRF
3. LAG
4. ECMP
5. Tunneling: VXLAN and NVGRE (including L2/L3 Gateway), Geneve, and GRE 
6. Basic ACL: MAC and IP ACLs
7. Unicast RPF check
8. MPLS: LER, LSR, IPVPN, VPLS, L2VPN

Upcoming Features
-----------------
1. Mirroring
2. Multicast: IP, PIM-SM
3. NAT
4. Counters/Statistics
5. Ingress Policers
6. QoS

Building Soft Switch
--------------------

The soft switch can be built with the auto-generated API or switchapi.

To build the softswitch with only the auto-generated API in a thrift server,

    make bm

To build the softswitch with the switchapi library,

    make bm-switchapi

When built with this option, there are thrift servers on ports 9090 and 9091
for the auto-generated table APIs and the switchapi library APIs respectively.

To build the softswitch with the SAI API library,

    make bm-switchsai

When built with this option, there are thrift servers on ports 9090, 9091 and 9092 
for the auto-generated table APIs, the switchapi library APIs and the SAI library APIs respectively.

Invoking make without an explicit target builds the softswitch with only the auto-generated API.

For details on the features supported by switchapi and switchsai libraries,
please refer to the README.md file in the switchapi and switchsai repositories respectively.

Running Tests
-------------

To run the pd thrift testcases,

    sudo ./run_tests.py --test-dir of-tests/tests/pd-tests switch

To run the api thrift testcases,

    sudo ./run_tests.py --test-dir of-tests/tests/api-tests switch

To run the SAI thrift testcases,

    sudo ./run_tests.py --test-dir of-tests/tests/sai-tests switch
