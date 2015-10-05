switch.p4
=========

The switch.p4 program describes a data plane of an L2/L3 switch.

Supported Features
------------------
1. Basic L2 switching: Flooding, learning and STP
2. Basic L3 Routing: IPv4 and IPv6 and VRF
3. LAG
4. ECMP
5. Tunneling: VXLAN and NVGRE (including L2/L3 Gateway), Geneve, and GRE
6. Basic ACL: MAC and IP ACLs
7. Unicast RPF check
8. MPLS: LER, LSR, IPVPN, VPLS, L2VPN
9. Host interface
10. Mirroring: Ingress and egress mirroring with ERSPAN
11. Counters/Statistics

Upcoming Features
-----------------
1. Multicast: IP, PIM-SM
2. NAT
3. Ingress Policers
4. QoS

Building Soft Switch
--------------------

The soft switch can be built with the auto-generated API or switchapi.
Please refer to README under p4factory for instructions to build P4 programs.

To build the softswitch with only the auto-generated API in a thrift server,

    make bm

To build the softswitch with the switchapi library,

    make bm-switchapi

When built with this option, there are thrift servers on ports 9090 and 9091
for the auto-generated table APIs and the switchapi library APIs respectively.

To build the softswitch with the SAI API library,

    make bm-switchsai

When built with this option, there are thrift servers on ports 9090, 9091 and
9092 for the auto-generated table APIs, the switchapi library APIs and the SAI
library APIs respectively.

To build the softswitch with switchlink library that uses SAI API library
to program the softswitch,

    make bm-switchlink

To build the softswitch with an Openflow Agent,

    make bm-p4ofagent PLUGIN_OPENFLOW=1

To build the docker-image for a target, set the variable DOCKER_IMAGE in the
file 'Makefile' to the appropriate target name and run the following command.
By default, DOCKER_IMAGE is set to 'bm-switchlink'.

    make docker-image

Invoking make without an explicit target builds the softswitch with only the
auto-generated API (make bm).

For details on the features supported by switchapi, switchsai, switchlink and
p4ofagent libraries, please refer to the README.md file in the switchapi, 
switchsai, switchlink and p4ofagent repositories respectively.

Running Tests
-------------

To run the pd thrift testcases,

    sudo ./run_tests.py --test-dir tests/ptf-tests/pd-tests switch

To run the api thrift testcases,

    sudo ./run_tests.py --test-dir tests/ptf-tests/api-tests switch

To run the SAI thrift testcases,

    sudo ./run_tests.py --test-dir tests/ptf-tests/sai-tests switch

To run switchlink testcases,

    cd ../../mininet

    # L2 topology: Loop free topology
    sudo ./swl_l2.py
    mininet> h1 ping h2
    mininet> exit

    # L2 topology: with MSTPD
    sudo ./swl_stp.py
    mininet> h1 ping h2
    mininet> exit

    # L3 topology: Static configuration
    sudo ./swl_l3_static.py
    mininet> h1 ping h2
    mininet> exit

    # L3 topology: OSPF (Quagga)
    sudo ./swl_ospf.py
    mininet> h1 ping h2
    mininet> exit

    # L3 topology: EBGP (Quagga)
    sudo ./swl_bgp.py
    mininet> h1 ping h2
    mininet> exit

    # To access the switches and check the behavioral model logs under
    # /tmp/model.log
    sudo ./swl_bgp.py
    mininet> xterm sw1
    mininet> xterm sw2
    mininet> h1 ping h2

The switchlink testcases have been verified with docker version 1.7.0 and
Mininet version 2.2.1 running on Ubuntu 14.04.

Running Openflow Testcases
--------------------------

To run the Openflow testcases,

    sudo ./run_of_tests.py --test-dir tests/of-tests

Trying it with bmv2
========

As explained at the end of the [p4factory README](../../README.md), we are
currently working on a new version of the behavioral model, which will
eventually deprecate the original code. To try this code with the switch.p4
target, follow the instructions in [bmv2/README](bmv2/README.md).
