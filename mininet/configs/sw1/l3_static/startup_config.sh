#!/bin/bash

ip link set dev swp1 address 00:01:00:00:00:01
ip link set dev swp2 address 00:01:00:00:00:02
ip address add 172.16.101.1/24 broadcast + dev swp1
ip address add 172.16.10.1/24 broadcast + dev swp2
ip neigh add 172.16.101.5 lladdr 00:04:00:00:00:02 dev swp1
ip neigh add 172.16.10.2 lladdr 00:02:00:00:00:02 dev swp2
ip route add 172.16.102/24 nexthop via 172.16.10.2
