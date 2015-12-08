#!/bin/bash

ip link set dev swp1 address 00:02:00:00:00:01
ip link set dev swp2 address 00:02:00:00:00:02
ip address add 172.16.102.1/24 broadcast + dev swp1
ip address add 172.16.10.2/24 broadcast + dev swp2
ip neigh add 172.16.102.5 lladdr 00:05:00:00:00:02 dev swp1
ip neigh add 172.16.10.1 lladdr 00:01:00:00:00:02 dev swp2
ip route add 172.16.101/24 nexthop via 172.16.10.1
