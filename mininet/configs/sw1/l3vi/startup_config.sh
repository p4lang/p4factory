#!/bin/bash

stty -echo; set +m

brctl addbr br0
brctl addif br0 swp2
brctl addif br0 swp3
brctl addif br0 swp4
ip link set br0 up

ip address add 172.16.101.1/24 broadcast + dev swp1
ip address add 172.16.102.1/24 broadcast + dev br0

sysctl -q net.ipv4.conf.all.rp_filter=0
