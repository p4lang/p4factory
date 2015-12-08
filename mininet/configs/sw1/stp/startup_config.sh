#!/bin/bash

# disable IPv6
sysctl -q net.ipv6.conf.all.disable_ipv6=1

/sbin/mstpd >& /dev/null

brctl addbr br0
brctl addif br0 swp1
brctl addif br0 swp2
brctl addif br0 swp3
brctl addif br0 swp4

mstpctl addbridge br0
mstpctl setforcevers br0 rstp

brctl stp br0 on
ip link set br0 up
