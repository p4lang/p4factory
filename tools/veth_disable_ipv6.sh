#!/bin/bash
noOfVeths=18
if [ $# -eq 1 ]; then 
    noOfVeths=$1
fi
echo "No of Veths is $noOfVeths"
idx=0
let "vethpairs=$noOfVeths/2"
while [ $idx -lt $vethpairs ]
do 
    intf0="veth$(($idx*2))"
    intf1="veth$(($idx*2+1))"
    sysctl net.ipv6.conf.$intf0.disable_ipv6=1
    sysctl net.ipv6.conf.$intf1.disable_ipv6=1
    idx=$((idx + 1))
done
idx=125
intf0="veth$(($idx*2))"
intf1="veth$(($idx*2+1))"
sysctl net.ipv6.conf.$intf0.disable_ipv6=1
sysctl net.ipv6.conf.$intf1.disable_ipv6=1
