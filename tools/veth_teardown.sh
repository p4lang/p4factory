#!/bin/bash
noOfVeths=18
if [ $# -eq 1 ]; then 
    noOfVeths=$1
fi
echo "No of Veths is $noOfVeths"
idx=0
while [ $idx -lt $noOfVeths ]
do 
#for idx in 0 1 2 3 4 5 6 7 125; do
    intf="veth$(($idx*2))"
    if ip link show $intf &> /dev/null; then
        ip link delete $intf type veth
    fi
    idx=$((idx + 1))
done
idx=125
intf="veth$(($idx*2))"
if ip link show $intf &> /dev/null; then
    ip link delete $intf type veth
fi
