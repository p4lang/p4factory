#!/bin/bash

# Setup CPU port
ip link add name veth250 type veth peer name veth251
ip link set dev veth250 up
ip link set dev veth251 up

# Setup front panel ports
ip tuntap add dev swp1 mode tap
ip tuntap add dev swp2 mode tap
ip tuntap add dev swp3 mode tap
ip tuntap add dev swp4 mode tap
ip link set swp1 up
ip link set swp2 up
ip link set swp3 up
ip link set swp4 up

if [ -x /configs/startup_config.sh ]
then
    /configs/startup_config.sh
fi
