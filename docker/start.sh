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
ip tuntap add dev swp5 mode tap
ip tuntap add dev swp6 mode tap
ip tuntap add dev swp7 mode tap
ip tuntap add dev swp8 mode tap
ip tuntap add dev swp9 mode tap
ip tuntap add dev swp10 mode tap
ip tuntap add dev swp11 mode tap
ip tuntap add dev swp12 mode tap
ip tuntap add dev swp13 mode tap
ip tuntap add dev swp14 mode tap
ip tuntap add dev swp15 mode tap
ip tuntap add dev swp16 mode tap
ip link set swp1 up
ip link set swp2 up
ip link set swp3 up
ip link set swp4 up
ip link set swp5 up
ip link set swp6 up
ip link set swp7 up
ip link set swp8 up
ip link set swp9 up
ip link set swp10 up
ip link set swp11 up
ip link set swp12 up
ip link set swp13 up
ip link set swp14 up
ip link set swp15 up
ip link set swp16 up

if [ -x /configs/startup_config.sh ]
then
    /configs/startup_config.sh
fi

exec /bin/bash
