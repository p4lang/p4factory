#!/bin/bash

stty -echo; set +m

ip link set dev swp1 address 00:02:00:00:00:01
ip link set dev swp2 address 00:02:00:00:00:02
ip link set dev swp3 address 00:02:00:00:00:03
ip link set dev swp4 address 00:02:00:00:00:04

ip address add 10.0.3.100/24 broadcast + dev swp1
ip address add 10.0.4.100/24 broadcast + dev swp2
ip address add 10.1.21.1/24 broadcast + dev swp3
ip address add 10.1.22.1/24 broadcast + dev swp4

cp /configs/quagga/* /etc/quagga/
chown quagga.quagga /etc/quagga/*
