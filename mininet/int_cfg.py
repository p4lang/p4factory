#!/usr/bin/python
# Copyright 2015-present Barefoot Networks, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from mininet.net import Mininet, VERSION
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from distutils.version import StrictVersion
from p4_mininet import P4DockerSwitch
from p4_mininet import P4Host
from mininet.link import TCLink

import os
import sys
import time
lib_path = os.path.abspath(os.path.join('..', 'targets', 'switch', 'tests', 'pd_thrift'))
sys.path.append(lib_path)
import switch_api_thrift.switch_api_rpc as api_rpc
from switch_api_thrift.ttypes import  *
from thrift.transport import TSocket
from thrift.transport import TTransport
from thrift.protocol import TBinaryProtocol

class HostConfig():
  def __init__(self, name, mac, ip, prefix_len, cls = P4Host, vxlan_cfg = None):
    self.name = name
    self.cls = cls
    self.mac = mac
    self.ip = ip
    self.prefix_len = prefix_len
    self.vxlan_cfg = vxlan_cfg

class SwitchConfig():
  def __init__(self, name, switch_id,
               swapi_port, port_cfgs, 
               target_name = "p4dockerswitch", cls = P4DockerSwitch, 
               target_dir = 'switch',
               int_transit_enable = True,  pcap_dump = True,
               pps = 0,
               qdepth = 0,
               config_fs = None ):
    self.name = name
    self.switch_id = switch_id
    self.swapi_port = swapi_port
    self.port_cfgs = port_cfgs
    self.target_name = target_name
    self.target_dir = target_dir
    self.cls = cls
    self.int_transit_enable = int_transit_enable
    self.pcap_dump = pcap_dump
    self.config_fs = config_fs
    self.pps = pps
    self.qdepth = qdepth

class PortConfig():
  def __init__(self, port_no, ip, prefix_len, mac):
    self.port_no = port_no
    self.ip = ip
    self.prefix_len = prefix_len
    self.mac = mac
    
class LinkConfig():
  def __init__(self, node1, node2, port1, port2 = None):
    self.node1 = node1
    self.node2 = node2
    self.port1 = port1
    self.port2 = port2

class SwitchRouteConfig():
  def __init__(self, dst_ip, dst_prefix_len, egress_port, nhop_mac, nhop_ip):
    self.dst_ip = dst_ip
    self.dst_prefix_len = dst_prefix_len
    self.egress_port = egress_port
    self.nhop_mac = nhop_mac
    self.nhop_ip = nhop_ip

class VxlanConfig():
  def __init__(self, vni, group, ip, prefix_len, veth_mac, mtu=1400):
    self.vni = vni
    self.group = group
    self.ip = ip
    self.prefix_len = prefix_len
    self.veth_mac = veth_mac 
    self.mtu = mtu

class NetworkManager():
  def __init__(self, host_cfgs, switch_cfgs, link_cfgs):
    self.net = Mininet( controller = None, link = TCLink )
    self.link_cfgs = link_cfgs
    self.host_cfgs = dict()
    self.switch_cfgs = dict()
    self.ip_addr = dict() # Cache of ip addr instances

    for h in host_cfgs:
      self.host_cfgs[h.name] = h

    for s in switch_cfgs:
      self.switch_cfgs[s.name] = s

  def setupAndStartNetwork(self):
    self.addHosts()
    self.addSwitches()
    self.addLinks()

    self.net.start()

    print 'Waiting 10 seconds for switches to intialize...'
    time.sleep(10)
 
    self.configSwitches()
    self.configHostRoutesAndArp()
    self.configINTSourcesAndSinks()
    self.setupHostToMonitorConns()
    self.startHostPreprocessors()
    
    print 'Waiting 20 seconds for Quagga to learn routes...'
    time.sleep(20)

    self.startPingMesh()

    return self.net
    
  def addHosts(self):
    for h in self.host_cfgs.values():
      ip_with_prefix = "%s/%d" % (h.ip, h.prefix_len)
      self.net.addHost( h.name, cls = h.cls, mac = h.mac, ip = ip_with_prefix ) 

  def addSwitches(self):
    for s in self.switch_cfgs.values():
      if s.config_fs != None:
        self.net.addSwitch(
          s.name,
          target_name = s.target_name, cls       = s.cls, 
          swapi_port  = s.swapi_port,  pcap_dump = s.pcap_dump,
          target_dir  = s.target_dir,  config_fs = s.config_fs,
          pps = s.pps, qdepth = s.qdepth)
      else:
        self.net.addSwitch(
          s.name,
          target_name = s.target_name, cls       = s.cls, 
          swapi_port  = s.swapi_port,  pcap_dump = s.pcap_dump,
          target_dir  = s.target_dir,
          pps = s.pps, qdepth = s.qdepth)

  def addLinks(self):
    for l in self.link_cfgs:
      n1 = self.net.get( l.node1 )
      n2 = self.net.get( l.node2 )
      if StrictVersion(VERSION) <= StrictVersion('2.2.0') :
        if l.port2 != None:
          self.net.addLink( n1, n2, port1 = l.port1 + 1, port2 = l.port2 + 1, bw=5)
        else:
          self.net.addLink( n1, n2, port1 = l.port1 + 1, bw=5)
      else:
        if l.port2 != None:
          self.net.addLink( n1, n2, port1 = l.port1 + 1, port2 = l.port2 + 1, fast=False, bw=5)
        else:
          self.net.addLink( n1, n2, port1 = l.port1 + 1, fast=False, bw=5)

  def configINTSourcesAndSinks(self):
    for c1 in self.host_cfgs.values():
      if c1.vxlan_cfg != None:
        vc = c1.vxlan_cfg
        h = self.net.get( c1.name )
        h.cmd( "brctl addbr testbr0" )
        h.cmd( "ip link add vxlan0 type vxlan id %d group %s dev eth0" % ( vc.vni, vc.group ))
        h.cmd( "brctl addif testbr0 vxlan0" )
        h.cmd( "ifconfig vxlan0 up" )
        h.cmd( "ifconfig testbr0 up" )
        h.cmd( "ip link add veth0 type veth peer name veth1" )
        h.cmd( "ifconfig veth0 %s/%d up" % ( vc.ip, vc.prefix_len ))
        h.cmd( "ifconfig veth0 mtu %d" % vc.mtu )
        h.cmd( "ifconfig veth1 up" )
        h.cmd( "ip link set dev veth0 address %s" % vc.veth_mac )
        h.cmd( "brctl addif testbr0 veth1" )

    for c1 in self.host_cfgs.values():
      if c1.vxlan_cfg != None:
        vc = c1.vxlan_cfg
        for c2 in self.host_cfgs.values():
          if ( c2 != c1 ) and (c2.vxlan_cfg != None):
            h = self.net.get( c2.name )
            h.cmd( "arp -s %s %s" % ( vc.ip, vc.veth_mac ))
            h.cmd( "bridge fdb add to %s dst %s dev vxlan0 via eth0" % ( vc.veth_mac, c1.ip ))

  def configHostRoutesAndArp(self):
    for l in self.link_cfgs:
      if l.port2 == None:
        sw = self.switch_cfgs[l.node1]
        h = self.net.get(l.node2)
        port = sw.port_cfgs[l.port1]
        h.cmd("route add default gw %s" % port.ip)
        h.cmd("arp -s %s %s" % (port.ip, port.mac))

  def configSwitches(self):
    for s in self.switch_cfgs.values():
      self.configSwitch(s)
    self.startQuaggaOnSwitches()

  def startQuaggaOnSwitches(self):
    print "Starting quagga on switches"
    for s in self.switch_cfgs.values():
      sw = self.net.get(s.name)
      sw.cmd("service quagga start")

  def configSwitch(self, cfg):
    device = 0
    transport, client = open_connection( cfg.swapi_port )
    print "INT Config ", cfg.name

    client.switcht_api_init( device )

    client.switcht_int_transit_enable( device, cfg.switch_id, 1 )

    close_connection( transport )

  def setupHostToMonitorConns(self):
    runOnNativeHost("brctl addbr testbr1")

    i = 21
    for hn in self.host_cfgs:
      h = self.net.get(hn) 
      vm_eth_intf = 'vm-eth%s' % i
      vm_eth_intf_ip = '192.168.1.%d' % i
      h_eth_intf  = '%s-vm-eth%d' % (h.name, i)
      h_eth_intf_ip = '192.168.1.%d' % (i * 2)
      runOnNativeHost('ip link add %s type veth peer name %s' % (h_eth_intf, vm_eth_intf))
      runOnNativeHost('ip link set %s netns %d' % (h_eth_intf, h.shell.pid))
      runOnNativeHost('brctl addif testbr1 %s' % vm_eth_intf)

      h.cmd('ifconfig %s up' % h_eth_intf)
      h.cmd('ifconfig %s %s/24' % (h_eth_intf, h_eth_intf_ip))
      runOnNativeHost('ifconfig %s up' % vm_eth_intf)

      i = i + 1

    runOnNativeHost("ip link add veth-t1 type veth peer name veth-t2")
    runOnNativeHost("brctl addif testbr1 veth-t1")
    runOnNativeHost("ifconfig veth-t1 up")
    runOnNativeHost("ifconfig veth-t2 up")
    runOnNativeHost("ifconfig veth-t2 192.168.1.100")
    runOnNativeHost("ifconfig testbr1 up")

    runOnNativeHost("../apps/int/monitor/monitor.py > tmp_monitor 2>&1 &")
    runOnNativeHost("../apps/int/monitor/client_msg_handler.py > tmp_client_msg_handler 2>&1 &")

  def startHostPreprocessors(self):
    for c in self.host_cfgs.values():
      h = self.net.get(c.name)
      cmd = "../apps/int/monitor/preprocessor.py %s > tmp_%s 2>&1 &" % (c.ip, c.name)
      print(cmd)
      h.cmd(cmd)

  def cleanup(self):
    for i in range(len(self.host_cfgs)):
      runOnNativeHost('ip link delete vm-eth%d' % (i + 21))
    runOnNativeHost('ip link delete veth-t1')
    runOnNativeHost('ifconfig testbr1 down')
    runOnNativeHost('brctl delbr testbr1')

  # Helper functions
  def get_ip_addr_handle(self, ip, prefix_len):
    k = (ip, prefix_len)
    if (k in self.ip_addr):
      return self.ip_addr[k]

    h = switcht_ip_addr_t(ipaddr = ip, prefix_length = prefix_len)
    self.ip_addr[k] = h

    return h

  def startPingMesh(self):
    print "Starting ping mesh sessions"
    for c1 in self.host_cfgs.values():
      if c1.vxlan_cfg != None:
        h = self.net.get( c1.name )
        for c2 in self.host_cfgs.values():
          if (c2.name != c1.name and c2.vxlan_cfg != None):
            vc = c2.vxlan_cfg
            h.cmd ( "ping %s > /dev/null &" % (vc.ip) )
            print h.name + " pinging " + vc.ip

def runOnNativeHost(cmd):
  #print '[CMD] ', cmd
  ret = os.system(cmd)
  if not ret == 0:
      error('[ERROR] Command failed. \'', cmd, '\'')

def open_connection(port):
    transport = TSocket.TSocket('localhost', port)
    transport = TTransport.TBufferedTransport(transport)
    protocol = TBinaryProtocol.TBinaryProtocol(transport)

    client = api_rpc.Client(protocol)
    transport.open()
    return transport, client

def close_connection(transport):
    transport.close()
