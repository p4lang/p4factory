from ptf.testutils import *
from scapy.all import Packet
from scapy.fields import *
from scapy.all import Ether
from scapy.all import bind_layers


###############################################################################
# Helper functions                                                            #
###############################################################################
def verify_any_packet_on_ports_list(test, pkts=[], ports=[], device_number=0):
    """
    Ports is list of port lists
    Check that _any_ packet is received atleast once in every sublist in
    ports belonging to the given device (default device_number is 0).

    Also verifies that the packet is ot received on any other ports for this
    device, and that no other packets are received on the device
    (unless --relax is in effect).
    """
    pkt_cnt = 0
    for port_list in ports:
        for port in port_list:
            (rcv_device, rcv_port, rcv_pkt, pkt_time) = test.dataplane.poll(
                port_number=port,
                timeout=1,
                filters=get_filters()
            )
            if rcv_device != device_number:
                continue
            for pkt in pkts:
                logging.debug("Checking for pkt on device %d, port %d",
                              device_number, port)
                if str(rcv_pkt) == str(pkt):
                    pkt_cnt += 1

    verify_no_other_packets(test)
    test.assertTrue(pkt_cnt == len(ports), "Did not receive pkt on one of ports %r for device %d" % (ports, device_number))


###############################################################################
# CPU Header                                                                  #
###############################################################################
class FabricHeader(Packet):
    name = "Fabric Header"
    fields_desc = [
        BitField("packet_type", 0, 3),
        BitField("header_version", 0, 2),
        BitField("packet_version", 0, 2),
        BitField("pad1", 0, 1),

        BitField("fabric_color", 0, 3),
        BitField("fabric_qos", 0, 5),

        XByteField("dst_device", 0),
        XShortField("dst_port_or_group", 0),
    ]

class FabricCpuHeader(Packet):
    name = "Fabric Cpu Header"
    fields_desc = [
        BitField("egress_queue", 0, 5),
        BitField("tx_bypass", 0, 1),
        BitField("reserved1", 0, 2),

        XShortField("ingress_port", 0),
        XShortField("ingress_ifindex", 0),
        XShortField("ingress_bd", 0),

        XShortField("reason_code", 0)
    ]

class FabricPayloadHeader(Packet):
    name = "Fabric Payload Header"
    fields_desc = [
        XShortField("ether_type", 0)
    ]


def simple_cpu_packet(header_version = 0,
                      packet_version = 0,
                      fabric_color = 0,
                      fabric_qos = 0,
                      dst_device = 0,
                      dst_port_or_group = 0,
                      ingress_ifindex = 1,
                      ingress_bd = 0,
                      egress_queue = 0,
                      tx_bypass = False,
                      ingress_port = 1,
                      reason_code = 0,
                      inner_pkt = None):

    ether = Ether(str(inner_pkt))
    eth_type = ether.type
    ether.type = 0x9000

    fabric_header = FabricHeader(packet_type = 0x5,
                                  header_version = header_version,
                                  packet_version = packet_version,
                                  pad1 = 0,
                                  fabric_color = fabric_color,
                                  fabric_qos = fabric_qos,
                                  dst_device = dst_device,
                                  dst_port_or_group = dst_port_or_group)

    fabric_cpu_header = FabricCpuHeader(egress_queue = egress_queue,
                                        tx_bypass = tx_bypass,
                                        reserved1 = 0,
                                        ingress_port = ingress_port,
                                        ingress_ifindex = ingress_ifindex,
                                        ingress_bd = ingress_bd,
                                        reason_code = reason_code)

    fabric_payload_header = FabricPayloadHeader(ether_type = eth_type)

    if inner_pkt:
        pkt = (str(ether)[:14]) / fabric_header / fabric_cpu_header / fabric_payload_header / (str(inner_pkt)[14:])
    else:
        ip_pkt = simple_ip_only_packet()
        pkt = (str(ether)[:14]) / fabric_header / fabric_cpu_header / fabric_payload_header / ip_pkt

    return pkt


###############################################################################
# CRC16 and Entropy hash calculation                                          #
###############################################################################
import crc16
def crc16_regular(buff, crc = 0, poly = 0xa001):
    l = len(buff)
    i = 0
    while i < l:
        ch = ord(buff[i])
        uc = 0
        while uc < 8:
            if (crc & 1) ^ (ch & 1):
                crc = (crc >> 1) ^ poly
            else:
                crc >>= 1
            ch >>= 1
            uc += 1
        i += 1
    return crc

def entropy_hash(pkt, layer='ipv4'):
    buff = pkt[Ether].src.translate(None, ':')
    buff += pkt[Ether].dst.translate(None, ':')
    if layer == 'ether':
        #buff += str(hex(pkt[Ether].type)[2:]).zfill(4)
        buff += ''.zfill(26)
    elif layer == 'ipv4':
        buff += socket.inet_aton(pkt[IP].src).encode('hex')
        buff += socket.inet_aton(pkt[IP].dst).encode('hex')
        buff += str(hex(pkt[IP].proto)[2:]).zfill(2)
        if pkt[IP].proto == 6:
            buff += str(hex(pkt[TCP].sport)[2:]).zfill(4)
            buff += str(hex(pkt[TCP].dport)[2:]).zfill(4)
        elif pkt[IP].proto == 17:
            buff += str(hex(pkt[UDP].sport)[2:]).zfill(4)
            buff += str(hex(pkt[UDP].dport)[2:]).zfill(4)
    elif layer == 'ipv6':
        print 'Not Implemented'
        buf = ''
    else:
        buf = ''
    h = socket.htons(crc16_regular(buff.decode('hex')))
    return h

