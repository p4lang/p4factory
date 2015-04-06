// Template parser.p4 file for p4_l2l3
// Edit this file as needed for your P4 program
// This exmaple shows basic L2 and L3 (ipv4) parsing

header ethernet_t ethernet;

parser start {
    return parse_ethernet;
}

#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_ARP 0x0806

parser parse_ethernet {
    extract(ethernet);
    return select(latest.etherType) {
        ETHERTYPE_VLAN : parse_vlan;
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header vlan_tag_t vlan_tag_;

parser parse_vlan {
    extract(vlan_tag_);
    return select(latest.etherType) {
        ETHERTYPE_IPV4 : parse_ipv4;
        default: ingress;
    }
}

header ipv4_t ipv4;

parser parse_ipv4 {
    extract(ipv4);
    return ingress;
}
