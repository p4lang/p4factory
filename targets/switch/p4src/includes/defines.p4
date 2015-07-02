/* Boolean */
#define FALSE                                  0
#define TRUE                                   1

/* Packet types */
#define L2_UNICAST                             1
#define L2_MULTICAST                           2
#define L2_BROADCAST                           4

#define STORM_CONTROL_COLOR_GREEN              0
#define STORM_CONTROL_COLOR_RED                1

/* IP types */
#define IPTYPE_NONE                            0
#define IPTYPE_IPV4                            1
#define IPTYPE_IPV6                            2

/* Multicast modes */
#define MCAST_MODE_NONE                        0
#define MCAST_MODE_SM                          1
#define MCAST_MODE_BIDIR                       2

#define OUTER_MCAST_KEY_TYPE_BD                0
#define OUTER_MCAST_KEY_TYPE_VRF               1

/* URPF modes */
#define URPF_MODE_NONE                         0
#define URPF_MODE_LOOSE                        1 
#define URPF_MODE_STRICT                       2

/* NAT modes */
#define NAT_MODE_NONE                          0
#define NAT_MODE_INSIDE                        1
#define NAT_MODE_OUTSIDE                       2

/* Egress tunnel types */
#define EGRESS_TUNNEL_TYPE_NONE                0
#define EGRESS_TUNNEL_TYPE_IPV4_VXLAN          1
#define EGRESS_TUNNEL_TYPE_IPV6_VXLAN          2
#define EGRESS_TUNNEL_TYPE_IPV4_GENEVE         3
#define EGRESS_TUNNEL_TYPE_IPV6_GENEVE         4
#define EGRESS_TUNNEL_TYPE_IPV4_NVGRE          5
#define EGRESS_TUNNEL_TYPE_IPV6_NVGRE          6
#define EGRESS_TUNNEL_TYPE_IPV4_ERSPANV2       7
#define EGRESS_TUNNEL_TYPE_IPV6_ERSPANV2       8
#define EGRESS_TUNNEL_TYPE_IPV4_GRE            9
#define EGRESS_TUNNEL_TYPE_IPV6_GRE            10
#define EGRESS_TUNNEL_TYPE_IPV4_IP             11
#define EGRESS_TUNNEL_TYPE_IPV6_IP             12
#define EGRESS_TUNNEL_TYPE_MPLS_L2VPN          13
#define EGRESS_TUNNEL_TYPE_MPLS_L3VPN          14
#define EGRESS_TUNNEL_TYPE_FABRIC              15
#define EGRESS_TUNNEL_TYPE_CPU                 16

#define VRF_BIT_WIDTH                          12
#define BD_BIT_WIDTH                           16
#define ECMP_BIT_WIDTH                         10
#define LAG_BIT_WIDTH                          8
#define IFINDEX_BIT_WIDTH                      16

#define STP_GROUP_NONE                         0

#define CPU_PORT_ID                            64
#define CPU_MIRROR_SESSION_ID                  250

/* Learning Receivers */
#define MAC_LEARN_RECEIVER                     1024

/* Nexthop Type */
#define NEXTHOP_TYPE_SIMPLE                    0
#define NEXTHOP_TYPE_ECMP                      1

#define INVALID_PORT_ID                        511

/* fabric device to indicate mutlicast */
#define FABRIC_DEVICE_MULTICAST                127

/* port type */
#define PORT_TYPE_NORMAL                       0
#define PORT_TYPE_FABRIC                       1
#define PORT_TYPE_CPU                          2
