
#ifdef MIN_PROFILE
#define MIN_SRAM_TABLE_SIZE                    1024
#define MIN_TCAM_TABLE_SIZE                    512

#define VALIDATE_PACKET_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define PORTMAP_TABLE_SIZE                     288
#define STORM_CONTROL_TABLE_SIZE               MIN_TCAM_TABLE_SIZE
#define STORM_CONTROL_METER_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define PORT_VLAN_TABLE_SIZE                   4096
#define OUTER_ROUTER_MAC_TABLE_SIZE            MIN_SRAM_TABLE_SIZE
#define DEST_TUNNEL_TABLE_SIZE                 MIN_SRAM_TABLE_SIZE
#define SRC_TUNNEL_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define OUTER_MULTICAST_STAR_G_TABLE_SIZE      MIN_TCAM_TABLE_SIZE
#define OUTER_MULTICAST_S_G_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define VNID_MAPPING_TABLE_SIZE                MIN_SRAM_TABLE_SIZE
#define BD_TABLE_SIZE                          MIN_SRAM_TABLE_SIZE
#define BD_FLOOD_TABLE_SIZE                    MIN_SRAM_TABLE_SIZE
#define BD_STATS_TABLE_SIZE                    MIN_SRAM_TABLE_SIZE
#define OUTER_MCAST_RPF_TABLE_SIZE             MIN_SRAM_TABLE_SIZE
#define MPLS_TABLE_SIZE                        MIN_SRAM_TABLE_SIZE
#define VALIDATE_MPLS_TABLE_SIZE               MIN_TCAM_TABLE_SIZE

#define ROUTER_MAC_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define DMAC_TABLE_SIZE                        MIN_SRAM_TABLE_SIZE
#define SMAC_TABLE_SIZE                        MIN_SRAM_TABLE_SIZE
#define IPSG_TABLE_SIZE                        MIN_SRAM_TABLE_SIZE
#define IPSG_PERMIT_SPECIAL_TABLE_SIZE         MIN_TCAM_TABLE_SIZE
#define INGRESS_MAC_ACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_IP_ACL_TABLE_SIZE              MIN_TCAM_TABLE_SIZE
#define INGRESS_IPV6_ACL_TABLE_SIZE            MIN_TCAM_TABLE_SIZE
#define INGRESS_QOS_ACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_IP_RACL_TABLE_SIZE             MIN_TCAM_TABLE_SIZE
#define INGRESS_IPV6_RACL_TABLE_SIZE           MIN_TCAM_TABLE_SIZE
#define IP_NAT_TABLE_SIZE                      MIN_SRAM_TABLE_SIZE
#define EGRESS_NAT_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define IPV4_LPM_TABLE_SIZE                    MIN_TCAM_TABLE_SIZE
#define IPV6_LPM_TABLE_SIZE                    MIN_TCAM_TABLE_SIZE
#define IPV4_HOST_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define IPV6_HOST_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define IPV4_MULTICAST_STAR_G_TABLE_SIZE       MIN_SRAM_TABLE_SIZE
#define IPV4_MULTICAST_S_G_TABLE_SIZE          MIN_SRAM_TABLE_SIZE
#define IPV6_MULTICAST_STAR_G_TABLE_SIZE       MIN_SRAM_TABLE_SIZE
#define IPV6_MULTICAST_S_G_TABLE_SIZE          MIN_SRAM_TABLE_SIZE
#define MCAST_RPF_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define FWD_RESULT_TABLE_SIZE                  MIN_TCAM_TABLE_SIZE
#define URPF_GROUP_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define ECMP_GROUP_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define ECMP_SELECT_TABLE_SIZE                 MIN_SRAM_TABLE_SIZE
#define NEXTHOP_TABLE_SIZE                     MIN_SRAM_TABLE_SIZE
#define LAG_GROUP_TABLE_SIZE                   MIN_SRAM_TABLE_SIZE
#define LAG_SELECT_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define SYSTEM_ACL_SIZE                        MIN_TCAM_TABLE_SIZE
#define LEARN_NOTIFY_TABLE_SIZE                MIN_TCAM_TABLE_SIZE

#define MAC_REWRITE_TABLE_SIZE                 MIN_TCAM_TABLE_SIZE
#define EGRESS_VNID_MAPPING_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define EGRESS_BD_MAPPING_TABLE_SIZE           MIN_SRAM_TABLE_SIZE
#define REPLICA_TYPE_TABLE_SIZE                MIN_TCAM_TABLE_SIZE
#define RID_TABLE_SIZE                         MIN_SRAM_TABLE_SIZE
#define TUNNEL_DECAP_TABLE_SIZE                MIN_SRAM_TABLE_SIZE
#define IP_MTU_TABLE_SIZE                      MIN_SRAM_TABLE_SIZE
#define EGRESS_VLAN_XLATE_TABLE_SIZE           MIN_SRAM_TABLE_SIZE
#define SPANNING_TREE_TABLE_SIZE               MIN_SRAM_TABLE_SIZE
#define FABRIC_REWRITE_TABLE_SIZE              MIN_TCAM_TABLE_SIZE
#define EGRESS_ACL_TABLE_SIZE                  MIN_TCAM_TABLE_SIZE
#define VLAN_DECAP_TABLE_SIZE                  MIN_SRAM_TABLE_SIZE
#define TUNNEL_HEADER_TABLE_SIZE               MIN_SRAM_TABLE_SIZE
#define TUNNEL_REWRITE_TABLE_SIZE              MIN_SRAM_TABLE_SIZE
#define TUNNEL_SMAC_REWRITE_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         MIN_SRAM_TABLE_SIZE
#define MIRROR_SESSIONS_TABLE_SIZE             MIN_SRAM_TABLE_SIZE
#define MIRROR_COALESCING_SESSIONS_TABLE_SIZE  MIN_SRAM_TABLE_SIZE

#else

#define VALIDATE_PACKET_TABLE_SIZE             64
#define PORTMAP_TABLE_SIZE                     288
#define STORM_CONTROL_TABLE_SIZE               512
#define STORM_CONTROL_METER_TABLE_SIZE         512
#define PORT_VLAN_TABLE_SIZE                   32768
#define OUTER_ROUTER_MAC_TABLE_SIZE            256
#define DEST_TUNNEL_TABLE_SIZE                 512
#define SRC_TUNNEL_TABLE_SIZE                  16384
#define OUTER_MULTICAST_STAR_G_TABLE_SIZE      512
#define OUTER_MULTICAST_S_G_TABLE_SIZE         1024
#define VNID_MAPPING_TABLE_SIZE                16384
#define BD_TABLE_SIZE                          16384
#define BD_FLOOD_TABLE_SIZE                    49152
#define BD_STATS_TABLE_SIZE                    49152
#define OUTER_MCAST_RPF_TABLE_SIZE             512
#define MPLS_TABLE_SIZE                        4096
#define VALIDATE_MPLS_TABLE_SIZE               512

#define ROUTER_MAC_TABLE_SIZE                  512
#define DMAC_TABLE_SIZE                        65536
#define SMAC_TABLE_SIZE                        65536
#define IPSG_TABLE_SIZE                        8192
#define IPSG_PERMIT_SPECIAL_TABLE_SIZE         512
#define INGRESS_MAC_ACL_TABLE_SIZE             512
#define INGRESS_IP_ACL_TABLE_SIZE              1024
#define INGRESS_IPV6_ACL_TABLE_SIZE            512
#define INGRESS_QOS_ACL_TABLE_SIZE             512
#define INGRESS_IP_RACL_TABLE_SIZE             1024
#define INGRESS_IPV6_RACL_TABLE_SIZE           512
#define IP_NAT_TABLE_SIZE                      4096
#define EGRESS_NAT_TABLE_SIZE                  512

#define IPV4_LPM_TABLE_SIZE                    8192
#define IPV6_LPM_TABLE_SIZE                    2048
#define IPV4_HOST_TABLE_SIZE                   65536
#define IPV6_HOST_TABLE_SIZE                   16384

#define IPV4_MULTICAST_STAR_G_TABLE_SIZE       2048
#define IPV4_MULTICAST_S_G_TABLE_SIZE          4096
#define IPV6_MULTICAST_STAR_G_TABLE_SIZE       512
#define IPV6_MULTICAST_S_G_TABLE_SIZE          512
#define MCAST_RPF_TABLE_SIZE                   32768

#define FWD_RESULT_TABLE_SIZE                  512
#define URPF_GROUP_TABLE_SIZE                  32768
#define ECMP_GROUP_TABLE_SIZE                  1024
#define ECMP_SELECT_TABLE_SIZE                 16384
#define NEXTHOP_TABLE_SIZE                     65536
#define LAG_GROUP_TABLE_SIZE                   1024
#define LAG_SELECT_TABLE_SIZE                  1024
#define SYSTEM_ACL_SIZE                        512
#define LEARN_NOTIFY_TABLE_SIZE                512

#define MAC_REWRITE_TABLE_SIZE                 512
#define EGRESS_VNID_MAPPING_TABLE_SIZE         16384
#define EGRESS_BD_MAPPING_TABLE_SIZE           16384
#define REPLICA_TYPE_TABLE_SIZE                16
#define RID_TABLE_SIZE                         65536
#define TUNNEL_DECAP_TABLE_SIZE                512
#define IP_MTU_TABLE_SIZE                      512
#define EGRESS_VLAN_XLATE_TABLE_SIZE           32768
#define SPANNING_TREE_TABLE_SIZE               4096
#define FABRIC_REWRITE_TABLE_SIZE              512
#define EGRESS_ACL_TABLE_SIZE                  1024
#define VLAN_DECAP_TABLE_SIZE                  256
#define TUNNEL_HEADER_TABLE_SIZE               256
#define TUNNEL_REWRITE_TABLE_SIZE              16384
#define TUNNEL_SMAC_REWRITE_TABLE_SIZE         512
#define TUNNEL_DMAC_REWRITE_TABLE_SIZE         16384

#define MIRROR_SESSIONS_TABLE_SIZE             1024
#define MIRROR_COALESCING_SESSIONS_TABLE_SIZE  8

#endif
