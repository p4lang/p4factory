/*
Copyright 2013-present Barefoot Networks, Inc. 
Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/
/*
* SAI auto generated header file
*/

#ifndef _SAI_TEMPL_H
#define _SAI_TEMPL_H

#include <p4_sim/saitypes.h>






/*
*  Attribute Id for sai switch object
*/

typedef enum  _sai_switch__attr_t {
        SAI_SWITCH_ATTR_PACKET_ACTION,
        SAI_SWITCH_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_switch_attr_t;

typedef sai_status_t (*sai_create_switch_fn)(
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_switch_fn)(
    );

typedef sai_status_t (*sai_set_switch_attribute_fn)(
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_switch_attribute_fn)(
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_switchs_fn)(void);



typedef struct _sai_switch_api_t
{
    sai_create_switch_fn                      create_switch;
    sai_remove_switch_fn                      remove_switch;
    sai_set_switch_attribute_fn               set_switch_attribute;
    sai_get_switch_attribute_fn               get_switch_attribute;
    sai_remove_all_switchs_fn                 remove_all_switchs;
} sai_switch_api_t;




/*
*   PORT Table API
*/

/*
*  This module defines SAI PORT API
*/
typedef struct _sai_port_entry_t {
  uint16_t standard_metadata_ingress_port;
} sai_port_entry_t;

/*
*  Attribute Id for sai port object
*/

typedef enum  _sai_port__attr_t {
        SAI_PORT_ATTR_PACKET_ACTION,
        SAI_PORT_ATTR_PORT,
        SAI_PORT_ATTR_TYPE_,
        SAI_PORT_ATTR_OPER_STATUS,
        SAI_PORT_ATTR_SPEED,
        SAI_PORT_ATTR_INGRESS_FILTERING,
        SAI_PORT_ATTR_DROP_UNTAGGED,
        SAI_PORT_ATTR_DROP_TAGGED,
        SAI_PORT_ATTR_PORT_LOOPBACK_MODE,
        SAI_PORT_ATTR_FDB_LEARNING,
        SAI_PORT_ATTR_STP_STATE,
        SAI_PORT_ATTR_UPDATE_DSCP,
        SAI_PORT_ATTR_MTU,
        SAI_PORT_ATTR_GLOBAL_FLOW_CONTROL,
        SAI_PORT_ATTR_MAX_LEARNED_ADDRESS,
        SAI_PORT_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_port_attr_t;

typedef sai_status_t (*sai_create_port_fn)(
    _In_ const sai_port_entry_t* port_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_port_fn)(
    _In_ const sai_port_entry_t* port_entry
    );

typedef sai_status_t (*sai_set_port_attribute_fn)(
    _In_ const sai_port_entry_t* port_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_port_attribute_fn)(
    _In_ const sai_port_entry_t* port_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_ports_fn)(void);


typedef enum _sai_port_stat_counter_t
{
    SAI_PORT_STAT_PACKETS
} sai_port_stat_counter_t;

typedef sai_status_t (*sai_get_port_stats_fn)(
    _In_ sai_port_entry_t* port_entry,
    _In_ const sai_port_stat_counter_t *counter_ids,
    _In_ uint32_t number_of_counters,
    _Out_ uint64_t* counters
    );

typedef struct _sai_port_api_t
{
    sai_create_port_fn                      create_port;
    sai_remove_port_fn                      remove_port;
    sai_set_port_attribute_fn               set_port_attribute;
    sai_get_port_attribute_fn               get_port_attribute;
    sai_remove_all_ports_fn                 remove_all_ports;
    sai_get_port_stats_fn                   get_port_stats;
} sai_port_api_t;




/*
*   VLAN Table API
*/

/*
*  This module defines SAI VLAN API
*/
typedef struct _sai_vlan_ports_t {
  uint16_t vlan_vid;
  uint16_t standard_metadata_ingress_port;
} sai_vlan_ports_t;


typedef struct _sai_vlan_entry_t {
  uint16_t vlan_vid;
} sai_vlan_entry_t;

/*
*  Attribute Id for sai vlan object
*/

typedef enum  _sai_vlan__attr_t {
        SAI_VLAN_ATTR_PACKET_ACTION,
        SAI_VLAN_ATTR_MAX_LEARNED_ADDRESS,
        SAI_VLAN_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_vlan_attr_t;

typedef sai_status_t (*sai_create_vlan_fn)(
    _In_ const sai_vlan_entry_t* vlan_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_vlan_fn)(
    _In_ const sai_vlan_entry_t* vlan_entry
    );

typedef sai_status_t (*sai_set_vlan_attribute_fn)(
    _In_ const sai_vlan_entry_t* vlan_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_vlan_attribute_fn)(
    _In_ const sai_vlan_entry_t* vlan_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_vlans_fn)(void);

/*
    Member add/delete functions for vlan
*/
typedef sai_status_t (*sai_add_ports_to_vlan_fn)(
    _In_ sai_vlan_entry_t* vlan_entry,
    _In_ uint32_t ports_count,
    _In_ const sai_vlan_ports_t* ports_list
    );

typedef sai_status_t (*sai_remove_ports_from_vlan_fn)(
    _In_ sai_vlan_entry_t* vlan_entry,
    _In_ uint32_t ports_count,
    _In_ const sai_vlan_ports_t* ports_list
    );

typedef enum _sai_vlan_stat_counter_t
{
    SAI_VLAN_STAT_PACKETS
} sai_vlan_stat_counter_t;

typedef sai_status_t (*sai_get_vlan_stats_fn)(
    _In_ sai_vlan_entry_t* vlan_entry,
    _In_ const sai_vlan_stat_counter_t *counter_ids,
    _In_ uint32_t number_of_counters,
    _Out_ uint64_t* counters
    );

typedef struct _sai_vlan_api_t
{
    sai_create_vlan_fn                      create_vlan;
    sai_remove_vlan_fn                      remove_vlan;
    sai_set_vlan_attribute_fn               set_vlan_attribute;
    sai_get_vlan_attribute_fn               get_vlan_attribute;
    sai_add_ports_to_vlan_fn  add_ports_to_vlan;
    sai_remove_ports_from_vlan_fn remove_ports_from_vlan;
    sai_remove_all_vlans_fn                 remove_all_vlans;
    sai_get_vlan_stats_fn                   get_vlan_stats;
} sai_vlan_api_t;




/*
*   LEARN_NOTIFY Table API
*/

/*
*  This module defines SAI LEARN_NOTIFY API
*/
typedef struct _sai_learn_notify_entry_t {
  uint16_t ingress_metadata_vlan_id;
  uint8_t eth_srcAddr[6];
} sai_learn_notify_entry_t;

/*
*  Attribute Id for sai learn_notify object
*/

typedef enum  _sai_learn_notify__attr_t {
        SAI_LEARN_NOTIFY_ATTR_PACKET_ACTION,
        SAI_LEARN_NOTIFY_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_learn_notify_attr_t;

typedef sai_status_t (*sai_create_learn_notify_fn)(
    _In_ const sai_learn_notify_entry_t* learn_notify_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_learn_notify_fn)(
    _In_ const sai_learn_notify_entry_t* learn_notify_entry
    );

typedef sai_status_t (*sai_set_learn_notify_attribute_fn)(
    _In_ const sai_learn_notify_entry_t* learn_notify_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_learn_notify_attribute_fn)(
    _In_ const sai_learn_notify_entry_t* learn_notify_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_learn_notifys_fn)(void);



typedef struct _sai_learn_notify_api_t
{
    sai_create_learn_notify_fn                      create_learn_notify;
    sai_remove_learn_notify_fn                      remove_learn_notify;
    sai_set_learn_notify_attribute_fn               set_learn_notify_attribute;
    sai_get_learn_notify_attribute_fn               get_learn_notify_attribute;
    sai_remove_all_learn_notifys_fn                 remove_all_learn_notifys;
} sai_learn_notify_api_t;




/*
*   FDB Table API
*/

/*
*  This module defines SAI FDB API
*/
typedef struct _sai_fdb_entry_t {
  uint16_t ingress_metadata_vlan_id;
  uint8_t eth_dstAddr[6];
} sai_fdb_entry_t;

/*
*  Attribute Id for sai fdb object
*/

typedef enum  _sai_fdb__attr_t {
        SAI_FDB_ATTR_PACKET_ACTION,
        SAI_FDB_ATTR_TYPE_,
        SAI_FDB_ATTR_PORT_ID,
        SAI_FDB_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_fdb_attr_t;

typedef sai_status_t (*sai_create_fdb_fn)(
    _In_ const sai_fdb_entry_t* fdb_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_fdb_fn)(
    _In_ const sai_fdb_entry_t* fdb_entry
    );

typedef sai_status_t (*sai_set_fdb_attribute_fn)(
    _In_ const sai_fdb_entry_t* fdb_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_fdb_attribute_fn)(
    _In_ const sai_fdb_entry_t* fdb_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_fdbs_fn)(void);



typedef struct _sai_fdb_api_t
{
    sai_create_fdb_fn                      create_fdb;
    sai_remove_fdb_fn                      remove_fdb;
    sai_set_fdb_attribute_fn               set_fdb_attribute;
    sai_get_fdb_attribute_fn               get_fdb_attribute;
    sai_remove_all_fdbs_fn                 remove_all_fdbs;
} sai_fdb_api_t;




/*
*   ROUTE Table API
*/

/*
*  This module defines SAI ROUTE API
*/
typedef struct _sai_route_entry_t {
  uint16_t ingress_metadata_vrf;
  uint32_t ipv4_dstAddr;
  uint16_t ipv4_dstAddr_prefix_length;
} sai_route_entry_t;

/*
*  Attribute Id for sai route object
*/

typedef enum  _sai_route__attr_t {
        SAI_ROUTE_ATTR_PACKET_ACTION,
        SAI_ROUTE_ATTR_TRAP_PRIORITY,
        SAI_ROUTE_ATTR_NEXT_HOP_ID,
        SAI_ROUTE_ATTR_NEXT_HOP_GROUP_ID,
        SAI_ROUTE_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_route_attr_t;

typedef sai_status_t (*sai_create_route_fn)(
    _In_ const sai_route_entry_t* route_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_route_fn)(
    _In_ const sai_route_entry_t* route_entry
    );

typedef sai_status_t (*sai_set_route_attribute_fn)(
    _In_ const sai_route_entry_t* route_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_route_attribute_fn)(
    _In_ const sai_route_entry_t* route_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_routes_fn)(void);



typedef struct _sai_route_api_t
{
    sai_create_route_fn                      create_route;
    sai_remove_route_fn                      remove_route;
    sai_set_route_attribute_fn               set_route_attribute;
    sai_get_route_attribute_fn               get_route_attribute;
    sai_remove_all_routes_fn                 remove_all_routes;
} sai_route_api_t;




/*
*   NEXT_HOP Table API
*/

/*
*  This module defines SAI NEXT_HOP API
*/
typedef struct _sai_next_hop_entry_t {
  uint16_t ingress_metadata_nhop;
} sai_next_hop_entry_t;

/*
*  Attribute Id for sai next_hop object
*/

typedef enum  _sai_next_hop__attr_t {
        SAI_NEXT_HOP_ATTR_PACKET_ACTION,
        SAI_NEXT_HOP_ATTR_ROUTER_INTERFACE_ID,
        SAI_NEXT_HOP_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_next_hop_attr_t;

typedef sai_status_t (*sai_create_next_hop_fn)(
    _In_ const sai_next_hop_entry_t* next_hop_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_next_hop_fn)(
    _In_ const sai_next_hop_entry_t* next_hop_entry
    );

typedef sai_status_t (*sai_set_next_hop_attribute_fn)(
    _In_ const sai_next_hop_entry_t* next_hop_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_next_hop_attribute_fn)(
    _In_ const sai_next_hop_entry_t* next_hop_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_next_hops_fn)(void);



typedef struct _sai_next_hop_api_t
{
    sai_create_next_hop_fn                      create_next_hop;
    sai_remove_next_hop_fn                      remove_next_hop;
    sai_set_next_hop_attribute_fn               set_next_hop_attribute;
    sai_get_next_hop_attribute_fn               get_next_hop_attribute;
    sai_remove_all_next_hops_fn                 remove_all_next_hops;
} sai_next_hop_api_t;




/*
*   NEXT_HOP_GROUP Table API
*/

/*
*  This module defines SAI NEXT_HOP_GROUP API
*/
typedef struct _sai_next_hop_group_nexthop_t {
  uint16_t ingress_metadata_ecmp_nhop;
} sai_next_hop_group_nexthop_t;


typedef struct _sai_next_hop_group_entry_t {
  uint16_t ingress_metadata_ecmp_nhop;
} sai_next_hop_group_entry_t;

/*
*  Attribute Id for sai next_hop_group object
*/

typedef enum  _sai_next_hop_group__attr_t {
        SAI_NEXT_HOP_GROUP_ATTR_PACKET_ACTION,
        SAI_NEXT_HOP_GROUP_ATTR_ROUTER_INTERFACE_ID,
        SAI_NEXT_HOP_GROUP_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_next_hop_group_attr_t;

typedef sai_status_t (*sai_create_next_hop_group_fn)(
    _In_ const sai_next_hop_group_entry_t* next_hop_group_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_next_hop_group_fn)(
    _In_ const sai_next_hop_group_entry_t* next_hop_group_entry
    );

typedef sai_status_t (*sai_set_next_hop_group_attribute_fn)(
    _In_ const sai_next_hop_group_entry_t* next_hop_group_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_next_hop_group_attribute_fn)(
    _In_ const sai_next_hop_group_entry_t* next_hop_group_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_next_hop_groups_fn)(void);

/*
    Member add/delete functions for next_hop_group
*/
typedef sai_status_t (*sai_add_nexthop_to_next_hop_group_fn)(
    _In_ sai_next_hop_group_entry_t* next_hop_group_entry,
    _In_ uint32_t nexthop_count,
    _In_ const sai_next_hop_group_nexthop_t* nexthop_list
    );

typedef sai_status_t (*sai_remove_nexthop_from_next_hop_group_fn)(
    _In_ sai_next_hop_group_entry_t* next_hop_group_entry,
    _In_ uint32_t nexthop_count,
    _In_ const sai_next_hop_group_nexthop_t* nexthop_list
    );


typedef struct _sai_next_hop_group_api_t
{
    sai_create_next_hop_group_fn                      create_next_hop_group;
    sai_remove_next_hop_group_fn                      remove_next_hop_group;
    sai_set_next_hop_group_attribute_fn               set_next_hop_group_attribute;
    sai_get_next_hop_group_attribute_fn               get_next_hop_group_attribute;
    sai_add_nexthop_to_next_hop_group_fn  add_nexthop_to_next_hop_group;
    sai_remove_nexthop_from_next_hop_group_fn remove_nexthop_from_next_hop_group;
    sai_remove_all_next_hop_groups_fn                 remove_all_next_hop_groups;
} sai_next_hop_group_api_t;




/*
*   QOS Table API
*/

/*
*  This module defines SAI QOS API
*/
typedef struct _sai_qos_entry_t {
  uint16_t standard_metadata_ingress_port;
} sai_qos_entry_t;

/*
*  Attribute Id for sai qos object
*/

typedef enum  _sai_qos__attr_t {
        SAI_QOS_ATTR_PACKET_ACTION,
        SAI_QOS_ATTR_PRIORITY,
        SAI_QOS_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_qos_attr_t;

typedef sai_status_t (*sai_create_qos_fn)(
    _In_ const sai_qos_entry_t* qos_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_qos_fn)(
    _In_ const sai_qos_entry_t* qos_entry
    );

typedef sai_status_t (*sai_set_qos_attribute_fn)(
    _In_ const sai_qos_entry_t* qos_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_qos_attribute_fn)(
    _In_ const sai_qos_entry_t* qos_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_qoss_fn)(void);



typedef struct _sai_qos_api_t
{
    sai_create_qos_fn                      create_qos;
    sai_remove_qos_fn                      remove_qos;
    sai_set_qos_attribute_fn               set_qos_attribute;
    sai_get_qos_attribute_fn               get_qos_attribute;
    sai_remove_all_qoss_fn                 remove_all_qoss;
} sai_qos_api_t;




/*
*   COS_MAP Table API
*/

/*
*  This module defines SAI COS_MAP API
*/
typedef struct _sai_cos_map_entry_t {
  uint16_t standard_metadata_ingress_port;
  uint8_t ingress_metadata_qos_selector;
  uint8_t ingress_metadata_cos_index;
} sai_cos_map_entry_t;

/*
*  Attribute Id for sai cos_map object
*/

typedef enum  _sai_cos_map__attr_t {
        SAI_COS_MAP_ATTR_PACKET_ACTION,
        SAI_COS_MAP_ATTR_COS_VALUE,
        SAI_COS_MAP_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_cos_map_attr_t;

typedef sai_status_t (*sai_create_cos_map_fn)(
    _In_ const sai_cos_map_entry_t* cos_map_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_cos_map_fn)(
    _In_ const sai_cos_map_entry_t* cos_map_entry
    );

typedef sai_status_t (*sai_set_cos_map_attribute_fn)(
    _In_ const sai_cos_map_entry_t* cos_map_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_cos_map_attribute_fn)(
    _In_ const sai_cos_map_entry_t* cos_map_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_cos_maps_fn)(void);



typedef struct _sai_cos_map_api_t
{
    sai_create_cos_map_fn                      create_cos_map;
    sai_remove_cos_map_fn                      remove_cos_map;
    sai_set_cos_map_attribute_fn               set_cos_map_attribute;
    sai_get_cos_map_attribute_fn               get_cos_map_attribute;
    sai_remove_all_cos_maps_fn                 remove_all_cos_maps;
} sai_cos_map_api_t;




/*
*   ROUTER_INTERFACE Table API
*/

/*
*  This module defines SAI ROUTER_INTERFACE API
*/
typedef struct _sai_router_interface_entry_t {
  uint16_t ingress_metadata_rif_id;
} sai_router_interface_entry_t;

/*
*  Attribute Id for sai router_interface object
*/

typedef enum  _sai_router_interface__attr_t {
        SAI_ROUTER_INTERFACE_ATTR_PACKET_ACTION,
        SAI_ROUTER_INTERFACE_ATTR_TYPE_,
        SAI_ROUTER_INTERFACE_ATTR_VLAN_ID,
        SAI_ROUTER_INTERFACE_ATTR_SRC_MAC_ADDRESS,
        SAI_ROUTER_INTERFACE_ATTR_ADMIN_V4_STATE,
        SAI_ROUTER_INTERFACE_ATTR_ADMIN_V6_STATE,
        SAI_ROUTER_INTERFACE_ATTR_MTU,
        SAI_ROUTER_INTERFACE_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_router_interface_attr_t;

typedef sai_status_t (*sai_create_router_interface_fn)(
    _In_ const sai_router_interface_entry_t* router_interface_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_router_interface_fn)(
    _In_ const sai_router_interface_entry_t* router_interface_entry
    );

typedef sai_status_t (*sai_set_router_interface_attribute_fn)(
    _In_ const sai_router_interface_entry_t* router_interface_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_router_interface_attribute_fn)(
    _In_ const sai_router_interface_entry_t* router_interface_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_router_interfaces_fn)(void);



typedef struct _sai_router_interface_api_t
{
    sai_create_router_interface_fn                      create_router_interface;
    sai_remove_router_interface_fn                      remove_router_interface;
    sai_set_router_interface_attribute_fn               set_router_interface_attribute;
    sai_get_router_interface_attribute_fn               get_router_interface_attribute;
    sai_remove_all_router_interfaces_fn                 remove_all_router_interfaces;
} sai_router_interface_api_t;




/*
*   VIRTUAL_ROUTER Table API
*/

/*
*  This module defines SAI VIRTUAL_ROUTER API
*/
typedef struct _sai_virtual_router_entry_t {
  uint16_t ingress_metadata_vrf;
} sai_virtual_router_entry_t;

/*
*  Attribute Id for sai virtual_router object
*/

typedef enum  _sai_virtual_router__attr_t {
        SAI_VIRTUAL_ROUTER_ATTR_PACKET_ACTION,
        SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V4_STATE,
        SAI_VIRTUAL_ROUTER_ATTR_ADMIN_V6_STATE,
        SAI_VIRTUAL_ROUTER_ATTR_SRC_MAC_ADDRESS,
        SAI_VIRTUAL_ROUTER_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_virtual_router_attr_t;

typedef sai_status_t (*sai_create_virtual_router_fn)(
    _In_ const sai_virtual_router_entry_t* virtual_router_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_virtual_router_fn)(
    _In_ const sai_virtual_router_entry_t* virtual_router_entry
    );

typedef sai_status_t (*sai_set_virtual_router_attribute_fn)(
    _In_ const sai_virtual_router_entry_t* virtual_router_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_virtual_router_attribute_fn)(
    _In_ const sai_virtual_router_entry_t* virtual_router_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_virtual_routers_fn)(void);



typedef struct _sai_virtual_router_api_t
{
    sai_create_virtual_router_fn                      create_virtual_router;
    sai_remove_virtual_router_fn                      remove_virtual_router;
    sai_set_virtual_router_attribute_fn               set_virtual_router_attribute;
    sai_get_virtual_router_attribute_fn               get_virtual_router_attribute;
    sai_remove_all_virtual_routers_fn                 remove_all_virtual_routers;
} sai_virtual_router_api_t;




/*
*   NEIGHBOR Table API
*/

/*
*  This module defines SAI NEIGHBOR API
*/
typedef struct _sai_neighbor_entry_t {
  uint16_t ingress_metadata_vrf;
  uint32_t ingress_metadata_ip_dest;
  uint16_t ingress_metadata_router_intf;
} sai_neighbor_entry_t;

/*
*  Attribute Id for sai neighbor object
*/

typedef enum  _sai_neighbor__attr_t {
        SAI_NEIGHBOR_ATTR_PACKET_ACTION,
        SAI_NEIGHBOR_ATTR_DST_MAC_ADDRESS,
        SAI_NEIGHBOR_ATTR_CUSTOM_RANGE_BASE  = 0x10000000
} sai_neighbor_attr_t;

typedef sai_status_t (*sai_create_neighbor_fn)(
    _In_ const sai_neighbor_entry_t* neighbor_entry,
    _In_ uint32_t attr_count,
    _In_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_neighbor_fn)(
    _In_ const sai_neighbor_entry_t* neighbor_entry
    );

typedef sai_status_t (*sai_set_neighbor_attribute_fn)(
    _In_ const sai_neighbor_entry_t* neighbor_entry,
    _In_ const sai_attribute_t *attr
    );

typedef sai_status_t (*sai_get_neighbor_attribute_fn)(
    _In_ const sai_neighbor_entry_t* neighbor_entry,
    _In_ uint32_t attr_count,
    _Inout_ const sai_attribute_t *attr_list
    );

typedef sai_status_t (*sai_remove_all_neighbors_fn)(void);



typedef struct _sai_neighbor_api_t
{
    sai_create_neighbor_fn                      create_neighbor;
    sai_remove_neighbor_fn                      remove_neighbor;
    sai_set_neighbor_attribute_fn               set_neighbor_attribute;
    sai_get_neighbor_attribute_fn               get_neighbor_attribute;
    sai_remove_all_neighbors_fn                 remove_all_neighbors;
} sai_neighbor_api_t;


#endif // _SAI_TEMPL_H

