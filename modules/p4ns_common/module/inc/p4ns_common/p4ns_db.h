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

#ifndef _P4NS_DB_H_
#define _P4NS_DB_H_

#include <hiredis/hiredis.h>
#include "p4ns_utils.h"

#define P4NSDB_DEFAULT_PORT 6379

#define P4NSDB_SUCCESS 0
#define P4NSDB_ERROR_INVALID_DATAPATH 10
#define P4NSDB_ERROR_DATAPATH_EXISTS 11
#define P4NSDB_ERROR_INVALID_PORT 20
#define P4NSDB_ERROR_PORT_EXISTS 21
#define P4NSDB_ERROR_PORT_NUM_TAKEN 30

typedef redisContext *p4ns_db_cxt_t;

p4ns_db_cxt_t p4ns_db_connect(char *ipv4, uint16_t port);
void p4ns_db_free(p4ns_db_cxt_t c);

int p4ns_db_has_datapath(p4ns_db_cxt_t c, const char *name);

int p4ns_db_add_datapath(p4ns_db_cxt_t c,
			 const char *name, uint64_t dpid);

int p4ns_db_del_datapath(p4ns_db_cxt_t c,
			 const char *name);

int p4ns_db_set_listener(p4ns_db_cxt_t c,
			 const char *name,
			 p4ns_tcp_over_ip_t *listener);

int p4ns_db_get_listener(p4ns_db_cxt_t c,
			 const char *name,
			 p4ns_tcp_over_ip_t *listener);

int p4ns_db_add_port(p4ns_db_cxt_t c,
		     const char *name, const char *iface, uint16_t port_num);

int p4ns_db_del_port(p4ns_db_cxt_t c,
		     const char *name, const char *iface);

int p4ns_db_has_port(p4ns_db_cxt_t c,
		     const char *name, const char *iface);

int p4ns_db_has_port_num(p4ns_db_cxt_t c,
			 const char *name, uint16_t port_num);

int p4ns_db_get_first_port_num(p4ns_db_cxt_t c,
			       const char *name,
			       uint16_t *port_num);

int p4ns_db_flush(p4ns_db_cxt_t c);

#endif
