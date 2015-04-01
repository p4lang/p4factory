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

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <assert.h>
#include <p4ns_common/p4ns_db.h>

#define DB_CONNECT_TIMEOUT_SECS 1

typedef struct p4ns_port_s {
  uint16_t port_num;
  char iface[64];
} p4ns_port_t;

typedef struct p4ns_config_s {
  char datapath_name[64];
  uint64_t dpid;
  p4ns_tcp_over_ip_t listener;
} p4ns_config_t;


p4ns_db_cxt_t p4ns_db_connect(char *ipv4, uint16_t port) {
  struct timeval timeout = { DB_CONNECT_TIMEOUT_SECS, 0 };
  redisContext *c = redisConnectWithTimeout(ipv4, port, timeout);
  if (c == NULL || c->err) {
    return NULL;
  }
  return c;
}

void p4ns_db_free(p4ns_db_cxt_t c){
  redisFree(c);
}

int p4ns_db_has_datapath(p4ns_db_cxt_t c,
			 const char *name) {
  redisReply *reply;
  reply = redisCommand(c, "EXISTS %s", name);
  int ret = (reply->integer == 1);
  freeReplyObject(reply);
  return ret;
}

int p4ns_db_add_datapath(p4ns_db_cxt_t c,
			 const char *name, uint64_t dpid) {
  if(p4ns_db_has_datapath(c, name)) {
    return P4NSDB_ERROR_DATAPATH_EXISTS;
  }

  redisReply *reply;

  p4ns_config_t p4ns_config;
  memset(&p4ns_config, 0, sizeof(p4ns_config_t));
  strncpy(p4ns_config.datapath_name, name, 64);
  p4ns_config.dpid = dpid;

  reply = redisCommand(c, "SET %s %b", name,
		       (char *) &p4ns_config, sizeof(p4ns_config_t));
  freeReplyObject(reply);
  
  return 0;
}

int p4ns_db_set_listener(p4ns_db_cxt_t c,
			 const char *name,
			 p4ns_tcp_over_ip_t *listener) {
  redisReply *reply1, *reply2;
  reply1 = redisCommand(c, "GET %s", name);
  if(!reply1->str) {
    freeReplyObject(reply1);
    return P4NSDB_ERROR_INVALID_DATAPATH;
  }

  p4ns_config_t *p4ns_config = (p4ns_config_t *) reply1->str;
  memcpy(&p4ns_config->listener, listener, sizeof(p4ns_tcp_over_ip_t));

  reply2 = redisCommand(c, "SET %s %b", name,
			(char *) p4ns_config, sizeof(p4ns_config_t));
  freeReplyObject(reply1);
  freeReplyObject(reply2);
  
  return 0;
}

int p4ns_db_get_listener(p4ns_db_cxt_t c,
			 const char *name,
			 p4ns_tcp_over_ip_t *listener) {
  redisReply *reply;
  reply = redisCommand(c, "GET %s", name);
  if(!reply->str) {
    freeReplyObject(reply);
    return P4NSDB_ERROR_INVALID_DATAPATH;
  }

  p4ns_config_t *p4ns_config = (p4ns_config_t *) reply->str;
  memcpy(listener, &p4ns_config->listener, sizeof(p4ns_tcp_over_ip_t));

  freeReplyObject(reply);
  
  return 0;
}


static inline void get_ports_key(char *dest, const char *name) {
  sprintf(dest, ".%s.ports", name);
}

static inline void get_port_nums_key(char *dest, const char *name) {
  sprintf(dest, ".%s.port_nums", name);
}

static int has_port(p4ns_db_cxt_t c,
		    const char *ports_key,
		    const char *iface) {
  redisReply *reply;
  reply = redisCommand(c, "HEXISTS %s %s", ports_key, iface);
  int ret = (reply->integer == 1);
  freeReplyObject(reply);
  return ret;
}

static int has_port_num(p4ns_db_cxt_t c,
			const char *port_nums_key,
			uint16_t port_num) {
  redisReply *reply;
  reply = redisCommand(c, "SISMEMBER %s %d", port_nums_key, port_num);
  int ret = (reply->integer == 1);
  freeReplyObject(reply);
  return ret;
}

int p4ns_db_has_port(p4ns_db_cxt_t c,
		     const char *name, const char *iface) {
  char ports_key[128];
  get_ports_key(ports_key, name);

  if(!p4ns_db_has_datapath(c, name)) { /* datapath does not exist */
    return 0;
  }
  
  return has_port(c, ports_key, iface);
}

int p4ns_db_has_port_num(p4ns_db_cxt_t c,
			 const char *name, uint16_t port_num) {
  char port_nums_key[128];
  get_port_nums_key(port_nums_key, name);

  if(!p4ns_db_has_datapath(c, name)) { /* datapath does not exist */
    return 0;
  }
  
  return has_port_num(c, port_nums_key, port_num);
}

int p4ns_db_add_port(p4ns_db_cxt_t c,
		     const char *name, const char *iface, uint16_t port_num) {
  redisReply *reply;
  char ports_key[128];
  char port_nums_key[128];
  get_ports_key(ports_key, name);
  get_port_nums_key(port_nums_key, name);

  if(!p4ns_db_has_datapath(c, name)) { /* datapath does not exist */
    return P4NSDB_ERROR_INVALID_DATAPATH;
  }
  
  if(has_port(c, ports_key, iface)) { /* port exists */
    return P4NSDB_ERROR_PORT_EXISTS;
  }

  if(has_port_num(c, port_nums_key, port_num)) { /* port num taken */
    return P4NSDB_ERROR_PORT_NUM_TAKEN;
  }

  p4ns_port_t p4ns_port;
  memset(&p4ns_port, 0, sizeof(p4ns_port_t));
  p4ns_port.port_num = port_num;
  strncpy(p4ns_port.iface, iface, 64);

  reply = redisCommand(c, "HSET %s %s %b", ports_key, iface, &p4ns_port, sizeof(p4ns_port_t));
  assert(reply->integer == 1);
  freeReplyObject(reply);

  reply = redisCommand(c, "SADD %s %d", port_nums_key, port_num);
  assert(reply->integer == 1);
  freeReplyObject(reply);

  return 0;
}

int p4ns_db_del_port(p4ns_db_cxt_t c,
		     const char *name, const char *iface) {
  redisReply *reply;
  char ports_key[128];
  char port_nums_key[128];
  get_ports_key(ports_key, name);
  get_port_nums_key(port_nums_key, name);

  if(!p4ns_db_has_datapath(c, name)) { /* datapath does not exist */
    return P4NSDB_ERROR_INVALID_DATAPATH;
  }
  
  if(!has_port(c, ports_key, iface)) { /* port invalid */
    return P4NSDB_ERROR_INVALID_PORT;
  }

  reply = redisCommand(c, "HGET %s %s", ports_key, iface);
  p4ns_port_t *p4ns_port = (p4ns_port_t *) reply->str;
  uint16_t port_num = p4ns_port->port_num;
  freeReplyObject(reply);

  reply = redisCommand(c, "HDEL %s %s", ports_key, iface);
  assert(reply->integer == 1);
  freeReplyObject(reply);

  reply = redisCommand(c, "SREM %s %d", port_nums_key, port_num);
  assert(reply->integer == 1);
  freeReplyObject(reply);

  return 0;
}

int p4ns_db_del_datapath(p4ns_db_cxt_t c,
			 const char *name) {
  redisReply *reply;
  int success;
  char ports_key[128];
  char port_nums_key[128];
  get_ports_key(ports_key, name);
  get_port_nums_key(port_nums_key, name);

  reply = redisCommand(c, "DEL %s", name);
  success = (reply->integer == 1);
  freeReplyObject(reply);
  if (!success) return P4NSDB_ERROR_INVALID_DATAPATH;

  reply = redisCommand(c, "DEL %s", ports_key);
  freeReplyObject(reply);

  reply = redisCommand(c, "DEL %s", port_nums_key);
  freeReplyObject(reply);
  
  return 0;
}

int p4ns_db_get_first_port_num(p4ns_db_cxt_t c,
			       const char *name,
			       uint16_t *port_num) {
  redisReply *reply;

  if(!p4ns_db_has_datapath(c, name)) { /* datapath does not exist */
    return P4NSDB_ERROR_INVALID_DATAPATH;
  }

  char port_nums_key[128];
  get_port_nums_key(port_nums_key, name);

  *port_num = 0;
  int found = 1;
  while(found) {
    (*port_num)++;
    reply = redisCommand(c, "SISMEMBER %s %d", port_nums_key, *port_num);
    found = reply->integer;
    freeReplyObject(reply); 
  }
  
  return 0;
}

int p4ns_db_flush(p4ns_db_cxt_t c) {
  redisReply *reply;
  reply = redisCommand(c, "FLUSHDB");
  freeReplyObject(reply);
  return 0;
}
