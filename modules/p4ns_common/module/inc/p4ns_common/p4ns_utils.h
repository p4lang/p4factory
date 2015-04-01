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

#ifndef _P4NS_UTILS_H_
#define _P4NS_UTILS_H_

#include <stdint.h>

#define P4NS_PROTO_IPV4 1
#define P4NS_PROTO_IPV6 2

typedef struct p4ns_tcp_over_ip_s {
  int proto;
  char ip[128];
  uint16_t port;
} p4ns_tcp_over_ip_t;

int parse_connection(const char *str,
		     p4ns_tcp_over_ip_t *tcp_over_ip,
		     uint16_t default_port);

int sendall(int sckt, char *buf, int len);
int recvall(int sckt, char *buf, int len);

#endif
