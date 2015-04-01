#ifndef _CTL_MESSAGES_H_
#define _CTL_MESSAGES_H_

#include <stdint.h>

#define CTL_MSG_ADD_PORT_CODE 10

typedef struct ctl_msg_add_port_s {
  uint8_t code;
  uint64_t dpid;
  uint64_t request_id;
  char iface[64];
  uint16_t port_num; /* 0 means some default value? */
} ctl_msg_add_port_t;

#define CTL_MSG_DEL_PORT_CODE 11

typedef struct ctl_msg_del_port_s {
  uint8_t code;
  uint64_t dpid;
  uint64_t request_id;
  char iface[64];
} ctl_msg_del_port_t;

#define CTL_MSG_STATUS 100
#define CTL_MSG_STATUS_SUCCESS 0
#define CTL_MSG_STATUS_ERROR 1

typedef struct ctl_msg_status_s {
  uint8_t code;
  uint64_t dpid;
  uint64_t request_id;
  int status;
} ctl_msg_status_t;

#endif
