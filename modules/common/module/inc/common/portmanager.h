#ifndef _PORTMANAGER_H_
#define _PORTMANAGER_H_

/* Common port manager header file. */

#include <common/common_types.h>

typedef void (*p4_packet_handler_vector_f)(uint32_t port_num,
                                            uint8_t *buffer,
                                            int length);

extern void
p4_packet_handler_vector_set(p4_packet_handler_vector_f fn);

extern p4_error_t p4_port_init(int port_count);
extern p4_error_t p4_port_finish(void);

extern p4_error_t p4_port_interface_add(char *ifname, uint32_t port_num,
					  char *sw_name, int dump_pcap);
extern p4_error_t p4_port_interface_remove(char *ifname);

extern p4_error_t p4_port_packet_emit(uint32_t port_num,
                                        uint16_t queue_id,
                                        uint8_t *data, int len);

extern void p4_set_pcap_outdir( char *outdir_name );

#endif /* _PORTMANAGER_H_ */
