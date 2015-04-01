/****************************************************************
 * 
 * This code derived from the Indigo PortManager module
 * git@github.com:floodlight/indigo.git
 *
 *        Copyright 2013, Big Switch Networks, Inc. 
 *        Copyright 2013, Barefoot Networks, Inc. 
 *
 * Licensed under the Eclipse Public License, Version 1.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 * 
 *        http://www.eclipse.org/legal/epl-v10.html
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the
 * License.
 * 
 ***************************************************************/

#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <asm/types.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/sockios.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <errno.h>

#include <VPI/vpi.h>
#include <SocketManager/socketmanager.h>

#include <indigo/types.h>

#include <common/portmanager.h>
#include <common/common_config.h>
#include <common/common_porting.h>
#include <common/common_types.h>

#include "common_log.h"

/* The vector for the packet handler */

static p4_packet_handler_vector_f packet_handler_vector;

/* Can hard code here or direct to vector above */
#define PACKET_HANDLER_VECTOR packet_handler_vector

void
p4_packet_handler_vector_set(p4_packet_handler_vector_f fn)
{
    packet_handler_vector = fn;
}


#define MAX_PKT_LEN   16384     /* Maximum packet length */
#define PORT_COUNT_MAX 512

/* Per-port data */
typedef struct port_info_s {
    char     ifname[128];       /* Name of port's VPI or Linux network intf */
    vpi_t    vpi;               /* VPI handle; NULL = not in use */
    uint64_t cnt_tx_pkts;       /* Transmitted packets counter */
    uint64_t cnt_tx_bytes;      /* Transmitted bytes counter */
    uint64_t cnt_rx_pkts;       /* Received packets counter */
    uint64_t cnt_rx_bytes;      /* Received bytes counter */
} port_info_t;

static port_info_t port_info[PORT_COUNT_MAX];

static int p4_port_count = 0;

// if p4_set_pcap_outdir is called the passed path name
// is copied here and pcap_output_dir is set to point to it
char  pcap_output_dir_storage[180] = {0};

char  pcap_output_dir_storage_default[2] = {'.', 0};
char *pcap_output_dir = pcap_output_dir_storage_default;

#include <sys/stat.h>
#include <sys/types.h>
int mkdir(const char *pathname, mode_t mode);

/* p4_set_pcap_outdir
 *
 */
void p4_set_pcap_outdir( char *outdir_name )
{
    sprintf( pcap_output_dir_storage, "%s", outdir_name );
    pcap_output_dir = pcap_output_dir_storage;
    mkdir( pcap_output_dir, 0777 );
}

/*
 * Follow the semantics that 0 is not used as a port number.
 * Subtract 1 from the port num to get the port_info index
 */
static int
port_number_valid(uint32_t port_num)
{
    return (port_num >= 0 && port_num <= p4_port_count);
}


/* Return pointer to port structure for given port number */

static port_info_t *
port_num_to_info(uint32_t port_num)
{
    return &port_info[port_num];
}

/* Check if a port is in use */
#define PORT_IN_USE(port_info) ((port_info)->vpi != NULL)


/* Return a pollable file descriptor */

static int
port2fd(port_info_t *pi)
{
    return vpi_descriptor_get(pi->vpi);
}

/* @FIXME Need port stats interface */

/* Process packet received on socket */

static void pkt_rx(int fd,
                   void *cookie,
                   int read_ready,
                   int write_ready,
                   int error_seen)
{
    int idx;
    port_info_t *pi = NULL;
    uint8_t buf[MAX_PKT_LEN];
    int len;
    int port_num;

    /* Ignore some params */
    COMPILER_REFERENCE(cookie);
    COMPILER_REFERENCE(write_ready);
    COMPILER_REFERENCE(error_seen);

    /* Find corresponding port */
    for (idx = 0; idx < p4_port_count; idx++) {
        if (fd == port2fd(&port_info[idx])) {
            pi = &port_info[idx];
            break;
        }
    }

    if (pi == NULL) {
        LOG_ERROR("RX:  Could not map fd %d to port", fd);
        return;
    }

    port_num = idx;
    LOG_TRACE("Packet RX for port %s (%d), fd %d", pi->ifname, port_num, fd);
    if ((len = vpi_recv(pi->vpi, buf, sizeof(buf), 0)) < 0) {
        LOG_ERROR("vpi_recv() failed");
        return;
    }

    if (len == 0) {
        /* No packet */
        LOG_TRACE("No packet data received from %s", pi->ifname);
        return; 
    }

    LOG_TRACE("Read %d bytes for port %s", len, pi->ifname);

    /* Update port stats */
    ++pi->cnt_rx_pkts;
    pi->cnt_rx_bytes += (uint64_t) len;
        
    /* Pass to the packet handler */
    if (PACKET_HANDLER_VECTOR != NULL) {
        PACKET_HANDLER_VECTOR(port_num, buf, len);
    } else {
        LOG_TRACE("Dropped packet as handler vector is NULL");
    }
}

/***************************************************************************/

/* Add the given Linux network interface as the given OF port number */
p4_error_t
p4_port_interface_add(char *ifname, uint32_t port_num,
		       char *sw_name, int dump_pcap)
{
    port_info_t *pi;
    vpi_t vpi = NULL;
    int fd;
    char vpi_spec[1024];

    LOG_INFO("Adding interface %s as port %d", ifname, port_num);

    if (!port_number_valid(port_num)) {
        LOG_ERROR("Invalid port number");
        return P4_E_PARAM;
    }

    if (PORT_IN_USE(pi = port_num_to_info(port_num))) {
        LOG_ERROR("OF port number in use");
        return P4_E_EXISTS;
    }

    /* @fixme Should check if name already exists */

    /*
     * Assume ifname refers to a network adapter unless it has a pipe character
     * in it.
     */
    if (strchr(ifname, '|') == NULL) {
        snprintf(vpi_spec, sizeof(vpi_spec), "pcap|%s", ifname);
    } else {
        strncpy(vpi_spec, ifname, sizeof(vpi_spec));
    }

    vpi = vpi_create(vpi_spec);
    if (vpi == NULL) {
        LOG_ERROR("vpi_create() failed");
        return P4_E_UNKNOWN;
    }

    if(dump_pcap)
    {
        snprintf(vpi_spec, sizeof(vpi_spec),
                 "pcapdump|%s/p4ns.%s-port%.2d.pcap", 
                 pcap_output_dir, sw_name, port_num); 
        vpi_add_sendrecv_listener_spec(vpi, vpi_spec);
    }


    COMMON_MEMSET(pi, 0, sizeof(*pi));
    COMMON_STRNCPY(pi->ifname, ifname, sizeof(pi->ifname) - 1);
    pi->ifname[sizeof(pi->ifname) - 1] = 0;
    pi->vpi = vpi;

    if ((fd = port2fd(pi)) == -1) {
        LOG_ERROR("port2fd() failed");
        if (vpi != NULL) {
            vpi_destroy(vpi);
            pi->vpi = NULL;
        }
    } else {
        /* Register to receive packets */
        ind_soc_socket_register(fd, pkt_rx, INDIGO_COOKIE_NULL);
    }

    return P4_E_NONE;
}

/* Stop using the given Linux network interface as an OF port */

p4_error_t
p4_port_interface_remove(char *ifname)
{
    port_info_t *pi;
    int idx;

    for (idx = 0; idx < PORT_COUNT_MAX; idx++) {
        pi = &port_info[idx];
        if (PORT_IN_USE(pi)) {
            if (COMMON_STRNCMP(ifname, pi->ifname, 128) == 0) {
                LOG_INFO("Removing port %d (%s)", idx + 1, pi->ifname);
                ind_soc_socket_unregister(port2fd(pi));
                vpi_destroy(pi->vpi);
            }
        }
    }

    return P4_E_NONE;
}


/***************************************************************************/

/* Transmit given packet out OF port */

p4_error_t
p4_port_packet_emit(uint32_t port_num,
                     uint16_t queue_id,
                     uint8_t *data,
                     int len)
{      
    port_info_t *pi;
  
    LOG_TRACE("Emit %d bytes to port %d, queue %d", 
              len, port_num, queue_id);

    if (!port_number_valid(port_num)) {
        LOG_ERROR("Invalid OF port number");
        return P4_E_PARAM;
    }

    if (queue_id != 0) {
        LOG_ERROR("Invalid transmit queue");
        return P4_E_PARAM;
    }

    if (!PORT_IN_USE(pi = port_num_to_info(port_num))) {
        LOG_ERROR("Port not in use");
        return P4_E_NOT_FOUND;
    }

    /* Send packet out network interface */
    if (vpi_send(pi->vpi, data, len) < 0) {
        LOG_ERROR("vpi_send() failed");
        return P4_E_UNKNOWN;
    }

    /* Update port stats */
    ++pi->cnt_tx_pkts;
    pi->cnt_tx_bytes += len;

    return P4_E_NONE;
}


#if 0 /* Emit to group probably won't be necessary due to egress pipe arch */
/**
 * Transmit given packet out a group of ports
 *
 * The only group ID currently supported is "flood".  The value for the
 * flood group is the port-flood id, 0xfffffffb.
 */

p4_error_t
p4_port_packet_emit_group(uint32_t group_id,
                           uint32_t ingress_port_num,
                           uint8_t *data,
                           int len)
{
    port_info_t *pi;
    int idx, port_num;

    /* @FIXME Implement groups */

    LOG_TRACE("Send %d bytes to group 0x%x", len, group_id);
    for (idx = 0, port_num = 1; idx < p4_port_count; ++idx, ++port_num) {
        pi = port_num_to_info(port_num);
        if (!PORT_IN_USE(pi) || port_num == ingress_port_num) {
            continue;
        }
        (void)common_port_packet_emit(port_num, 0, data, len);
    }

    return P4_E_NONE;  /* @FIXME */
}


/* Transmit given packet out all OF ports, except given one */

p4_error_t
p4_port_packet_emit_all(uint32_t skip_port_num,
                         uint8_t *data,
                         int len)
{       
    port_info_t *pi;
    int idx, port_num;

    LOG_TRACE("Send %d bytes to all except %d", len, skip_port_num);

    for (idx = 0, port_num = 1; idx < p4_port_count; ++idx, ++port_num) {
        pi = port_num_to_info(port_num);
        if (!PORT_IN_USE(pi) || port_num == skip_port_num) {
            continue;
        }
        (void)common_port_packet_emit(port_num, 0, data, len);
    }

    return P4_E_NONE;  /* @FIXME */
}

#endif

/***************************************************************************/

/* Initialize module */

p4_error_t
p4_port_init(int port_count)
{
    LOG_TRACE("Init called");
    vpi_init();

    if (port_count >= PORT_COUNT_MAX) {
        LOG_ERROR("Too many ports for port manager: %d > %d",
                  port_count, PORT_COUNT_MAX);
        return P4_E_PARAM;
    }

    p4_port_count = port_count;

    COMMON_MEMSET(port_info, 0, sizeof(port_info));

    return P4_E_NONE;
}

p4_error_t
p4_port_finish(void)
{
    LOG_TRACE("Finish called");

    return P4_E_NONE;
}

