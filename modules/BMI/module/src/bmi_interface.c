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

#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include <pcap/pcap.h>

typedef struct bmi_interface_s {
  pcap_t *pcap;
  int fd;
  pcap_dumper_t *pcap_dumper;
} bmi_interface_t;

int bmi_interface_create(bmi_interface_t **bmi, const char *device) {
  int ret = 0;
  bmi_interface_t *bmi_ = malloc(sizeof(bmi_interface_t));

  if(!bmi_) return -1;

  bmi_->pcap_dumper = NULL;

  char errbuf[PCAP_ERRBUF_SIZE];
  bmi_->pcap = pcap_create(device, errbuf);

  if(!bmi_->pcap) {
    free(bmi_);
    return -1;
  }

  if(pcap_set_promisc(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  if(pcap_set_timeout(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  if(pcap_set_immediate_mode(bmi_->pcap, 1) != 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  if ((ret = pcap_activate(bmi_->pcap)) != 0) {
    if(ret == PCAP_ERROR_IFACE_NOT_UP) {
        printf("Port Not up - Failing data port creation for %s\n", device);
    }
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  bmi_->fd = pcap_get_selectable_fd(bmi_->pcap);
  if(bmi_->fd < 0) {
    pcap_close(bmi_->pcap);
    free(bmi_);
    return -1;
  }

  *bmi = bmi_;
  return 0;
}

int bmi_interface_destroy(bmi_interface_t *bmi) {
  pcap_close(bmi->pcap);
  if(bmi->pcap_dumper) pcap_dump_close(bmi->pcap_dumper);
  free(bmi);
  return 0;
}

int bmi_interface_add_dumper(bmi_interface_t *bmi, const char *filename) {
  if((bmi->pcap_dumper = pcap_dump_open(bmi->pcap, filename)) == NULL) {
    return -1;
  }
  return 0;
}

int bmi_interface_send(bmi_interface_t *bmi, const char *data, int len) {
  int ret;

  if(bmi->pcap_dumper) {
    struct pcap_pkthdr pkt_header;
    memset(&pkt_header, 0, sizeof(pkt_header));
    gettimeofday(&pkt_header.ts, NULL);
    pkt_header.caplen = len;
    pkt_header.len = len;
    pcap_dump((unsigned char *) bmi->pcap_dumper, &pkt_header,
	      (unsigned char *) data);
    pcap_dump_flush(bmi->pcap_dumper);
  }

  ret = pcap_sendpacket(bmi->pcap, (unsigned char *) data, len);
  if (ret != 0) {
      pcap_perror(bmi->pcap, "bmi_interface_send");
  }
  return ret;
}

/* Does not make a copy! */
int bmi_interface_recv(bmi_interface_t *bmi, const char **data) {
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if(pcap_next_ex(bmi->pcap, &pkt_header, &pkt_data) != 1) {
    return -1;
  }

  if(pkt_header->caplen != pkt_header->len) {
    return -1;
  }

  if(bmi->pcap_dumper) {
    pcap_dump((unsigned char *) bmi->pcap_dumper, pkt_header, pkt_data);
    pcap_dump_flush(bmi->pcap_dumper);
  }

  *data = (const char *) pkt_data;

  return pkt_header->len;
}

int bmi_interface_recv_with_copy(bmi_interface_t *bmi, char *data, int max_len) {
  int rv;
  struct pcap_pkthdr *pkt_header;
  const unsigned char *pkt_data;

  if(pcap_next_ex(bmi->pcap, &pkt_header, &pkt_data) != 1) {
    return -1;
  }

  if(pkt_header->caplen != pkt_header->len) {
    return -1;
  }

  if(bmi->pcap_dumper) {
    pcap_dump((unsigned char *) bmi->pcap_dumper, pkt_header, pkt_data);
    pcap_dump_flush(bmi->pcap_dumper);
  }

  rv = (max_len < pkt_header->len) ? max_len : pkt_header->len;

  memcpy(data, pkt_data, rv);

  return rv;
}

int bmi_interface_get_fd(bmi_interface_t *bmi) {
  return bmi->fd;
}
