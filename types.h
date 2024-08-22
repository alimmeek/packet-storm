#ifndef PACKET_STORM_TYPES_H
#define PACKET_STORM_TYPES_H

#include <pcap.h>

typedef struct node {
    char *addr;
    int count;
} node_t;

typedef struct list_node {
    struct list_node *next;
    node_t node;
} list_t;

typedef struct Param {
  struct pcap_pkthdr *header;
  const unsigned char *packet;
} Param;

#endif