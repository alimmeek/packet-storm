#ifndef PACKET_STORM_TYPES_H
#define PACKET_STORM_TYPES_H

#include <pcap.h>


/*
 * This file contains type definitions
*/

typedef struct node {
    char *addr;
    int count;
} node_t;

typedef struct list_node {
    struct list_node *next;
    node_t node;
} list_t;

typedef struct param_t {
  struct pcap_pkthdr *header;
  const unsigned char *packet;
} param_t;

#endif