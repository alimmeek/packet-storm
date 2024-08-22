#ifndef PACKET_STORM_ANALYSIS_H
#define PACKET_STORM_ANALYSIS_H

#include <pcap.h>

void *packet_handler(void *_i);
void packet_init(unsigned char * args, struct pcap_pkthdr *header, const unsigned char *packet);

#endif