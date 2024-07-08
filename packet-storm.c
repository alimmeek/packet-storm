#include <stdio.h>
#include <pcap.h>

/*
TODO:
    - Average packet size
    - Total volume of data received during attack
    - Destination IPs ranked by frequency (most frequent first)
    - No. packets sent with different transport layer protocols
    - Verbose option (will also print results to console)
        - Default is just a .txt file to make sharing results easier
*/

void packet_handler(struct pcap_pkthdr *header, const unsigned char *packet);

void packet_init(unsigned char * args, struct pcap_pkthdr *header, const unsigned char *packet) {
    pcap_pkthdr pkt_header;
    const unsigned char pkt_packet;

    memcpy(pkt_header, header, sizeof(pcap_pkthdr));
    memcpy(pkt_packet, packet, sizeof(unsigned char));

    packet_handler(pkt_header, pkt_packet);
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline("packet-storm.pcap", error_buffer);

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void*) &handler, NULL);

    return;
}