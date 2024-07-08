#include <stdio.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <string.h>

/*
TODO:
    - Average packet size
    - Total volume of data received during attack
    - Destination IPs ranked by frequency (most frequent first)
    - No. packets sent with different transport layer protocols
    - Verbose option (will also print results to console)
        - Default is just a .txt file to make sharing results easier
*/

void packet_handler(struct pcap_pkthdr *header, const unsigned char *packet) {
    unsigned int i;
    int length = header->len;
    // Decode Packet Header
    struct ether_header *eth_header = (struct ether_header *) packet;
    printf("\n\n === PACKET HEADER ===");
    printf("\nSource MAC: ");
    for (i = 0; i < 6; ++i) {
        printf("%02x", eth_header->ether_shost[i]);
        if (i < 5) {
            printf(":");
        }
    }
    // printf("\nDestination MAC: ");
    // // for (i = 0; i < 6; ++i) {
    //     printf("%02x", eth_header->ether_dhost[i]);
    //     if (i < 5) {
    //         printf(":");
    //     }
    // }
    // printf("\nType: %hu\n", eth_header->ether_type);
    // printf(" === PACKET DATA == \n");
    // Decode Packet Data (Skipping over the header)
    // int data_bytes = length - ETH_HLEN;
    // const unsigned char *payload = packet + ETH_HLEN;
    // const static int output_sz = 20; // Output this many bytes at a time
    // while (data_bytes > 0) {
    //     int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    //     // Print data in raw hexadecimal form
    //     for (i = 0; i < output_sz; ++i) {
    //         if (i < output_bytes) {
    //             printf("%02x ", payload[i]);
    //         } else {
    //             printf ("   "); // Maintain padding for partial lines
    //         }
    //     }
    //     printf ("| ");
    //     // Print data in ascii form
    //     for (i = 0; i < output_bytes; ++i) {
    //         char byte = payload[i];
    //         if (byte > 31 && byte < 127) {
    //         // Byte is in printable ascii range
    //             printf("%c", byte);
    //         } else {
    //             printf(".");
    //         }
    //     }
    //     printf("\n");
    //     payload += output_bytes;
    //     data_bytes -= output_bytes;
    // }
}

void packet_init(unsigned char * args, struct pcap_pkthdr *header, const unsigned char *packet) {
    struct pcap_pkthdr *pkt_header;
    const unsigned char *pkt_packet;

    // memcpy((void *) pkt_header, header, sizeof(struct pcap_pkthdr *));
    // memcpy((void *) pkt_packet, packet, sizeof(unsigned char *));

    packet_handler(header, packet);
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline("packet-storm.pcap", error_buffer);

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void*) &packet_handler, NULL);

    return 0;
}