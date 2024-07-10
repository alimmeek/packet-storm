#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <string.h>

/*
TODO:
    - Average packet size
    - Total volume of data received during attack
        - Just the payloads?
    - Destination IPs ranked by frequency (most frequent first)
    - No. packets sent with different transport layer protocols
    - Verbose option (will also print results to console)
        - Default is just a .txt file to make sharing results easier
*/

typedef struct node {
    unsigned int addr;
    int count;
} node_t;

typedef struct list_node {
    struct list_node *next;
    node_t node;
} list_t;

list_t *head = NULL;
int unique_ips = 0;


void packet_handler(struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *) (packet + ETH_HLEN);

        unsigned int dest = ntohs(ip->daddr);
        list_t **head_pointer = &head;

        if (unique_ips == 0) {
            list_t *temp = (list_t *) malloc(sizeof(list_t));
            node_t temp_node;

            temp_node.addr = dest;
            temp_node.count = 1;
            temp->next = NULL;
            temp->node = temp_node;

            *head_pointer = temp;

            unique_ips++;
        } else {
            list_t *prev = NULL;
            list_t *curr = *head_pointer;
            int found = 0;

            while (curr != NULL) {
                prev = curr;
                if (curr->node.addr == dest) {
                    curr->node.count++;
                    found = 1;
                    break;
                }
                curr = curr->next;
            }

            if (found == 0) {
                list_t *temp = (list_t *) malloc(sizeof(list_t));
                node_t temp_node;

                temp_node.addr = dest;
                temp_node.count = 1;
                temp->next = *head_pointer;
                temp->node = temp_node;

                *head_pointer = temp;
                unique_ips++;
            }
        }
    }
}

void packet_init(unsigned char * args, struct pcap_pkthdr *header, const unsigned char *packet) {
    struct pcap_pkthdr *pkt_header;
    const unsigned char *pkt_packet; 

    memcpy((void *) &pkt_header, header, sizeof(header));
    memcpy((void *) &pkt_packet, packet, sizeof(packet));

    packet_handler(header, packet);
}

void print_list() {
    list_t *prev = NULL;
    list_t *curr = head;
    
    while (curr != NULL) {
        prev = curr;
        unsigned int ip = curr->node.addr;
        printf("IP address: %d.%d.%d.%d \t Count: %d\n", (ip >> 24) & 0xFF, (ip >> 16) & 0xFF, (ip >> 8) & 0xFF, ip & 0xFF, curr->node.count);
        curr = curr->next;
    }
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline("packet-storm.pcap", error_buffer);

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void*) &packet_init, NULL);

    print_list();

    //merge_sort(root, 0, unique_ips-1);

    // unsigned int root_ip = head->node.addr;

    // printf("Most frequent IP address: %d.%d.%d.%d\n", (root_ip >> 24) & 0xFF, (root_ip >> 16) & 0xFF, (root_ip >> 8) & 0xFF, root_ip & 0xFF);

    return 0;
}