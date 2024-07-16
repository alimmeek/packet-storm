#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <string.h>
#include <inttypes.h>

#define NUM_PACKETS 1000000

/*
TODO:
MUST
    - Average packet size
    - Total volume of data received during attack
        - Just the payloads?
    - No. packets sent with different transport layer protocols
SHOULD
    - Multithreading
    - Separate code out into different files/functions
        - packet_handler definitely needs de-monolithing
        - probably can make a util.c and main.c?
COULD
    - Text file option (will also print results to console)
        - -t to create a .txt file to make sharing results easier
    - some sort of CLI so they're not just waiting on my code running (e.g. progress bar)
*/

typedef struct node {
    char *addr;
    int count;
} node_t;

typedef struct list_node {
    struct list_node *next;
    node_t node;
} list_t;

typedef struct int_list_node {
    struct int_list_node *next;
    uint8_t protocol;
} int_list_t;

list_t *ips_head = NULL;
int_list_t *protocol_head = NULL;
int unique_ips = 0;
int unique_protcols = 0;
int packets_count = 0;

list_t *SortedMerge(list_t *a, list_t *b);

void FrontBackSplit(list_t *source, list_t **frontRef, list_t **backRef);

/* sorts the linked list by changing next pointers (not data) */
void MergeSort(list_t **head_pointer) {
    list_t *h = *head_pointer;
    list_t *a;
    list_t *b;

    /* Base case -- length 0 or 1 */
    if ((h == NULL) || (h->next == NULL)) {
        return;
    }

    /* Split head into 'a' and 'b' sublists */
    FrontBackSplit(h, &a, &b);

    /* Recursively sort the sublists */
    MergeSort(&a);
    MergeSort(&b);

    /* answer = merge the two sorted lists together */
    *head_pointer = SortedMerge(a, b);
}

/* See https://www.geeksforgeeks.org/merge-two-sorted-linked-lists/
for details of this function */
list_t *SortedMerge(list_t *a, list_t *b) {
    list_t *result = NULL;

    /* Base cases */
    if (a == NULL)
        return (b);
    else if (b == NULL)
        return (a);

    /* Pick either a or b, and recur */
    if (a->node.count >= b->node.count) {
        result = a;
        result->next = SortedMerge(a->next, b);
    }
    else {
        result = b;
        result->next = SortedMerge(a, b->next);
    }
    return result;
}

/* UTILITY FUNCTIONS */
/* Split the nodes of the given list into front and back halves,
    and return the two lists using the reference parameters.
    If the length is odd, the extra node should go in the front list.
    Uses the fast/slow pointer strategy. */
void FrontBackSplit(list_t *source, list_t **frontRef, list_t **backRef)
{
    list_t *fast;
    list_t *slow;
    slow = source;
    fast = source->next;

    /* Advance 'fast' two nodes, and advance 'slow' one node */
    while (fast != NULL) {
        fast = fast->next;
        if (fast != NULL) {
            slow = slow->next;
            fast = fast->next;
        }
    }

    /* 'slow' is before the midpoint in the list, so split it in two
    at that point. */
    *frontRef = source;
    *backRef = slow->next;
    slow->next = NULL;
}


void packet_handler(struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETH_P_IP) {
        struct ip *ip_hdr = (struct ip *) (packet + ETH_HLEN);

        list_t **head_pointer = &ips_head;

        if (unique_ips == 0) {            

            list_t *temp = (list_t *) malloc(sizeof(list_t));
            node_t temp_node;

            temp_node.addr = (char *) malloc(100 * sizeof(char));
            strcpy(temp_node.addr, inet_ntoa(ip_hdr->ip_dst));
            temp_node.count = 1;
            temp->next = NULL;
            temp->node = temp_node;

            *head_pointer = temp;

            unique_ips++;
        } else {
            list_t *prev = NULL;
            list_t *curr = *head_pointer;
            int found = 0;

            char addr[100];
            strcpy(addr, inet_ntoa(ip_hdr->ip_dst));

            while (curr != NULL) {
                prev = curr;
                if (strcmp(curr->node.addr, addr) == 0) {
                    curr->node.count++;
                    found = 1;
                    break;
                }
                curr = curr->next;
            }

            if (found == 0) {
                list_t *temp = (list_t *) malloc(sizeof(list_t));
                node_t temp_node;

                temp_node.addr = (char *) malloc(100 * sizeof(char));
                strcpy(temp_node.addr, inet_ntoa(ip_hdr->ip_dst));
                temp_node.count = 1;
                temp->next = *head_pointer;
                temp->node = temp_node;

                *head_pointer = temp;
                unique_ips++;
            }
        }

        int_list_t **protocol_head_ptr = &protocol_head;

        if (unique_protcols == 0) {
            int_list_t *temp = (int_list_t *) malloc(sizeof(int_list_t));

            temp->next = NULL;
            temp->protocol = ip_hdr->ip_p;

            *protocol_head_ptr = temp;

            unique_protcols++;
        } else {
            int_list_t *prev = NULL;
            int_list_t *curr = *protocol_head_ptr;
            int found = 0;

            while (curr != NULL) {
                prev = curr;
                if (curr->protocol == ip_hdr->ip_p) {
                    found = 1;
                    break;
                }
                curr = curr->next;
            }

            if (found == 0) {
                int_list_t *temp = (int_list_t *) malloc(sizeof(int_list_t));

                temp->next = *protocol_head_ptr;
                temp->protocol = ip_hdr->ip_p;

                *protocol_head_ptr = temp;

                unique_protcols++;
                // printf("New protocol encountered: %" PRIu8 "\n", ip->protocol);
            }
        }
    }
}

void packet_init(unsigned char * args, struct pcap_pkthdr *header, const unsigned char *packet) {
    struct pcap_pkthdr *pkt_header = (struct pcap_pkthdr *) malloc(sizeof(header));
    unsigned char *pkt_packet = (unsigned char *) malloc(sizeof(packet)); 

    memcpy((void *) &pkt_header, &header, sizeof(header));
    memcpy((void *) &pkt_packet, &packet, sizeof(packet));

    packet_handler(pkt_header, pkt_packet);

    packets_count++;
    if (packets_count % 100000 == 0) {
        printf("%d00000 packets analysed\n", packets_count / 100000);
    }
}

void print_ips() {
    list_t *prev = NULL;
    list_t *curr = ips_head;
    
    while (curr != NULL) {
        prev = curr;
        printf("IP address: %s \t Count: %d\n", curr->node.addr, curr->node.count);
        curr = curr->next;
    }
}

void print_protocols() {
    int_list_t *prev = NULL;
    int_list_t *curr = protocol_head;
    
    while (curr != NULL) {
        prev = curr;
        printf("%u\n", curr->protocol);
        curr = curr->next;
    }
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline("packet-storm.pcap", error_buffer);

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void *) &packet_init, NULL);

    MergeSort(&ips_head);
    printf("\n");

    printf("Number of unique IP addresses: %d\n", unique_ips);
    printf("Number of unique protocols: %d\n", unique_protcols);

    return 0;
}