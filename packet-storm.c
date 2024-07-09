#include <stdio.h>
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

struct ip_node {
    unsigned int addr;
    int count;
    struct ip_node *next;
};

struct ip_node *root = NULL;
int unique_ips = 0;

void merge(struct ip_node *arr, int low, int mid, int high)
{
    int i, j, k;
    int lower_size = mid - low + 1;
    int upper_size = high - mid;

    // Create temp arrays
    struct ip_node left_sub_array[lower_size], right_sub_array[upper_size];

    // Copy data to temp arrays L[] and R[]
    for (i = 0; i < lower_size; i++)
        left_sub_array[i] = arr[low + i];
    for (j = 0; j < upper_size; j++)
        right_sub_array[j] = arr[mid + 1 + j];

    // Merge the temp arrays back into arr[l..r
    i = 0;
    j = 0;
    k = low;
    while (i < lower_size && j < upper_size) {
        if (left_sub_array[i].count >= right_sub_array[j].count) {
            arr[k] = left_sub_array[i];
            i++;
        }
        else {
            arr[k] = right_sub_array[j];
            j++;
        }
        k++;
    }

    // Copy the remaining elements of L[],
    // if there are any
    while (i < lower_size) {
        arr[k] = left_sub_array[i];
        i++;
        k++;
    }

    // Copy the remaining elements of R[],
    // if there are any
    while (j < upper_size) {
        arr[k] = right_sub_array[j];
        j++;
        k++;
    }
}

// l is for left index and r is right index of the
// sub-array of arr to be sorted
void merge_sort(struct ip_node arr[], int low, int high) {
    if (low < high) {
        int mid = low + (high - low) / 2;

        // Sort first and second halves
        merge_sort(arr, low, mid);
        merge_sort(arr, mid + 1, high);

        merge(arr, low, mid, high);
    }
}

void packet_handler(struct pcap_pkthdr *header, const unsigned char *packet) {
    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETH_P_IP) {
        struct iphdr *ip = (struct iphdr *) (packet + header->len);

        unsigned int dest = ntohs(ip->daddr);
        
        struct ip_node temp = {dest, 1, NULL};

        if (root == NULL) {
            root = &temp;
            unique_ips++;
        } else {
            struct ip_node *prev = NULL;
            struct ip_node *curr = root;
            int found = 0;

            while (curr != NULL) {
                prev = curr;
                
                if (curr->addr == dest) {
                    curr->count++;
                    found = 1;
                    break;
                }
                curr = curr->next;
            }

            if (found == 0) {
                prev->next = &temp;
                unique_ips++;
            }
        }
        // printf("Source IP address: %d.%d.%d.%d\n", (source >> 24) & 0xFF, (source >> 16) & 0xFF, (source >> 8) & 0xFF, source & 0xFF);
    }
}

void packet_init(unsigned char * args, struct pcap_pkthdr *header, const unsigned char *packet) {
    struct pcap_pkthdr *pkt_header;
    const unsigned char *pkt_packet; 

    memcpy((void *) &pkt_header, header, sizeof(header));
    memcpy((void *) &pkt_packet, packet, sizeof(packet));

    packet_handler(header, packet);
}

int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];
    
    pcap_t *handle = pcap_open_offline("get250.pcap", error_buffer);

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void*) &packet_init, NULL);

    merge_sort(root, 0, unique_ips-1);

    return 0;
}