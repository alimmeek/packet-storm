#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>
#include <pthread.h>
#include <inttypes.h>
#include <time.h>

#define TCP 6
#define UDP 17
#define UDP_HEADER_LENGTH 8
#define MAX_THREADS 8

/*
TODO:
MUST

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

typedef struct Param {
  struct pcap_pkthdr *header;
  const unsigned char *packet;
} Param;


list_t *ips_head = NULL;
int unique_ips = 0;
int tcp_count = 0;
int udp_count = 0;
int packets_count = 0;
int average_size = 0;
int total_payload = 0;

int available_indices[MAX_THREADS];   // queue of threads not doing anything
int thread_count = MAX_THREADS;       // number of threads available
pthread_t threads[MAX_THREADS];       // threads
pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;    // mutex lock for available_indices
pthread_cond_t no_threads_cond = PTHREAD_COND_INITIALIZER;    // signals a thread is available
pthread_mutex_t ip_list_mutex = PTHREAD_MUTEX_INITIALIZER;

void mthread_setup() {  // initialises available_indices to store its current index
  int i;
  for(i=0; i<MAX_THREADS; i++) {
    available_indices[i] = i;
  }
}

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


void *packet_handler(void *_i) {

    Param a = *((Param *) _i);

    struct pcap_pkthdr *header = a.header;
    const unsigned char *packet = a.packet;

    average_size += header->len;

    struct ether_header *eth_header = (struct ether_header *) packet;

    if (ntohs(eth_header->ether_type) == ETH_P_IP) {
        struct ip *ip_hdr = (struct ip *) (packet + ETH_HLEN);

        pthread_mutex_lock(&ip_list_mutex);
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
        pthread_mutex_unlock(&ip_list_mutex);

        unsigned int size_ip = ip_hdr->ip_hl;

        if (ip_hdr->ip_p == TCP) {
            struct tcphdr *tcp = (struct tcphdr*) (packet + ETH_HLEN + size_ip*4);
            tcp_count++;
            total_payload += (header->len) - (ETH_HLEN + size_ip*4 + (tcp->th_off)*4);
        } else if (ip_hdr->ip_p == UDP) {
            udp_count++;
            total_payload += (header->len) - (ETH_HLEN + size_ip*4 + UDP_HEADER_LENGTH);
        }
    }
}

void packet_init(unsigned char * args, struct pcap_pkthdr *header, const unsigned char *packet) {
    struct pcap_pkthdr *pkt_header = (struct pcap_pkthdr *) malloc(sizeof(header));
    unsigned char *pkt_packet = (unsigned char *) malloc(sizeof(packet)); 

    memcpy((void *) &pkt_header, &header, sizeof(header));
    memcpy((void *) &pkt_packet, &packet, sizeof(packet));

    Param a_p = {pkt_header, pkt_packet};

    // if threads are available, acquire mutex lock for available_threads, otherwise wait
    if (thread_count > 0) {
        pthread_mutex_lock(&threads_mutex);
    } else {
        while (thread_count == 0) {
        pthread_cond_wait(&no_threads_cond, &threads_mutex);
        }
    }

    // take the first available index, then shuffle the remaining indices forward one position
    // decrement the number of available threads and release the mutex lock
    int i;
    int t = available_indices[0];
    for (i=0; i < thread_count-1; i++) {
        available_indices[i] = available_indices[i+1];
    }
    thread_count--;
    pthread_mutex_unlock(&threads_mutex);

    // create the thread and join it back to the main program
    pthread_create(&threads[t], NULL, &packet_handler, &a_p);
    pthread_join(threads[t], NULL);

    // acquire mutex lock, and add the index to the back of the queue
    // incremenet the number of available threads and signal anything waiting for a thread
    pthread_mutex_lock(&threads_mutex);
    available_indices[thread_count-1] = t;
    thread_count++;
    pthread_cond_signal(&no_threads_cond);
    pthread_mutex_unlock(&threads_mutex);

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


int main() {

    clock_t start, stop;
    char error_buffer[PCAP_ERRBUF_SIZE];

    start = clock();

    mthread_setup();
    
    pcap_t *handle = pcap_open_offline("packet-storm.pcap", error_buffer);

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void *) &packet_init, NULL);

    MergeSort(&ips_head);
    average_size = average_size / packets_count;
    printf("\n");

    printf("Most frequent IP address: %s \t Count: %d\n", ips_head->node.addr, ips_head->node.count);
    printf("Number of packets sent with TCP: %d\n", tcp_count);
    printf("Number of packets sent with UDP: %d\n", udp_count);
    printf("Total payload: %d bytes\n", total_payload);
    printf("Average size of packets received: %d bytes\n", average_size);

    stop = clock();

    printf("Program run time: %f seconds \n", (double) (stop - start) / CLOCKS_PER_SEC);

    return 0;
}