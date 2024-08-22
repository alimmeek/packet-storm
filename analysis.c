#include <pcap.h>
#include <stdlib.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include "types.h"
#include "util.h"

int thread_count = MAX_THREADS;       // number of threads available
pthread_t threads[MAX_THREADS];       // threads
pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;    // mutex lock for available_indices
pthread_cond_t no_threads_cond = PTHREAD_COND_INITIALIZER;    // signals a thread is available
pthread_mutex_t ip_list_mutex = PTHREAD_MUTEX_INITIALIZER;
extern int available_indices[MAX_THREADS];


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
            create_list_node(ip_hdr, head_pointer);
        } else {
            list_t *curr = *head_pointer;
            int found = 0;

            char addr[100];
            strcpy(addr, inet_ntoa(ip_hdr->ip_dst));

            while (curr != NULL) {
                if (strcmp(curr->node.addr, addr) == 0) {
                    curr->node.count++;
                    found = 1;
                    break;
                }
                curr = curr->next;
            }

            if (found == 0) {
                create_list_node(ip_hdr, head_pointer);
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