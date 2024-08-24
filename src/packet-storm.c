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

#include "types.h"
#include "analysis.h"
#include "util.h"
#include "globals.h"


int thread_count = MAX_THREADS;       // number of threads available
pthread_t threads[MAX_THREADS];       // threads
pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER;    // mutex lock for available_indices
pthread_cond_t no_threads_cond = PTHREAD_COND_INITIALIZER;    // signals a thread is available
pthread_mutex_t ip_list_mutex = PTHREAD_MUTEX_INITIALIZER;
int available_indices[MAX_THREADS];    // queue of available threads
list_t *ips_head = NULL;    // pointer to the head of a linked list of all previously seen IP addresses
int unique_ips = 0;    // length of the ip list
int tcp_count = 0;    // number of packets with the TCP protocol
int udp_count = 0;    // number of packets with the UDP protocol
int packets_count = 0;    // number of packets analysed
double average_size = 0;  // stores the total length (i.e., including headers) of all packets received, then the average across these packets
int total_payload = 0;    // stores the total length of the payloads (so no headers)

/*
TODO:
MUST

SHOULD

COULD
    - some sort of CLI so they're not just waiting on my code running (e.g. progress bar)
*/

void mthread_setup() {  // initialises available_indices to store its current index
  for (int i = 0; i < MAX_THREADS; i++) {
    available_indices[i] = i;
  }
}


void free_list() {
  list_t *prev = NULL;
  list_t *curr = ips_head;
        
  while (curr != NULL) {
      prev = curr;
      curr = curr->next;
      free(prev->node.addr);
      free(prev);
  }
}


int main() {
    char error_buffer[PCAP_ERRBUF_SIZE];

    mthread_setup();
    
    pcap_t *handle;

    if ((handle = pcap_open_offline("packet-storm.pcap", error_buffer)) == NULL) {
      printf("Error: unable to open .pcap file");
      exit(1);
    }

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void *) &packet_init, NULL);

    merge_sort(&ips_head);
    average_size = average_size / packets_count;
    printf("\n");

    print_stats(stdout);

    char choice_buff[100];
    char choice;

    do {
      printf("Write results to file? [y/n] ");
      fgets(choice_buff, 100, stdin);
      choice = choice_buff[0];
    } while ((choice != 'y') && (choice != 'n'));

    if (choice == 'y') {
      write_to_file("results.txt");
    }

    pcap_close(handle);
    free_list();

    return 0;
}