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


/*
 * This file initialises all global variables and controls program execution
*/


int thread_count = MAX_THREADS;                            // number of threads available
pthread_t threads[MAX_THREADS];                            // threads
pthread_mutex_t threads_mutex = PTHREAD_MUTEX_INITIALIZER; // mutex lock for available_indices
pthread_cond_t no_threads_cond = PTHREAD_COND_INITIALIZER; // signals a thread is available
pthread_mutex_t ip_list_mutex = PTHREAD_MUTEX_INITIALIZER; // mutex lock for the list of encountered IP addresses
int available_indices[MAX_THREADS];                        // queue of available threads
list_t *ips_head = NULL;                                   // pointer to the head of a linked list of all previously seen IP addresses
int unique_ips = 0;                                        // length of the IP list
int tcp_count = 0;                                         // number of packets with the TCP protocol
int udp_count = 0;                                         // number of packets with the UDP protocol
int packets_count = 0;                                     // number of packets analysed
double average_size = 0;                                   // stores the total length (including headers) of all packets received, then the average across these packets
int total_payload = 0;                                     // stores the total length of the payloads (so no headers)


int main() {

    printf("MAX_THREADS has been set to %d\n", MAX_THREADS);
    char error_buffer[PCAP_ERRBUF_SIZE];

    mthread_setup();

    // open the pcap file for analysis, if error report and exit
    
    pcap_t *handle;

    if ((handle = pcap_open_offline("packet-storm.pcap", error_buffer)) == NULL) {
      printf("Error: unable to open .pcap file");
      exit(1);
    }

    // "A value of -1 or 0 for cnt causes all the packets received in one buffer to be processed when reading a live capture and causes all the packets in a file to be processed when reading a savefile"
    pcap_loop(handle, -1, (void *) &packet_init, NULL);

    // once all packets have been analysed:
    //  - sort the ip list in descending order of the number of times they were encountered
    //  - calculate the metrics
    //  - print them to the command line

    merge_sort(&ips_head);
    average_size = average_size / packets_count;
    printf("\n");

    print_stats(stdout);

    // extra bit: analysis like this probably needs to be shared between people
    // this stores the results in a text file for easy sharing
    // this also stores *every* entry in the ip list so it's a fairly long file (approx 5Mb)

    char choice_buff[100];
    char choice;

    do {
      printf("\nWrite results to file? [y/n] ");
      fgets(choice_buff, 100, stdin);
      choice = choice_buff[0];
    } while ((choice != 'y') && (choice != 'n'));

    if (choice == 'y') {
      write_to_file("results.txt");
    }

    // memory management

    pcap_close(handle);
    free_list();

    return 0;
}