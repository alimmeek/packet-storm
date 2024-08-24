#ifndef PACKET_STORM_GLOBALS_H
#define PACKET_STORM_GLOBALS_H

#include <pthread.h>
#include "types.h"

#define TCP 6
#define UDP 17
#define UDP_HEADER_LENGTH 8


// See packet_storm.c for explanations and initialisations

extern int thread_count;
extern pthread_t threads[MAX_THREADS];
extern pthread_mutex_t threads_mutex;
extern pthread_cond_t no_threads_cond;
extern pthread_mutex_t ip_list_mutex;
extern int available_indices[MAX_THREADS];
extern list_t *ips_head;
extern int unique_ips;
extern int tcp_count;
extern int udp_count;
extern int packets_count;
extern double average_size;
extern int total_payload;
extern int available_indices[MAX_THREADS];

#endif