#ifndef PACKET_STORM_GLOBALS_H
#define PACKET_STORM_GLOBALS_H

#include <pthread.h>
#include "types.h"

#define TCP 6
#define UDP 17
#define UDP_HEADER_LENGTH 8
#define MAX_THREADS 8

extern int thread_count;       // number of threads available
extern pthread_t threads[MAX_THREADS];       // threads
extern pthread_mutex_t threads_mutex;    // mutex lock for available_indices
extern pthread_cond_t no_threads_cond;    // signals a thread is available
extern pthread_mutex_t ip_list_mutex;
extern int available_indices[MAX_THREADS];
extern list_t *ips_head;
extern int unique_ips;
extern int tcp_count;
extern int udp_count;
extern int packets_count;
extern double average_size;
extern int total_payload;
extern int available_indices[MAX_THREADS];   // queue of threads not doing anything

#endif