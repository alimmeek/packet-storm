#ifndef PACKET_STORM_UTIL_H
#define PACKET_STORM_UTIL_H

#include <netinet/ip.h>

void mthread_setup();
void free_list();
void print_stats(FILE *f);
void write_to_file(char *filename);
void create_list_node(struct ip *ip_hdr, list_t **head_pointer);
list_t *sorted_merge(list_t *a, list_t *b);
void front_back_split(list_t *source, list_t **front_ref, list_t **back_ref);
void merge_sort(list_t **head_pointer);
list_t *sorted_merge(list_t *a, list_t *b);
void front_back_split(list_t *source, list_t **front_ref, list_t **back_ref);

#endif