#include <stdlib.h>
#include <netinet/ip.h>

#include "types.h"

extern int tcp_count;
extern int udp_count;
extern int total_payload;
extern double average_size;

void print_stats(FILE *f) {
    fprintf(f, "Most frequent IP address: %s \t Count: %d\n", ips_head->node.addr, ips_head->node.count);
    fprintf(f, "Number of packets sent with TCP: %d\n", tcp_count);
    fprintf(f, "Number of packets sent with UDP: %d\n", udp_count);
    fprintf(f, "Total payload: %d bytes\n", total_payload);
    fprintf(f, "Average size of packets received: %d bytes\n", average_size);
}

void write_to_file(char *filename) {
    FILE *f;

    if ((f = fopen(filename, "w")) != NULL) {
        list_t *curr = ips_head;
        
        while (curr != NULL) {
            fprintf(f, "IP address: %s \t Count: %d\n", curr->node.addr, curr->node.count);
            curr = curr->next;
        }
        printf("\n");

        print_stats(f);
    }
}

void create_list_node(struct ip *ip_hdr, list_t **head_pointer) {
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

list_t *sorted_merge(list_t *a, list_t *b);

void front_back_split(list_t *source, list_t **front_ref, list_t **back_ref);

/* sorts the linked list by changing next pointers (not data) */
void merge_sort(list_t **head_pointer) {
    list_t *h = *head_pointer;
    list_t *a;
    list_t *b;

    /* Base case -- length 0 or 1 */
    if ((h == NULL) || (h->next == NULL)) {
        return;
    }

    /* Split head into 'a' and 'b' sublists */
    front_back_split(h, &a, &b);

    /* Recursively sort the sublists */
    merge_sort(&a);
    merge_sort(&b);

    /* answer = merge the two sorted lists together */
    *head_pointer = sorted_merge(a, b);
}

/* See https://www.geeksforgeeks.org/merge-two-sorted-linked-lists/
for details of this function */
list_t *sorted_merge(list_t *a, list_t *b) {
    list_t *result = NULL;

    /* Base cases */
    if (a == NULL)
        return (b);
    else if (b == NULL)
        return (a);

    /* Pick either a or b, and recur */
    if (a->node.count >= b->node.count) {
        result = a;
        result->next = sorted_merge(a->next, b);
    }
    else {
        result = b;
        result->next = sorted_merge(a, b->next);
    }
    return result;
}

/* UTILITY FUNCTIONS */
/* Split the nodes of the given list into front and back halves,
    and return the two lists using the reference parameters.
    If the length is odd, the extra node should go in the front list.
    Uses the fast/slow pointer strategy. */
void front_back_split(list_t *source, list_t **front_ref, list_t **back_ref) {
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
    *front_ref = source;
    *back_ref = slow->next;
    slow->next = NULL;
}