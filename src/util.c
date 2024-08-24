#include <stdlib.h>
#include <netinet/ip.h>
#include <string.h>

#include "types.h"
#include "globals.h"


/*
 * This file contains various utility functions used during the program
*/


// initialises available_indices to store its current index
void mthread_setup() {
  for (int i = 0; i < MAX_THREADS; i++) {
    available_indices[i] = i;
  }
}


// deallocates all memory in the IP list
void free_list() {
  list_t *prev = NULL;
  list_t *curr = ips_head;
  
  // go through the list, update the pointers
  // have to free memory allocated to store the IP address and the node itself
  while (curr != NULL) {
      prev = curr;
      curr = curr->next;
      free(prev->node.addr);
      free(prev);
  }
}

// prints the results of analysis to a specified file
void print_stats(FILE *f) {
    fprintf(f, "Most frequent IP address: %s    Count: %d\n", ips_head->node.addr, ips_head->node.count);
    fprintf(f, "Number of packets sent with TCP: %d\n", tcp_count);
    fprintf(f, "Number of packets sent with UDP: %d\n", udp_count);
    fprintf(f, "Total payload: %d bytes\n", total_payload);
    fprintf(f, "Average size of packets received: %f bytes\n", average_size);
}


// if required, writes the entire analysis to a file
void write_to_file(char *filename) {
    FILE *f;

    // check whether this filename doesn't already exist
    // If it does, warn the user that this will be overwritten
    if ((f = fopen(filename, "r")) != NULL) {
        fclose(f);

        char choice_buff[100];
        char choice;
        do {
            printf("WARNING: %s already exists. Overwrite? [y/n] ", filename);
            fgets(choice_buff, 100, stdin);
            choice = choice_buff[0];
        } while ((choice != 'y') && (choice != 'n'));

        if (choice == 'n') {
            return;
        }
    }

    // reopen file to write results
    if ((f = fopen(filename, "w")) != NULL) {
        list_t *curr = ips_head;

        print_stats(f);
        fprintf(f, "\n\n");
        
        // print the list in descending order
        fprintf(f, "All IPs encountered:\n");
        
        while (curr != NULL) {
            fprintf(f, "IP address: %s \t Count: %d\n", curr->node.addr, curr->node.count);
            curr = curr->next;
        }

        fclose(f);
    }
}

// creates a node for the IP list and adds it to the head of the list
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

// merge sort code adapted from https://www.geeksforgeeks.org/merge-sort-for-linked-list/

list_t *sorted_merge(list_t *a, list_t *b);

void front_back_split(list_t *source, list_t **front_ref, list_t **back_ref);

// sorts the linked list by changing next pointers (not data)
void merge_sort(list_t **head_pointer) {
    list_t *h = *head_pointer;
    list_t *a;
    list_t *b;

    // base case - length 0 or 1
    if ((h == NULL) || (h->next == NULL)) {
        return;
    }

    // split head into 'a' and 'b' sublists
    front_back_split(h, &a, &b);

    // recursively sort the sublists
    merge_sort(&a);
    merge_sort(&b);

    // answer = merge the two sorted lists together
    *head_pointer = sorted_merge(a, b);
}

list_t *sorted_merge(list_t *a, list_t *b) {
    list_t *result = NULL;

    // base cases
    if (a == NULL)
        return (b);
    else if (b == NULL)
        return (a);

    // pick either a or b, and recur
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


// split the nodes of the given list into front and back halves, and return the two lists using the reference parameters
// if the length is odd, the extra node should go in the front list
// uses the fast/slow pointer strategy
void front_back_split(list_t *source, list_t **front_ref, list_t **back_ref) {
    list_t *fast;
    list_t *slow;
    slow = source;
    fast = source->next;

    // advance 'fast' two nodes, and advance 'slow' one node
    while (fast != NULL) {
        fast = fast->next;
        if (fast != NULL) {
            slow = slow->next;
            fast = fast->next;
        }
    }

    // 'slow' is before the midpoint in the list, so split it in two at that point
    *front_ref = source;
    *back_ref = slow->next;
    slow->next = NULL;
}