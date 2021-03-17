#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <stdint.h>
#include <endian.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <dirent.h>

#include "session_table.h"

#define INIT_BUCKETS 10000

/**
* Initialises the session table. The session table is a hash map implemented
* using separate chaining, where each entry corresponds to a file transfer
* session. The key of an entry is the session ID of the file transfer, and the
* value stored holds information about which sections of the file still need
* to be transferred. The data structure is protected by a single mutex to
* ensure thread-safe access.
*
* @return The session_table object.
*/
struct session_table *session_table_init() {
    struct session_table *st = malloc(sizeof(struct session_table));
    st->buckets = calloc(INIT_BUCKETS, sizeof(struct st_node *));
    st->n_buckets = INIT_BUCKETS;
    pthread_mutex_init(&st->global_lock, NULL);

    return st;
}

/**
* Gets an entry from the session table corresponding to a given session ID.
* If the entry does not exist, it is created and returned.
*
* @param st The session table object.
* @param session_id The session ID of the entry to get from the session table.
* @return The st_node object for the session.
*/
struct st_node *session_table_get(struct session_table *st, uint32_t session_id) {
    pthread_mutex_lock(&st->global_lock);
    int index = (int)(session_id % st->n_buckets);
    struct st_node *ptr = st->buckets[index];
    struct st_node *prev_ptr = NULL;

    // Iterate through the bucket to find the session
    while (ptr != NULL) {
        if (ptr->session_id == session_id) {
            pthread_mutex_unlock(&st->global_lock);
            return ptr;
        }
        prev_ptr = ptr;
        ptr = ptr->next;
    }

    // If session isn't in the table, create a new session
    struct st_node *new_node = calloc(1, sizeof(struct st_node));
    new_node->session_id = session_id;
    new_node->src_fd = -1;
    new_node->curr_offset = 0;
    new_node->target_offset = 0;
    pthread_mutex_init(&new_node->lock, NULL);
    new_node->next = NULL;
    int fd[2];
    pipe(fd);
    new_node->dequeue_new_fd = fd[0];
    new_node->enqueue_new_fd = fd[1];
    fcntl(fd[0], F_SETFL, O_NONBLOCK); // Set pipe reads to non-blocking

    // Add the new node to the session table
    if (prev_ptr != NULL) {
        prev_ptr->next = new_node;
    } else {
        st->buckets[index] = new_node;
    }
    pthread_mutex_unlock(&st->global_lock);
    return new_node;
}

/**
* Removes an entry from the session table corresponding to a given session ID.
* Does nothing if the entry does not exist.
*
* @param st The session table object.
* @param session_id The session ID of the entry to remove from the session table.
*/
void session_table_remove(struct session_table *st, uint32_t session_id) {

    pthread_mutex_lock(&st->global_lock);
    int index = (int)(session_id % st->n_buckets);
    struct st_node *ptr = st->buckets[index];
    struct st_node *prev_ptr = NULL;

    // Iterate through the bucket to find a matching session ID
    while (ptr != NULL) {
        // Delete
        if (ptr->session_id == session_id) {
            if (prev_ptr == NULL) {
                st->buckets[index] = ptr->next;
            } else {
                prev_ptr->next = ptr->next;
            }
            pthread_mutex_destroy(&ptr->lock);
            free(ptr->dest_fds);
            free(ptr);
            pthread_mutex_unlock(&st->global_lock);
            return;
        }
        prev_ptr = ptr;
        ptr = ptr->next;
    }
    pthread_mutex_unlock(&st->global_lock);
}

/**
* Frees all memory associated with a session table object.
*
* @param st The session table object.
*/
void session_table_destroy(struct session_table *st) {
    for (size_t i=0; i<st->n_buckets; i++) {
        struct st_node *ptr = st->buckets[i];
        struct st_node *next;
        while (ptr != NULL) {
            pthread_mutex_destroy(&ptr->lock);
            next = ptr->next;
            free(ptr);
            ptr = next;
        }
    }
    pthread_mutex_destroy(&st->global_lock);
    free(st->buckets);
    free(st);
}
