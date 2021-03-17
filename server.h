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

// Structure to hold information which gets passed into the worker function
// for worker threads.
struct worker_data {
    struct server *svr;
    int worker_index;
};

// An entry object for the compression dictionary. The compression dictionary
// is a look-up table which holds a list of c_dict_entry objects each
// corresponding to a bit encoding of a specific byte value.
struct c_dict_entry {
    uint8_t n_bits;
    uint8_t encoding[32];
};

// A node object for the decoding tree. The decoding tree is a binary tree
// which is traversed depending on a sequence of bits. Each leaf node of the
// decoding tree contains the decoded byte value of the bit sequence
// corresponding to the path taken in the binary tree.
struct decode_node {
    struct decode_node *children[2];
    uint8_t byte;
};

// Server object to hold all memory and data relevant to the server operation.
struct server {
    uint32_t ipv4_addr;
    uint16_t tcp_port;
    char *directory;

    int listener; // Listener socket

    int enqueue_fd;
    int dequeue_fd;

    pthread_t *thread_pool;

    struct c_dict_entry c_dict[256]; // Compression dictionary
    struct decode_node *decode_head; // Decoding tree

    struct session_table *st;
};


int get_file_size(uint64_t *file_len, char *file_path);

unsigned char *read_file(uint64_t *file_len, char *file_path);

void send_message(struct server *svr, int socket_fd, uint8_t msg_header,
                  uint64_t payload_len, unsigned char *payload);

void work(struct server *svr, int socket_fd, int worker_index);

void *worker(void *arg);

void move_bits(unsigned char *dest, int *dest_byte_offset, uint8_t *dest_bit_offset,
                unsigned char *src, int *src_byte_offset, uint8_t *src_bit_offset,
                uint8_t n_bits);

unsigned char *compress(struct server *svr, uint64_t *compressed_len,
                        unsigned char *data, uint64_t data_len);

unsigned char *decompress(struct server *svr, uint64_t *decompressed_len,
                          unsigned char *compressed_data, uint64_t data_len);

void compression_init(struct server *svr);

struct server *server_init(char *config_filepath);

void server_destroy(struct server *svr);
