#include "server.h"
#include "session_table.h"

#define MAX_PENDING_CONNECTIONS SOMAXCONN

#define TYPE_DIGIT 0b11110000
#define COMPRESS_BIT 0b00001000

#define REQ_ECHO 0x00
#define RET_ECHO 0x10
#define REQ_DIR_LIST 0x20
#define RET_DIR_LIST 0x30
#define REQ_FILE_SIZE 0x40
#define RET_FILE_SIZE 0x50
#define REQ_RETRIEVE_FILE 0x60
#define RET_RETRIEVE_FILE 0x70
#define REQ_SHUTDOWN 0x80
#define INVALID_RESPONSE 0xF0

#define THREAD_POOL_SIZE 150

#define PACKET_SIZE 1000

/**
* Finds the size of a file.
*
* @param file_len Pointer to the memory where the file size result will be stored.
* @param file_path The file path of the file.
* @return 1 if successful, 0 otherwise.
*/
int get_file_size(uint64_t *file_len, char *file_path) {
    FILE *f = fopen(file_path, "r");
    if (f == NULL) {
        return 0;
    }
    fseek(f, 0L, SEEK_END);
    *file_len = ftell(f);
    fclose(f);
    return 1;
}

/**
* Reads a file using a memory mapping.
*
* @param file_len Pointer to the memory where the file size result will be stored.
* @param file_path The file path of the file.
* @return A pointer to the bytes that were read.
*/
unsigned char *read_file(uint64_t *file_len, char *file_path) {
    // Open the source file and get the file length
    int src_fd = open(file_path, O_RDONLY);
    if (src_fd < 0) {
        return NULL;
    }
    uint64_t file_size = lseek(src_fd, 0, SEEK_END);

    // Map file to the virtual address space
    unsigned char *src = mmap(NULL, file_size, PROT_READ, MAP_PRIVATE, src_fd, 0);

    *file_len = file_size;
    return src;
}

/**
* Writes a message to the specified file descriptor using the message header,
* payload length, payload format.
*
* @param svr The server object.
* @param socket_fd The file descriptor to write to.
* @param msg_header The one byte message header for the message.
* @param payload_len The length of the payload in host order.
* @param payload The payload as an array of bytes.
*/
void send_message(struct server *svr, int socket_fd, uint8_t msg_header,
                  uint64_t payload_len, unsigned char *payload) {

    uint64_t payload_len_network = htobe64(payload_len);
    send(socket_fd, &msg_header, 1, 0);
    send(socket_fd, &payload_len_network, 8, 0);
    if (payload_len_network != 0) {
        send(socket_fd, payload, payload_len, 0);
    }
}

/**
* The work function which all worker threads are running. This function monitors
* a client socket file descriptor for incoming messages. Upon receiving a
* message, the appropriate action is performed. This loops infinitely until the
* client shuts down the connection.
*
* @param svr The server object.
* @param socket_fd The file descriptor of the client to write to.
*/
void work(struct server *svr, int socket_fd, int worker_index) {
    while (1) {
        // Read the message header
        uint8_t msg_header;
        if (recv(socket_fd, &msg_header, 1, 0) == 0) {
            return;
        };
        uint8_t type = msg_header & 0b11110000;
        uint8_t compressed = msg_header & 0b00001000;
        uint8_t req_compress = msg_header & 0b00000100;

        // Read the payload length
        uint64_t payload_len_network;
        if (recv(socket_fd, &payload_len_network, 8, 0) == 0) {
            return;
        }
        uint64_t payload_len = be64toh(payload_len_network);

        // Read the payload
        unsigned char *payload = NULL;
        if (payload_len != 0) {
            payload = malloc(payload_len);
            if (recv(socket_fd, payload, payload_len, 0) == 0) {
                return;
            };
        }

        // Decompress the incoming payload if it is compressed
        if (compressed != 0) {
            unsigned char *compressed_payload = decompress(svr, &payload_len,
                                                        payload, payload_len);
            free(payload);
            payload = compressed_payload;
        }

        // If the request is for an echo, send the same payload back to
        // the client.
        if (type == REQ_ECHO) {
            if (req_compress == 0) {
                send_message(svr, socket_fd, RET_ECHO, payload_len, payload);
            } else {
                uint64_t compressed_len;
                unsigned char *compressed_payload = compress(svr, &compressed_len,
                                                            payload, payload_len);
                send_message(svr, socket_fd, RET_ECHO | COMPRESS_BIT, compressed_len,
                                                            compressed_payload);
                free(compressed_payload);
            }
        }

        // If the request is for the directory list, send a list of all
        // file names in the target directory.
        else if (type == REQ_DIR_LIST) {
            // Allocate memory to store the list of file names
            unsigned char *dir_payload = malloc(100);
            int dir_cap = 1;
            int dir_len = 0;

            // Open the target directory
            DIR *d;
            struct dirent *dir;
            d = opendir(svr->directory);
            if (d) {
                // Iterate through all the file names and append them
                // to the payload
                while ((dir = readdir(d)) != NULL) {
                    if (dir->d_type == DT_REG) {
                        int len = strlen(dir->d_name)+1;
                        while (dir_len + len > dir_cap) {
                            dir_cap *= 2;
                            dir_payload = realloc(dir_payload, dir_cap);
                        }
                        memcpy(dir_payload + dir_len, dir->d_name, len);
                        dir_len += len;
                    }
                }
                closedir(d);
                dir_payload = realloc(dir_payload, dir_len);

                // Send the payload to the client
                if (req_compress == 0) {
                    send_message(svr, socket_fd, RET_DIR_LIST, dir_len, dir_payload);
                } else {
                    uint64_t compressed_len;
                    unsigned char *compressed_dir_payload = compress(svr,
                                            &compressed_len, dir_payload, dir_len);
                    send_message(svr, socket_fd, RET_DIR_LIST | COMPRESS_BIT,
                                            compressed_len, compressed_dir_payload);
                    free(compressed_dir_payload);
                }
                free(dir_payload);
            }
        }

        // If the request corresponds to a file size request, the size
        // of the specified file is sent to the client.
        else if (type == REQ_FILE_SIZE) {
            // Construct the full path name
            int dir_name_len = strlen(svr->directory)+1;
            char *full_path = calloc(1, dir_name_len + payload_len + 1);
            sprintf(full_path, "%s/%s", svr->directory, (char *)payload);

            // Read the file size and send it to the client
            uint64_t file_size;
            if (get_file_size(&file_size, (char *)full_path) == 0) {
                // Send an invalid response if the file does not exist
                send_message(svr, socket_fd, INVALID_RESPONSE, 0, NULL);
            } else {
                if (req_compress == 0) {
                    uint64_t file_size_network = htobe64(file_size);
                    send_message(svr, socket_fd, RET_FILE_SIZE, sizeof(uint64_t),
                                 (unsigned char *)&file_size_network);
                } else {
                    uint64_t file_size_network = htobe64(file_size);
                    uint64_t compressed_len;
                    unsigned char *compressed_payload = compress(svr, &compressed_len,
                                            (unsigned char *)&file_size_network, 8);
                    send_message(svr, socket_fd, RET_FILE_SIZE | COMPRESS_BIT,
                                compressed_len, (unsigned char *)compressed_payload);
                    free(compressed_payload);
                }
            }
            free(full_path);

        }

        // If the request corresponds to a file retrieval, file data is
        // sent back across the connection in packets.
        else if (type == REQ_RETRIEVE_FILE) {

            // Read the header data at the beginning of the payload
            uint32_t session_id = be32toh(*((uint32_t*)payload));
            uint64_t offset = be64toh(*((uint64_t*)(payload+4)));
            uint64_t length = be64toh(*((uint64_t*)(payload+12)));
            int dir_name_len = strlen(svr->directory)+1;
            char *file_name = malloc(payload_len-20);
            memcpy(file_name, payload+20, payload_len-20);
            char *full_path = calloc(1, dir_name_len + (payload_len-20) + 1);
            sprintf(full_path, "%s/%s", svr->directory, (char *)payload+20);
            uint64_t file_size = 0;

            // Get the session st_node object from the session table
            int session_exists = 0;
            struct st_node *node = session_table_get(svr->st, session_id);

            // If the session was new, create a new session
            int file_fd;
            pthread_mutex_lock(&node->lock);
            if (node->src_fd == -1) {
                file_fd = open(full_path, O_RDONLY);
                node->src_fd = file_fd;
                if (file_fd >= 0) {
                    file_size = lseek(file_fd, 0L, SEEK_END);
                    lseek(file_fd, 0L, SEEK_SET);
                    node->file_name = file_name;
                    node->start_offset = offset;
                    node->curr_offset = offset;
                    node->target_offset = offset+length;

                    // Add the current client to the destination socket list
                    node->dest_fds = malloc(sizeof(int));
                    node->n_dest_fds = 1;
                    node->dest_fds[0] = socket_fd;
                }
                pthread_mutex_unlock(&node->lock);
            }

            // If the session already existed, add the destination file
            // descriptor to the session
            else {
                session_exists = 1;
                if (strcmp(node->file_name, file_name) != 0 ||
                    node->start_offset != offset ||
                    node->target_offset != offset+length) {
                    send_message(svr, socket_fd, INVALID_RESPONSE, 0, NULL);
                } else {
                    // Add the current client to the destination socket list
                    // and move on to another client.
                    // The client which handled the session at initialisation
                    // will handle multiplexing to all destination sockets.
                    write(node->enqueue_new_fd, &socket_fd, sizeof(int));
                }
                pthread_mutex_unlock(&node->lock);
                free(file_name);
                free(full_path);
                free(payload);
                continue;
            }

            // Only check for invalid offset, length or file descriptor when a
            // new session is created
            if (session_exists == 0 &&
                (file_fd < 0 || offset+length > file_size ||
                    offset > file_size || length > file_size)) {
                send_message(svr, socket_fd, INVALID_RESPONSE, 0, NULL);
                free(node->dest_fds);
                node->src_fd = -1;
            } else {
                uint32_t session_id_network = htobe32(session_id);
                lseek(file_fd, offset, SEEK_SET);

                // Buffer for uncompressed packet data
                unsigned char buffer[PACKET_SIZE];
                uint64_t bytes_sent = 0;
                uint64_t bytes_sent_network;
                uint64_t n_bytes;
                uint64_t n_bytes_network;

                // Buffer for compressed packet data
                unsigned char packet_payload[4*PACKET_SIZE + 80];

                int fd_index = 0;
                int dest_fd;

                while (1) {
                    // Get new file descriptors for multiplexing and add
                    // them to the array of destination sockets
                    int new_fd;
                    while (read(node->dequeue_new_fd, &new_fd,
                                            sizeof(int)) > 0) {
                        node->n_dest_fds += 1;
                        node->dest_fds = realloc(node->dest_fds,
                                        node->n_dest_fds * sizeof(int));
                        node->dest_fds[node->n_dest_fds - 1] = new_fd;
                    }

                    // Break out of the while loop if all data is sent
                    if (node->curr_offset >= node->target_offset) {
                        free(node->dest_fds);
                        node->src_fd = -1;
                        break;
                    }

                    // Get the next file descriptor to write to
                    fd_index = fd_index % node->n_dest_fds;
                    dest_fd = node->dest_fds[fd_index];

                    // Read a packet of data from the source file and adjust the
                    // offset variable
                    n_bytes = read(file_fd, buffer, PACKET_SIZE);
                    if (node->curr_offset + n_bytes > node->target_offset) {
                        n_bytes = node->target_offset - node->curr_offset;
                    }
                    bytes_sent = node->curr_offset;
                    node->curr_offset += n_bytes;

                    if (req_compress == 0) {
                        // Send the packet of data to the destination socket
                        uint8_t response_header = RET_RETRIEVE_FILE;
                        send(dest_fd, &response_header, 1, 0);
                        uint64_t response_len_network = htobe64(n_bytes+20);
                        send(dest_fd, &response_len_network, 8, 0);
                        send(dest_fd, &session_id_network, 4, 0);
                        bytes_sent_network = htobe64(bytes_sent);
                        send(dest_fd, &bytes_sent_network, 8, 0);
                        n_bytes_network = htobe64(n_bytes);
                        send(dest_fd, &n_bytes_network, 8, 0);
                        send(dest_fd, buffer, n_bytes, 0);

                    } else {
                        // Construct the payload of the data packet
                        memcpy(packet_payload, &session_id_network, 4);
                        bytes_sent_network = htobe64(bytes_sent);
                        memcpy(packet_payload+4, &bytes_sent_network, 8);
                        n_bytes_network = htobe64(n_bytes);
                        memcpy(packet_payload+12, &n_bytes_network, 8);
                        memcpy(packet_payload+20, buffer, n_bytes);

                        // Compress the payload
                        uint64_t packet_len;
                        unsigned char *compressed_packet = compress(svr,
                                &packet_len, packet_payload, n_bytes+20);

                        // Send the data packet with the compressed payload
                        uint8_t response_header = RET_RETRIEVE_FILE
                                                        | COMPRESS_BIT;
                        send(socket_fd, &response_header, 1, 0);
                        uint64_t packet_len_network = htobe64(packet_len);
                        send(socket_fd, &packet_len_network, 8, 0);
                        send(socket_fd, compressed_packet, packet_len, 0);
                        free(compressed_packet);
                    }
                    fd_index++; // Increment to the next file descriptor
                }
                close(file_fd);
            }
            free(file_name);
            free(full_path);
        }

        // If the request is a shutdown, terminate the server
        else if (type == REQ_SHUTDOWN) {
            free(payload);
            session_table_destroy(svr->st);
            // server_destroy(svr);
            exit(0);
        }

        // Send an invalid response message if the type digit is invalid
        else {
            send_message(svr, socket_fd, INVALID_RESPONSE, 0, NULL);
        }
        free(payload);
    }
}

/**
* Continuously monitors the client queue for new incoming connections, and
* connects to available clients and performs the specified requests.
* All the worker threads of the server run this function.
*
* @param arg The worker_data object which contains the server data.
* @return NULL
*/
void *worker(void *arg) {
    // Cast the data from the argument
    struct worker_data *wd = (struct worker_data *)arg;
    struct server *svr = wd->svr;
    int worker_index = wd->worker_index;
    free(wd);

    // Continuously get and deal with new clients
    while (1) {
        // Get a new client from the client queue
        int socket_fd;
        read(svr->dequeue_fd, &socket_fd, sizeof(int));

        // Run the work() function on the client socket
        if (socket_fd != -1) {
            work(svr, socket_fd, worker_index);
            close(socket_fd);
        }
    }
    return NULL;
}

/**
* Copies a number of bits from one memory location to another.
*
* @param dest Destination address.
* @param dest_byte_offset Number of bytes offset from dest to write to.
* @param dest_bit_offset Number of bits offset from dest_byte_offset to write to.
* @param src Source address.
* @param src_byte_offset Number of bytes offset from src to read from.
* @param src_bit_offset Number of bits offset from src_byte_offset to read from.
* @param n_bits Number of bits to copy over.
*/
void move_bits(unsigned char *dest, int *dest_byte_offset, uint8_t *dest_bit_offset,
                unsigned char *src, int *src_byte_offset, uint8_t *src_bit_offset,
                uint8_t n_bits) {

    int n_bits_remaining = (int)n_bits;

    while (n_bits_remaining > 0) {

        // Align the bytes and copy bits up to the next byte boundary
        uint8_t src_byte  = (uint8_t)src[*src_byte_offset];
        uint8_t shifted = src_byte << *src_bit_offset >> *dest_bit_offset;
        dest[*dest_byte_offset] |= shifted;

        // Calculate the number of bits that were moved
        uint8_t bits_moved;
        if (*src_bit_offset > *dest_bit_offset) {
            bits_moved = (8 - (*src_bit_offset));
        } else {
            bits_moved = (8 - (*dest_bit_offset));
        }

        // Update the number of bits remaining to move
        n_bits_remaining -= (int)bits_moved;

        // If too many bits have been written, clear the extra bits
        if (n_bits_remaining < 0) {
            int shift = 8 - (*dest_bit_offset) - (n_bits_remaining + bits_moved);
            dest[*dest_byte_offset] = dest[*dest_byte_offset] >> shift << shift;
            bits_moved += n_bits_remaining;
        }

        // Update the bit and byte offsets based on the number of moved bits
        (*dest_bit_offset) += bits_moved;
        if (*dest_bit_offset >= 8) {
            (*dest_bit_offset) -= 8;
            (*dest_byte_offset)++;
        }
        (*src_bit_offset) += bits_moved;
        if (*src_bit_offset >= 8) {
            (*src_bit_offset) -= 8;
            (*src_byte_offset)++;
        }
    }
}

/**
* Compresses byte data by replacing bytes with bit sequences determined
* by the compression dictionary.
*
* @param svr The server object.
* @param compressed_len Pointer to memory to store the compressed length.
* @param data The decompressed data to compress.
* @param data_len Length of the decompressed data.
* @return The compressed data.
*/
unsigned char *compress(struct server *svr, uint64_t *compressed_len,
                        unsigned char *data, uint64_t data_len) {

    // Allocate a new array to hold the compressed data
    unsigned char *compressed = calloc(4*data_len, 1);

    // For each byte in the data, write the corresponding bit code to the
    // compressed data array.
    int dest_byte_offset = 0;
    uint8_t dest_bit_offset = 0;
    int src_byte_offset = 0;
    uint8_t src_bit_offset = 0;
    for (uint64_t i=0; i<data_len; i++) {
        uint8_t byte = (uint8_t)data[i];
        struct c_dict_entry *entry = svr->c_dict + (int)byte;
        src_byte_offset = 0;
        src_bit_offset = 0;
        move_bits((unsigned char *)compressed, &dest_byte_offset, &dest_bit_offset,
                  entry->encoding, &src_byte_offset, &src_bit_offset, entry->n_bits);
    }

    // Add the final byte which specifies the number of padding bits.
    uint8_t padding_len;
    if (dest_bit_offset == 0) {
        *compressed_len = dest_byte_offset + 1;
        padding_len = 0;
    } else {
        *compressed_len = dest_byte_offset + 2;
        padding_len = 8 - dest_bit_offset;
    }
    compressed = realloc(compressed, *compressed_len);
    compressed[(*compressed_len)-1] = padding_len;

    return compressed;
}

/**
* Decompresses data compressed using the compress() function by finding
* the byte value for each bit sequence using the decoding binary tree.
*
* @param svr The server object.
* @param decompressed_len Pointer to memory to store the decompressed length.
* @param data The compressed data to decompress.
* @param data_len Length of the compressed data.
* @return The decompressed data.
*/
unsigned char *decompress(struct server *svr, uint64_t *decompressed_len,
                          unsigned char *compressed_data, uint64_t data_len) {

    unsigned char *decompressed = calloc(4*data_len, 1);
    *decompressed_len = 0;
    int dest_byte_offset = 0;
    uint8_t dest_bit_offset = 0;
    int src_byte_offset = 0;
    uint8_t src_bit_offset = 0;

    // Calculate the number of bits which are part of the data
    uint8_t padding_len = compressed_data[data_len-1];
    int n_bits = 8*(data_len-1) - padding_len;

    // Start at the head of the decoding tree
    struct decode_node *decode_ptr = svr->decode_head;
    for (int i=0; i<n_bits; i++) {

        // Read one bit from the compressed data
        uint8_t bit = 0;
        dest_byte_offset = 0;
        dest_bit_offset = 0;
        move_bits((unsigned char *)&bit, &dest_byte_offset, &dest_bit_offset,
                  compressed_data, &src_byte_offset, &src_bit_offset, 1);

        // If a leaf node of the decoding tree is reached, append the
        // corresponding byte to the decompressed payload, and go back to
        // the decoding tree head to repeat this process for the remainder
        // of the compressed bit sequence.
        if (bit != 0) {
            bit = 1;
        }
        decode_ptr = decode_ptr->children[bit];
        if (decode_ptr->children[0] == NULL && decode_ptr->children[1] == NULL) {
            decompressed[*decompressed_len] = (unsigned char)(decode_ptr->byte);
            (*decompressed_len)++;
            decode_ptr = svr->decode_head;
        }
    }
    decompressed = realloc(decompressed, *decompressed_len);
    return decompressed;
}

/**
* Initialises the compression dictionary and decoding tree. The
* compression dictionary maps bytes to bit sequences, and the decoding
* tree finds the reverse mapping.
*
* @param svr The server object.
*/
void compression_init(struct server *svr) {
    memset(svr->c_dict, 0, 256*sizeof(struct c_dict_entry));

    // Read in the compression dictionary file.
    uint64_t len;
    unsigned char *dict = read_file(&len, "compression.dict");

    // Read all entries from the compression dictionary file into the
    // compression dictionary data structure.
    int dest_byte_offset = 0;
    uint8_t dest_bit_offset = 0;
    int src_byte_offset = 0;
    uint8_t src_bit_offset = 0;
    for (int i=0; i<256; i++) {
        struct c_dict_entry *entry = svr->c_dict + i;

        // Read the encoding length
        dest_byte_offset = 0;
        dest_bit_offset = 0;
        move_bits((unsigned char *)&entry->n_bits, &dest_byte_offset, &dest_bit_offset,
                  dict, &src_byte_offset, &src_bit_offset, 8);

        // Read the bit sequence
        dest_byte_offset = 0;
        dest_bit_offset = 0;
        move_bits((unsigned char *)entry->encoding, &dest_byte_offset, &dest_bit_offset,
                  dict, &src_byte_offset, &src_bit_offset, entry->n_bits);
    }

    // Construct the decoding tree by iterating through each byte value
    // in the dictionary and constructing a path in the tree corresponding
    // to the compressed bit sequence.
    svr->decode_head = calloc(1, sizeof(struct decode_node));
    for (int i=0; i<256; i++) {
        struct c_dict_entry *entry = svr->c_dict + i;
        uint8_t bit;
        struct decode_node *decode_ptr = svr->decode_head;
        src_byte_offset = 0;
        src_bit_offset = 0;
        for (uint8_t j=0; j<entry->n_bits; j++) {
            bit = 0;
            dest_byte_offset = 0;
            dest_bit_offset = 0;
            move_bits((unsigned char *)&bit, &dest_byte_offset, &dest_bit_offset,
                      entry->encoding, &src_byte_offset, &src_bit_offset, 1);

            if (bit != 0) {
                bit = 1;
            }
            // If the next node in the path doesn't already exist, create
            // a new node and add it to the path.
            if (decode_ptr->children[bit] == NULL) {
                decode_ptr->children[bit] = calloc(1, sizeof(struct decode_node));
            }
            decode_ptr = decode_ptr->children[bit];
        }
        decode_ptr->byte = (uint8_t)i;
    }
}

/**
* Initialises the server object which holds all memory and data relevant
* for the server to function.
*
* @param config_filepath The filepath to the server configuration file.
* @return The created server object.
*/
struct server *server_init(char *config_filepath) {

    struct server *svr = calloc(1, sizeof(struct server));

    // Read the configuration file data into the server structure
    FILE *f = fopen(config_filepath, "r");
    fseek(f, 0L, SEEK_END);
    uint32_t dir_name_len = ftell(f) - 6;
    rewind(f);
    fread(&svr->ipv4_addr, 4, 1, f);
    svr->ipv4_addr = ntohl(svr->ipv4_addr);
    fread(&svr->tcp_port, 2, 1, f);
    svr->tcp_port = ntohs(svr->tcp_port);
    svr->directory = calloc(dir_name_len + 1, sizeof(char));
    fread(svr->directory, dir_name_len, 1, f);
    fclose(f);

    // Initialise listener socket
    svr->listener = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in socket_addr;
    socket_addr.sin_family = AF_INET;
    socket_addr.sin_addr.s_addr = INADDR_ANY;
    socket_addr.sin_port = htons(svr->tcp_port);
    uint32_t option = 1;
    setsockopt(svr->listener, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &option, sizeof(option));
    bind(svr->listener, (struct sockaddr *)&socket_addr, sizeof(socket_addr));
    listen(svr->listener, MAX_PENDING_CONNECTIONS);

    // Initialise compression dictionary and decoding tree
    compression_init(svr);

    // Initialise connection queue
    int fd[2];
    pipe(fd);
    svr->dequeue_fd = fd[0];
    svr->enqueue_fd = fd[1];

    // Initialise session table for file transfers
    svr->st = session_table_init();

    // Initialise thread pool
    svr->thread_pool = malloc(THREAD_POOL_SIZE * sizeof(pthread_t));
    for (int i=0; i<THREAD_POOL_SIZE; i++) {
        struct worker_data *wd = malloc(sizeof(struct worker_data));
        wd->svr = svr;
        wd->worker_index = i;
        pthread_create(svr->thread_pool + i, NULL, worker, wd);
    }
    return svr;
}

int main(int argc, char **argv) {
    // Verify that the server configuration file has been provided
    if (argc != 2) {
        return 0;
    }

    // Initialise the server
    struct server *svr = server_init(argv[1]);

    // Continually listen for connection requests from clients and
    // append accepted connections to the client queue for worker threads
    // to connect to.
    int client;
    struct sockaddr_in client_addr;
    uint32_t addr_len = sizeof(struct sockaddr_in);
    while (1) {
        client = accept(svr->listener, (struct sockaddr *)&client_addr, &addr_len);
        write(svr->enqueue_fd, &client, sizeof(int));
    }

    server_destroy(svr);
    return 0;
}
