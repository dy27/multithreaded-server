// An st_node object is used for the nodes of the session table hash map which
// is implemented using separate chaining. It contains the relevant information
// for the current file transfer session, as well as a pointer to the next node
// and a mutex for the session.
struct st_node {
    uint32_t session_id;
    char *file_name;
    int src_fd;
    int *dest_fds;
    int n_dest_fds;
    uint64_t start_offset;
    uint64_t curr_offset;
    uint64_t target_offset;
    pthread_mutex_t lock;
    int enqueue_new_fd;
    int dequeue_new_fd;
    struct st_node *next;
};

// A session_table is a fixed-size hash map implemented using separate chaining.
// It contains all the file transfer sessions.
struct session_table {
    struct st_node **buckets;
    size_t n_buckets;
    pthread_mutex_t global_lock;
};

struct session_table *session_table_init();

struct st_node *session_table_get(struct session_table *st, uint32_t session_id);

void session_table_remove(struct session_table *st, uint32_t session_id);

void session_table_destroy(struct session_table *st);
