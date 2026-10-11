/*
 * p2p.c - TCP-based peer-to-peer file sharing system (single file, C, POSIX)
 *
 * Stage 1: networking foundation, tracker, seed preparation, metadata
 * Stage 2: peer-to-peer piece transfer and integrity verification
 *
 * Build:  gcc -Wall -Wextra p2p.c -o p2p -pthread
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <errno.h>
#include <time.h>

#define MAX_PEERS 32
#define MAX_PIECES 4096
#define MAX_SOURCES 32
#define PIECE_SIZE 262144
#define BUFFER_SIZE 4096

#define CMD_BITFIELD 1
#define CMD_PIECE 2

#define OK 0
#define FAIL 1

/* Stage 2 additions */
#define MAX_PIECE_SIZE (16 * 1024 * 1024) /* sanity limit for metadata */
#define IO_TIMEOUT_SEC 10                 /* per-socket send/recv timeout */
#define MAX_FAILS 3                       /* failures before a source is dropped in a round */
#define MAX_ROUNDS 3                      /* discovery rounds before giving up */

typedef struct {
    char id[32];
    int port;
    char filename[256];
    time_t last_seen;
    int active;
} Peer;

typedef struct {
    int count;
    Peer peers[MAX_PEERS];
} PeerList;

typedef struct {
    char filename[256];
    long long size;
    int piece_size;
    int piece_count;
    uint64_t file_hash;
    uint64_t piece_hash[MAX_PIECES];
} FileInfo;

typedef struct {
    Peer peer;
    unsigned char bits[(MAX_PIECES + 7) / 8];
} Source;

typedef struct {
    Source *sources;
    int source_count;
} DownloadContext;

char peer_id[32];
int peer_port;
int tracker_port;
char data_dir[512];
char output_file[512];

FileInfo info;

unsigned char have[(MAX_PIECES + 7) / 8];
unsigned char busy[(MAX_PIECES + 7) / 8];

pthread_mutex_t state_mutex = PTHREAD_MUTEX_INITIALIZER;

volatile int running = 1;

/* ---------------- BASIC HELPERS ---------------- */

void set_bit(unsigned char *bits, int n)
{
    bits[n / 8] |= (1 << (n % 8));
}

void clear_bit(unsigned char *bits, int n)
{
    bits[n / 8] &= ~(1 << (n % 8));
}

int get_bit(unsigned char *bits, int n)
{
    return (bits[n / 8] >> (n % 8)) & 1;
}

int send_all(int fd, void *buffer, int size)
{
    int sent = 0;

    while (sent < size) {
        int n = send(fd, buffer + sent, size - sent, 0);

        if (n <= 0)
            return -1;

        sent += n;
    }

    return 0;
}

int recv_all(int fd, void *buffer, int size)
{
    int received = 0;

    while (received < size) {
        int n = recv(fd, buffer + received, size - received, 0);

        if (n <= 0)
            return -1;

        received += n;
    }

    return 0;
}

/* Stage 2: now returns the send_all() result so callers can detect failure. */
int send_int(int fd, int value)
{
    int x = htonl(value);

    return send_all(fd, &x, sizeof(int));
}

int recv_int(int fd)
{
    int x;

    if (recv_all(fd, &x, sizeof(int)) < 0)
        return -1;

    return ntohl(x);
}

/* ---------------- SOCKET HELPERS (Stage 2) ---------------- */

/* Make blocking socket calls give up instead of hanging on a dead peer. */
void set_timeouts(int fd)
{
    struct timeval tv;

    tv.tv_sec = IO_TIMEOUT_SEC;
    tv.tv_usec = 0;

    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

/* Connect to 127.0.0.1:port. Returns a socket or -1. */
int connect_local(int port)
{
    int fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0)
        return -1;

    set_timeouts(fd);

    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

    if (connect(fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
}

/* ---------------- INTEGRITY HASH ---------------- */

/*
   64-bit FNV-1a hash.
   Used to detect corrupted or modified pieces.
*/
uint64_t hash_data(unsigned char *data, int size)
{
    uint64_t hash = 1469598103934665603ULL;

    for (int i = 0; i < size; i++) {
        hash ^= data[i];
        hash *= 1099511628211ULL;
    }

    return hash;
}

uint64_t hash_file(FILE *file)
{
    unsigned char buffer[8192];
    int n;

    uint64_t hash = 1469598103934665603ULL;

    while ((n = fread(buffer, 1, sizeof(buffer), file)) > 0) {
        for (int i = 0; i < n; i++) {
            hash ^= buffer[i];
            hash *= 1099511628211ULL;
        }
    }

    return hash;
}

/* ---------------- FILE PATH ---------------- */

void piece_path(char *path, int piece)
{
    sprintf(path, "%s/piece_%04d.dat", data_dir, piece);
}

/* Length in bytes of piece number `piece` (the last piece may be shorter). */
int piece_length(int piece)
{
    long long start = (long long)piece * info.piece_size;
    long long remaining = info.size - start;

    return remaining < info.piece_size ? (int)remaining : info.piece_size;
}

int has_piece(int piece)
{
    pthread_mutex_lock(&state_mutex);
    int value = get_bit(have, piece);
    pthread_mutex_unlock(&state_mutex);

    return value;
}

int count_have(void)
{
    int total = 0;

    pthread_mutex_lock(&state_mutex);

    for (int i = 0; i < info.piece_count; i++)
        total += get_bit(have, i);

    pthread_mutex_unlock(&state_mutex);

    return total;
}

/* ---------------- FILE PREPARATION ---------------- */

int create_seed_data(char *filename)
{
    FILE *input = fopen(filename, "rb");

    if (!input) {
        perror("file");
        return -1;
    }

    fseek(input, 0, SEEK_END);
    info.size = ftell(input);
    rewind(input);

    info.piece_size = PIECE_SIZE;

    /* Stage 2: reject sizes that would overflow info.piece_hash[]. */
    if (info.size <= 0 ||
        info.size > (long long)MAX_PIECES * info.piece_size) {
        fprintf(stderr,
                "%s must be between 1 and %lld bytes\n",
                filename,
                (long long)MAX_PIECES * info.piece_size);
        fclose(input);
        return -1;
    }

    info.piece_count =
        (info.size + info.piece_size - 1) / info.piece_size;

    const char *base = strrchr(filename, '/') ?
                       strrchr(filename, '/') + 1 :
                       filename;

    /* The tracker and metadata formats are whitespace-delimited. */
    if (strlen(base) >= sizeof(info.filename) ||
        strpbrk(base, " \t\r\n")) {
        fprintf(stderr,
                "file name must be shorter than %d characters and contain no whitespace\n",
                (int)sizeof(info.filename));
        fclose(input);
        return -1;
    }

    strcpy(info.filename, base);

    if (mkdir(data_dir, 0755) < 0 && errno != EEXIST) {
        perror(data_dir);
        fclose(input);
        return -1;
    }

    unsigned char *buffer = malloc(info.piece_size);

    if (!buffer) {
        fclose(input);
        return -1;
    }

    for (int i = 0; i < info.piece_count; i++) {
        int remaining = info.size - ((long long)i * info.piece_size);

        int length = remaining < info.piece_size ?
                     remaining :
                     info.piece_size;

        if (fread(buffer, 1, length, input) != (size_t)length) {
            fprintf(stderr, "read error while splitting %s\n", filename);
            free(buffer);
            fclose(input);
            return -1;
        }

        char path[512];
        piece_path(path, i);

        FILE *piece = fopen(path, "wb");

        if (!piece) {
            perror(path);
            free(buffer);
            fclose(input);
            return -1;
        }

        fwrite(buffer, 1, length, piece);
        fclose(piece);

        info.piece_hash[i] = hash_data(buffer, length);

        set_bit(have, i);
    }

    rewind(input);

    info.file_hash = hash_file(input);

    fclose(input);
    free(buffer);

    char meta[512];

    snprintf(meta, sizeof(meta), "%s.meta", filename);

    FILE *metadata = fopen(meta, "w");

    if (!metadata)
        return -1;

    fprintf(metadata, "%s\n", info.filename);
    fprintf(metadata, "%lld\n", info.size);
    fprintf(metadata, "%d\n", info.piece_size);
    fprintf(metadata, "%d\n", info.piece_count);
    fprintf(metadata, "%llu\n", (unsigned long long)info.file_hash);

    for (int i = 0; i < info.piece_count; i++) {
        fprintf(metadata, "%llu\n", (unsigned long long)info.piece_hash[i]);
    }

    fclose(metadata);

    return 0;
}

/* ---------------- READ METADATA ---------------- */

/*
   Stage 2: every fscanf() result is checked and the values are range-checked,
   because a corrupt .meta file would otherwise overflow info.piece_hash[].
*/
int read_metadata(char *filename)
{
    FILE *file = fopen(filename, "r");

    if (!file)
        return -1;

    unsigned long long value;

    if (fscanf(file, "%255s", info.filename) != 1 ||
        fscanf(file, "%lld", &info.size) != 1 ||
        fscanf(file, "%d", &info.piece_size) != 1 ||
        fscanf(file, "%d", &info.piece_count) != 1 ||
        fscanf(file, "%llu", &value) != 1) {
        fclose(file);
        return -1;
    }

    info.file_hash = value;

    if (info.size <= 0 ||
        info.piece_size <= 0 ||
        info.piece_size > MAX_PIECE_SIZE ||
        info.piece_count <= 0 ||
        info.piece_count > MAX_PIECES ||
        (info.size + info.piece_size - 1) / info.piece_size != info.piece_count) {
        fclose(file);
        return -1;
    }

    for (int i = 0; i < info.piece_count; i++) {
        if (fscanf(file, "%llu", &value) != 1) {
            fclose(file);
            return -1;
        }

        info.piece_hash[i] = value;
    }

    fclose(file);

    return 0;
}

/* ---------------- TRACKER ---------------- */

Peer tracker_peers[MAX_PEERS];

pthread_mutex_t tracker_mutex = PTHREAD_MUTEX_INITIALIZER;

void send_tracker_peers(int fd, char *filename)
{
    char response[4096];
    int count = 0;

    for (int i = 0; i < MAX_PEERS; i++) {
        if (!tracker_peers[i].active)
            continue;

        if (strcmp(tracker_peers[i].filename, filename) == 0)
            count++;
    }

    sprintf(response, "%d\n", count);

    send_all(fd, response, strlen(response));

    for (int i = 0; i < MAX_PEERS; i++) {
        if (!tracker_peers[i].active)
            continue;

        if (strcmp(tracker_peers[i].filename, filename) != 0)
            continue;

        sprintf(response, "%s %d\n",
                tracker_peers[i].id,
                tracker_peers[i].port);

        send_all(fd, response, strlen(response));
    }
}

void *tracker_client(void *arg)
{
    int fd = *(int *)arg;

    free(arg);

    char buffer[1024];

    int n = recv(fd, buffer, sizeof(buffer) - 1, 0);

    if (n <= 0) {
        close(fd);
        return NULL;
    }

    buffer[n] = '\0';

    if (strncmp(buffer, "REGISTER", 8) == 0) {
        char id[32];
        int port;
        char filename[256];

        sscanf(buffer, "REGISTER %31s %d %255s", id, &port, filename);

        pthread_mutex_lock(&tracker_mutex);

        int slot = -1;

        for (int i = 0; i < MAX_PEERS; i++) {
            if (tracker_peers[i].active &&
                strcmp(tracker_peers[i].id, id) == 0) {
                slot = i;
                break;
            }
        }

        if (slot == -1) {
            for (int i = 0; i < MAX_PEERS; i++) {
                if (!tracker_peers[i].active) {
                    slot = i;
                    break;
                }
            }
        }

        if (slot != -1) {
            strcpy(tracker_peers[slot].id, id);
            strcpy(tracker_peers[slot].filename, filename);

            tracker_peers[slot].port = port;
            tracker_peers[slot].last_seen = time(NULL);
            tracker_peers[slot].active = 1;
        }

        pthread_mutex_unlock(&tracker_mutex);

        send(fd, "OK\n", 3, 0);
    }
    else if (strncmp(buffer, "GET", 3) == 0) {
        char filename[256];

        sscanf(buffer, "GET %255s", filename);

        pthread_mutex_lock(&tracker_mutex);

        send_tracker_peers(fd, filename);

        pthread_mutex_unlock(&tracker_mutex);
    }

    close(fd);

    return NULL;
}

void run_tracker(int port)
{
    int server = socket(AF_INET, SOCK_STREAM, 0);

    int reuse = 1;

    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("bind");
        exit(1);
    }

    listen(server, 20);

    printf("Tracker running on port %d\n", port);

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t size = sizeof(client_addr);

        int client = accept(server, (struct sockaddr *)&client_addr, &size);

        if (client < 0)
            continue;

        int *fd = malloc(sizeof(int));

        *fd = client;

        pthread_t thread;

        pthread_create(&thread, NULL, tracker_client, fd);
        pthread_detach(thread);
    }
}

/* ---------------- PEER REGISTRATION ---------------- */

/* Stage 2: returns 0 only if the tracker answered "OK", otherwise -1. */
int register_peer(void)
{
    int fd = connect_local(tracker_port);

    if (fd < 0)
        return -1;

    char message[512];

    snprintf(message, sizeof(message),
             "REGISTER %s %d %s\n",
             peer_id,
             peer_port,
             info.filename);

    if (send_all(fd, message, strlen(message)) < 0) {
        close(fd);
        return -1;
    }

    char reply[16];

    int n = recv(fd, reply, sizeof(reply) - 1, 0);

    close(fd);

    if (n < 2 || strncmp(reply, "OK", 2) != 0)
        return -1;

    return 0;
}

/* ---------------- GET PEERS ---------------- */

/*
   `peers` must have room for MAX_PEERS entries.

   Stage 2: the reply is now read until the tracker closes the connection.
   The tracker sends the count and each peer line with separate send() calls,
   so a single recv() could return only the first line and report 0 peers.
*/
int get_peers(Peer *peers)
{
    int fd = connect_local(tracker_port);

    if (fd < 0)
        return 0;

    char message[512];

    snprintf(message, sizeof(message), "GET %s\n", info.filename);

    if (send_all(fd, message, strlen(message)) < 0) {
        close(fd);
        return 0;
    }

    char buffer[4096];
    int n = 0;

    while (n < (int)sizeof(buffer) - 1) {
        int r = recv(fd, buffer + n, sizeof(buffer) - 1 - n, 0);

        if (r <= 0)
            break;

        n += r;
    }

    close(fd);

    if (n <= 0)
        return 0;

    buffer[n] = '\0';

    int count = 0;

    char *line = strtok(buffer, "\n");

    if (!line)
        return 0;

    int total = atoi(line);

    line = strtok(NULL, "\n");

    while (line && count < total && count < MAX_PEERS) {
        if (sscanf(line, "%31s %d", peers[count].id, &peers[count].port) == 2)
            count++;

        line = strtok(NULL, "\n");
    }

    return count;
}

/* ================================================================
   STAGE 2: PEER-TO-PEER PIECE TRANSFER AND INTEGRITY VERIFICATION

   Wire protocol (one request per TCP connection, integers are 32-bit
   big-endian, i.e. htonl/ntohl, via send_int/recv_int):

     BITFIELD request : int CMD_BITFIELD
     BITFIELD reply   : int OK, int nbytes, nbytes of bitfield
                        (bit i set = peer holds a verified piece i)

     PIECE request    : int CMD_PIECE, int piece_index
     PIECE reply      : int OK, int length, `length` bytes of data
                        or just int FAIL if the piece is unavailable
   ================================================================ */

/* ---------------- SERVING SIDE ---------------- */

void serve_bitfield(int fd)
{
    int nbytes = (info.piece_count + 7) / 8;
    unsigned char bits[(MAX_PIECES + 7) / 8];

    pthread_mutex_lock(&state_mutex);
    memcpy(bits, have, nbytes);
    pthread_mutex_unlock(&state_mutex);

    if (send_int(fd, OK) < 0 || send_int(fd, nbytes) < 0)
        return;

    send_all(fd, bits, nbytes);
}

void serve_piece(int fd)
{
    int piece = recv_int(fd);

    if (piece < 0 || piece >= info.piece_count || !has_piece(piece)) {
        send_int(fd, FAIL);
        return;
    }

    int length = piece_length(piece);

    /* One extra byte so a file that is too long is detected as well. */
    unsigned char *buffer = malloc(length + 1);

    if (!buffer) {
        send_int(fd, FAIL);
        return;
    }

    char path[512];

    piece_path(path, piece);

    FILE *file = fopen(path, "rb");
    size_t got = 0;

    if (file) {
        got = fread(buffer, 1, length + 1, file);
        fclose(file);
    }

    /* Never forward a piece that no longer matches the metadata hash. */
    if (got != (size_t)length ||
        hash_data(buffer, length) != info.piece_hash[piece]) {
        fprintf(stderr,
                "[%s] local copy of piece %d is missing or corrupted; refusing to serve it\n",
                peer_id, piece);
        free(buffer);
        send_int(fd, FAIL);
        return;
    }

    if (send_int(fd, OK) == 0 &&
        send_int(fd, length) == 0 &&
        send_all(fd, buffer, length) == 0)
        printf("[%s] served piece %d (%d bytes)\n", peer_id, piece, length);
    else
        fprintf(stderr, "[%s] client disconnected during piece %d\n", peer_id, piece);

    free(buffer);
}

void *peer_client(void *arg)
{
    int fd = *(int *)arg;

    free(arg);

    set_timeouts(fd);

    int command = recv_int(fd);

    if (command == CMD_BITFIELD)
        serve_bitfield(fd);
    else if (command == CMD_PIECE)
        serve_piece(fd);

    close(fd);

    return NULL;
}

/* Create the listening socket (done before registering with the tracker). */
int open_listener(int port)
{
    int server = socket(AF_INET, SOCK_STREAM, 0);

    if (server < 0) {
        perror("socket");
        return -1;
    }

    int reuse = 1;

    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

    struct sockaddr_in address;

    memset(&address, 0, sizeof(address));

    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0) {
        fprintf(stderr, "Cannot listen on port %d: %s\n", port, strerror(errno));
        close(server);
        return -1;
    }

    if (listen(server, 20) < 0) {
        perror("listen");
        close(server);
        return -1;
    }

    return server;
}

/* Accept loop; one detached thread per request. Argument: listening fd. */
void *accept_loop(void *arg)
{
    int server = (int)(intptr_t)arg;

    while (running) {
        struct sockaddr_in client_addr;
        socklen_t size = sizeof(client_addr);

        int client = accept(server, (struct sockaddr *)&client_addr, &size);

        if (client < 0)
            continue;

        int *fd = malloc(sizeof(int));

        if (!fd) {
            close(client);
            continue;
        }

        *fd = client;

        pthread_t thread;

        if (pthread_create(&thread, NULL, peer_client, fd) != 0) {
            close(client);
            free(fd);
            continue;
        }

        pthread_detach(thread);
    }

    return NULL;
}

/* ---------------- DOWNLOADING SIDE ---------------- */

/* Ask a peer which pieces it holds. Returns 0 on success. */
int fetch_bitfield(int port, unsigned char *bits)
{
    int nbytes = (info.piece_count + 7) / 8;
    int result = -1;

    int fd = connect_local(port);

    if (fd < 0)
        return -1;

    if (send_int(fd, CMD_BITFIELD) == 0 &&
        recv_int(fd) == OK &&
        recv_int(fd) == nbytes &&
        recv_all(fd, bits, nbytes) == 0)
        result = 0;

    close(fd);

    return result;
}

/*
   Download one piece, verify it, store it and mark it as held.
   A piece is stored and marked ONLY if its length and 64-bit hash match
   the metadata. The data is written to a .part file and renamed so a
   half-written piece can never be mistaken for a good one.
*/
int download_piece(const Peer *peer, int piece)
{
    int length = piece_length(piece);
    int status = FAIL;
    unsigned char *buffer = malloc(length);
    int fd = -1;

    if (!buffer)
        return FAIL;

    fd = connect_local(peer->port);

    if (fd < 0) {
        printf("  cannot connect to %s (port %d)\n", peer->id, peer->port);
        goto done;
    }

    if (send_int(fd, CMD_PIECE) < 0 || send_int(fd, piece) < 0) {
        printf("  failed to send request to %s\n", peer->id);
        goto done;
    }

    if (recv_int(fd) != OK) {
        printf("  %s does not have a usable copy of piece %d\n", peer->id, piece);
        goto done;
    }

    if (recv_int(fd) != length) {
        printf("  %s announced a wrong length for piece %d\n", peer->id, piece);
        goto done;
    }

    if (recv_all(fd, buffer, length) < 0) {
        printf("  %s disconnected during piece %d\n", peer->id, piece);
        goto done;
    }

    if (hash_data(buffer, length) != info.piece_hash[piece]) {
        printf("  INTEGRITY FAILURE: piece %d from %s does not match its hash; discarded\n",
               piece, peer->id);
        goto done;
    }

    char path[512];
    char temp[560];

    piece_path(path, piece);
    snprintf(temp, sizeof(temp), "%s.part", path);

    FILE *out = fopen(temp, "wb");

    if (!out) {
        perror(temp);
        goto done;
    }

    size_t written = fwrite(buffer, 1, length, out);
    int closed = fclose(out);

    if (written != (size_t)length || closed != 0) {
        perror("write piece");
        remove(temp);
        goto done;
    }

    if (rename(temp, path) != 0) {
        perror("rename piece");
        remove(temp);
        goto done;
    }

    pthread_mutex_lock(&state_mutex);
    set_bit(have, piece);
    pthread_mutex_unlock(&state_mutex);

    status = OK;

done:
    if (fd >= 0)
        close(fd);

    free(buffer);

    return status;
}

/*
   On start-up, re-verify piece files left by an earlier run so an
   interrupted download can resume. Returns the number of valid pieces,
   or -1 on out-of-memory.
*/
int load_existing_pieces(void)
{
    int found = 0;

    unsigned char *buffer = malloc(info.piece_size + 1);

    if (!buffer)
        return -1;

    for (int i = 0; i < info.piece_count; i++) {
        char path[512];

        piece_path(path, i);

        FILE *file = fopen(path, "rb");

        if (!file)
            continue;

        int length = piece_length(i);
        size_t got = fread(buffer, 1, length + 1, file);

        fclose(file);

        if (got == (size_t)length &&
            hash_data(buffer, length) == info.piece_hash[i]) {
            pthread_mutex_lock(&state_mutex);
            set_bit(have, i);
            pthread_mutex_unlock(&state_mutex);
            found++;
        } else {
            printf("Existing piece %d is corrupt or incomplete; it will be downloaded again\n", i);
        }
    }

    free(buffer);

    return found;
}

/*
   Discover peers, read their bitfields and fetch every missing piece from
   the first reachable peer that advertises it. Returns the number of pieces
   that are still missing (0 = complete).
*/
int download_all(void)
{
    static Source sources[MAX_SOURCES];
    int failures[MAX_SOURCES];
    Peer peers[MAX_PEERS];

    for (int round = 1; round <= MAX_ROUNDS; round++) {
        if (count_have() == info.piece_count)
            return 0;

        memset(peers, 0, sizeof(peers));

        int found = get_peers(peers);
        int count = 0;

        for (int i = 0; i < found && count < MAX_SOURCES; i++) {
            /* Never download from ourselves. */
            if (peers[i].port == peer_port ||
                strcmp(peers[i].id, peer_id) == 0)
                continue;

            memset(&sources[count], 0, sizeof(Source));
            sources[count].peer = peers[i];

            if (fetch_bitfield(peers[i].port, sources[count].bits) == 0) {
                failures[count] = 0;
                count++;
            } else {
                printf("Peer %s (port %d) is unreachable; skipping it\n",
                       peers[i].id, peers[i].port);
            }
        }

        printf("Round %d/%d: tracker listed %d peer(s), %d reachable\n",
               round, MAX_ROUNDS, found, count);

        for (int piece = 0; piece < info.piece_count; piece++) {
            if (has_piece(piece))
                continue;

            int ok = 0;
            int tried = 0;

            for (int s = 0; s < count && !ok; s++) {
                if (!get_bit(sources[s].bits, piece) || failures[s] >= MAX_FAILS)
                    continue;

                tried++;

                printf("Requesting piece %d from %s (port %d)\n",
                       piece, sources[s].peer.id, sources[s].peer.port);

                if (download_piece(&sources[s].peer, piece) == OK) {
                    printf("  piece %d verified and stored (%d/%d pieces held)\n",
                           piece, count_have(), info.piece_count);
                    ok = 1;
                } else {
                    failures[s]++;
                }
            }

            if (!ok && tried == 0)
                printf("No reachable peer currently offers piece %d\n", piece);
        }

        if (count_have() == info.piece_count)
            return 0;

        if (round < MAX_ROUNDS)
            sleep(2);
    }

    return info.piece_count - count_have();
}

/* ---------------- COMMAND-LINE HANDLING ---------------- */

int parse_port(const char *text)
{
    char *end;

    errno = 0;

    long value = strtol(text, &end, 10);

    if (errno != 0 || end == text || *end != '\0' || value < 1 || value > 65535)
        return -1;

    return (int)value;
}

int valid_peer_id(const char *id)
{
    size_t length = strlen(id);

    if (length == 0 || length >= sizeof(peer_id))
        return 0;

    for (size_t i = 0; i < length; i++) {
        unsigned char c = id[i];

        if (!isalnum(c) && c != '_' && c != '-')
            return 0;
    }

    return 1;
}

/* Validate and store <peer_id> <port> <tracker_port>. Returns 0 on success. */
int setup_peer(const char *id, const char *port_text, const char *tracker_text)
{
    if (!valid_peer_id(id)) {
        fprintf(stderr,
                "Invalid peer_id '%s': use 1-31 letters, digits, '-' or '_'\n", id);
        return -1;
    }

    int port = parse_port(port_text);
    int tport = parse_port(tracker_text);

    if (port < 0) {
        fprintf(stderr, "Invalid port '%s' (use 1-65535)\n", port_text);
        return -1;
    }

    if (tport < 0) {
        fprintf(stderr, "Invalid tracker port '%s' (use 1-65535)\n", tracker_text);
        return -1;
    }

    if (port == tport) {
        fprintf(stderr, "Peer port and tracker port must differ\n");
        return -1;
    }

    strcpy(peer_id, id);

    peer_port = port;
    tracker_port = tport;

    snprintf(data_dir, sizeof(data_dir), "data_%s", peer_id);

    return 0;
}

int run_seed(char *id, char *port_text, char *tracker_text, char *file)
{
    if (setup_peer(id, port_text, tracker_text) != 0)
        return 1;

    if (create_seed_data(file) != 0) {
        fprintf(stderr, "Could not prepare '%s' for seeding\n", file);
        return 1;
    }

    int listener = open_listener(peer_port);

    if (listener < 0)
        return 1;

    if (register_peer() != 0) {
        fprintf(stderr,
                "Could not register with the tracker on port %d. Is it running?\n",
                tracker_port);
        return 1;
    }

    printf("Seed '%s' serving %d piece(s) of %s on port %d\n",
           peer_id, info.piece_count, info.filename, peer_port);
    printf("Pieces are in %s/ and metadata is in %s.meta\n", data_dir, file);

    accept_loop((void *)(intptr_t)listener);

    return 0;
}

/*
 * Reconstruct the original file from verified pieces.
 * The output stays inside this peer's data directory.
 * A temporary file is renamed only after size and whole-file hash checks pass.
 */
int reconstruct_file(void)
{
    char final_path[1024];
    char temp_path[1024];

    if (strchr(info.filename, '/') != NULL ||
        strcmp(info.filename, ".") == 0 ||
        strcmp(info.filename, "..") == 0) {
        fprintf(stderr, "Invalid filename in metadata\n");
        return -1;
    }

    int a = snprintf(final_path, sizeof(final_path), "%s/%s",
                     data_dir, info.filename);
    int b = snprintf(temp_path, sizeof(temp_path), "%s/%s.reconstructing",
                     data_dir, info.filename);

    if (a < 0 || (size_t)a >= sizeof(final_path) ||
        b < 0 || (size_t)b >= sizeof(temp_path)) {
        fprintf(stderr, "Reconstructed file path is too long\n");
        return -1;
    }

    unsigned char *buffer = malloc((size_t)info.piece_size + 1);
    if (!buffer) {
        perror("malloc");
        return -1;
    }

    FILE *out = fopen(temp_path, "wb");
    if (!out) {
        perror(temp_path);
        free(buffer);
        return -1;
    }

    int failed = 0;

    for (int i = 0; i < info.piece_count; i++) {
        char path[512];
        piece_path(path, i);

        FILE *piece_file = fopen(path, "rb");
        if (!piece_file) {
            fprintf(stderr, "Cannot open piece %d: %s\n", i, path);
            failed = 1;
            break;
        }

        int length = piece_length(i);
        size_t got = fread(buffer, 1, (size_t)length + 1, piece_file);
        int read_error = ferror(piece_file);
        fclose(piece_file);

        if (read_error || got != (size_t)length ||
            hash_data(buffer, length) != info.piece_hash[i]) {
            fprintf(stderr, "Piece %d failed reconstruction verification\n", i);
            failed = 1;
            break;
        }

        if (fwrite(buffer, 1, (size_t)length, out) != (size_t)length) {
            perror("writing reconstructed file");
            failed = 1;
            break;
        }
    }

    if (fclose(out) != 0) {
        perror("closing reconstructed file");
        failed = 1;
    }

    free(buffer);

    if (failed) {
        remove(temp_path);
        return -1;
    }

    FILE *check = fopen(temp_path, "rb");
    if (!check) {
        perror(temp_path);
        remove(temp_path);
        return -1;
    }

    int size_ok = fseek(check, 0, SEEK_END) == 0;
    long long actual_size = size_ok ? (long long)ftell(check) : -1;
    int hash_ok = fseek(check, 0, SEEK_SET) == 0;
    uint64_t actual_hash = hash_ok ? hash_file(check) : 0;
    int check_error = ferror(check);
    fclose(check);

    if (!size_ok || !hash_ok || check_error ||
        actual_size != info.size || actual_hash != info.file_hash) {
        fprintf(stderr, "Reconstructed file failed size or hash verification\n");
        remove(temp_path);
        return -1;
    }

    if (rename(temp_path, final_path) != 0) {
        perror("renaming reconstructed file");
        remove(temp_path);
        return -1;
    }

    printf("Reconstructed and verified file: %s\n", final_path);
    return 0;
}

int run_download(char *id, char *port_text, char *tracker_text,
                 char *meta, int exit_when_done)
{
    if (setup_peer(id, port_text, tracker_text) != 0)
        return 1;

    if (read_metadata(meta) != 0) {
        fprintf(stderr, "Cannot read valid metadata from '%s'\n", meta);
        return 1;
    }

    if (mkdir(data_dir, 0755) < 0 && errno != EEXIST) {
        perror(data_dir);
        return 1;
    }

    printf("File %s: %lld bytes in %d piece(s) of up to %d bytes\n",
           info.filename, info.size, info.piece_count, info.piece_size);

    int existing = load_existing_pieces();

    if (existing < 0)
        return 1;

    if (existing > 0)
        printf("Resuming: %d of %d piece(s) already present and verified\n",
               existing, info.piece_count);

    int listener = open_listener(peer_port);

    if (listener < 0)
        return 1;

    pthread_t thread;

    if (pthread_create(&thread, NULL, accept_loop, (void *)(intptr_t)listener) != 0) {
        fprintf(stderr, "Could not start the upload thread\n");
        return 1;
    }

    pthread_detach(thread);

    if (register_peer() != 0) {
        fprintf(stderr,
                "Could not register with the tracker on port %d. Is it running?\n",
                tracker_port);
        return 1;
    }

    int missing = download_all();

    if (missing > 0) {
        printf("\nINCOMPLETE: %d of %d piece(s) are still missing:", missing, info.piece_count);

        int shown = 0;

        for (int i = 0; i < info.piece_count && shown < 20; i++) {
            if (!has_piece(i)) {
                printf(" %d", i);
                shown++;
            }
        }

        printf("%s\nRun the same command again once a peer holding them is available.\n",
               missing > 20 ? " ..." : "");

        return 2;
    }

    if (reconstruct_file() != 0) {
        fprintf(stderr, "Download pieces are present, but reconstruction failed.\n");
        return 3;
    }

    printf("\nDownload complete: %d piece(s) verified and reconstructed in %s/%s\n",
           info.piece_count, data_dir, info.filename);

    if (exit_when_done)
        return 0;

    printf("Seeding on port %d. Press Ctrl+C to stop.\n", peer_port);

    while (running)
        sleep(1);

    return 0;
}

void print_usage(FILE *out)
{
    fprintf(out,
            "P2P file sharing - peer-to-peer piece transfer and integrity verification\n\n"
            "Usage:\n"
            "  ./p2p tracker <port>\n"
            "  ./p2p seed <peer_id> <port> <tracker_port> <file>\n"
            "  ./p2p download <peer_id> <port> <tracker_port> <meta_file> [--exit-when-done]\n\n"
            "Examples:\n"
            "  ./p2p tracker 9000\n"
            "  ./p2p seed A 9001 9000 test.bin\n"
            "  ./p2p download B 9002 9000 test.bin.meta\n");
}

/* ---------------- MAIN ---------------- */

int main(int argc, char **argv)
{
    /* A peer that disconnects mid-transfer must not kill this process. */
    signal(SIGPIPE, SIG_IGN);

    /* Show progress immediately even when output is redirected to a file. */
    setvbuf(stdout, NULL, _IOLBF, 0);

    if (argc == 3 && strcmp(argv[1], "tracker") == 0) {
        int port = parse_port(argv[2]);

        if (port < 0) {
            fprintf(stderr, "Invalid port '%s' (use 1-65535)\n", argv[2]);
            return 1;
        }

        run_tracker(port);

        return 0;
    }

    if (argc == 6 && strcmp(argv[1], "seed") == 0)
        return run_seed(argv[2], argv[3], argv[4], argv[5]);

    if ((argc == 6 || argc == 7) && strcmp(argv[1], "download") == 0) {
        int exit_when_done = 0;

        if (argc == 7) {
            if (strcmp(argv[6], "--exit-when-done") != 0) {
                print_usage(stderr);
                return 1;
            }

            exit_when_done = 1;
        }

        return run_download(argv[2], argv[3], argv[4], argv[5], exit_when_done);
    }

    print_usage(stderr);

    return 1;
}