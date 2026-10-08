#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

void send_int(int fd, int value)
{
    int x = htonl(value);
    send_all(fd, &x, sizeof(int));
}

int recv_int(int fd)
{
    int x;

    if (recv_all(fd, &x, sizeof(int)) < 0)
        return -1;

    return ntohl(x);
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
    sprintf(
        path,
        "%s/piece_%04d.dat",
        data_dir,
        piece
    );
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

    info.piece_count =
        (info.size + info.piece_size - 1) /
        info.piece_size;

    strcpy(
        info.filename,
        strrchr(filename, '/') ?
        strrchr(filename, '/') + 1 :
        filename
    );

    mkdir(data_dir, 0755);

    unsigned char *buffer =
        malloc(info.piece_size);

    if (!buffer) {
        fclose(input);
        return -1;
    }

    for (int i = 0; i < info.piece_count; i++) {

        int remaining =
            info.size -
            ((long long)i * info.piece_size);

        int length =
            remaining < info.piece_size ?
            remaining :
            info.piece_size;

        fread(buffer, 1, length, input);

        char path[512];

        piece_path(path, i);

        FILE *piece =
            fopen(path, "wb");

        if (!piece) {
            free(buffer);
            fclose(input);
            return -1;
        }

        fwrite(buffer, 1, length, piece);
        fclose(piece);

        info.piece_hash[i] =
            hash_data(buffer, length);

        set_bit(have, i);
    }

    rewind(input);

    info.file_hash =
        hash_file(input);

    fclose(input);

    free(buffer);

    char meta[512];

    sprintf(
        meta,
        "%s.meta",
        filename
    );

    FILE *metadata =
        fopen(meta, "w");

    if (!metadata)
        return -1;

    fprintf(
        metadata,
        "%s\n",
        info.filename
    );

    fprintf(
        metadata,
        "%lld\n",
        info.size
    );

    fprintf(
        metadata,
        "%d\n",
        info.piece_size
    );

    fprintf(
        metadata,
        "%d\n",
        info.piece_count
    );

    fprintf(
        metadata,
        "%llu\n",
        (unsigned long long)info.file_hash
    );

    for (int i = 0; i < info.piece_count; i++) {
        fprintf(
            metadata,
            "%llu\n",
            (unsigned long long)info.piece_hash[i]
        );
    }

    fclose(metadata);

    return 0;
}


/* ---------------- READ METADATA ---------------- */

int read_metadata(char *filename)
{
    FILE *file =
        fopen(filename, "r");

    if (!file)
        return -1;

    fscanf(
        file,
        "%255s",
        info.filename
    );

    fscanf(
        file,
        "%lld",
        &info.size
    );

    fscanf(
        file,
        "%d",
        &info.piece_size
    );

    fscanf(
        file,
        "%d",
        &info.piece_count
    );

    unsigned long long value;

    fscanf(
        file,
        "%llu",
        &value
    );

    info.file_hash =
        value;

    for (int i = 0;
         i < info.piece_count;
         i++) {

        fscanf(
            file,
            "%llu",
            &value
        );

        info.piece_hash[i] =
            value;
    }

    fclose(file);

    return 0;
}


/* ---------------- TRACKER ---------------- */

Peer tracker_peers[MAX_PEERS];

pthread_mutex_t tracker_mutex =
    PTHREAD_MUTEX_INITIALIZER;


void send_tracker_peers(
    int fd,
    char *filename
)
{
    char response[4096];

    int count = 0;

    for (int i = 0; i < MAX_PEERS; i++) {

        if (!tracker_peers[i].active)
            continue;

        if (
            strcmp(
                tracker_peers[i].filename,
                filename
            ) == 0
        )
            count++;
    }

    sprintf(
        response,
        "%d\n",
        count
    );

    send_all(
        fd,
        response,
        strlen(response)
    );

    for (int i = 0; i < MAX_PEERS; i++) {

        if (!tracker_peers[i].active)
            continue;

        if (
            strcmp(
                tracker_peers[i].filename,
                filename
            ) != 0
        )
            continue;

        sprintf(
            response,
            "%s %d\n",
            tracker_peers[i].id,
            tracker_peers[i].port
        );

        send_all(
            fd,
            response,
            strlen(response)
        );
    }
}


void *tracker_client(void *arg)
{
    int fd =
        *(int *)arg;

    free(arg);

    char buffer[1024];

    int n =
        recv(
            fd,
            buffer,
            sizeof(buffer) - 1,
            0
        );

    if (n <= 0) {
        close(fd);
        return NULL;
    }

    buffer[n] = '\0';

    if (
        strncmp(
            buffer,
            "REGISTER",
            8
        ) == 0
    ) {

        char id[32];
        int port;
        char filename[256];

        sscanf(
            buffer,
            "REGISTER %31s %d %255s",
            id,
            &port,
            filename
        );

        pthread_mutex_lock(
            &tracker_mutex
        );

        int slot = -1;

        for (int i = 0; i < MAX_PEERS; i++) {

            if (
                tracker_peers[i].active &&
                strcmp(
                    tracker_peers[i].id,
                    id
                ) == 0
            ) {
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

            strcpy(
                tracker_peers[slot].id,
                id
            );

            strcpy(
                tracker_peers[slot].filename,
                filename
            );

            tracker_peers[slot].port =
                port;

            tracker_peers[slot].last_seen =
                time(NULL);

            tracker_peers[slot].active =
                1;
        }

        pthread_mutex_unlock(
            &tracker_mutex
        );

        send(
            fd,
            "OK\n",
            3,
            0
        );
    }

    else if (
        strncmp(
            buffer,
            "GET",
            3
        ) == 0
    ) {

        char filename[256];

        sscanf(
            buffer,
            "GET %255s",
            filename
        );

        pthread_mutex_lock(
            &tracker_mutex
        );

        send_tracker_peers(
            fd,
            filename
        );

        pthread_mutex_unlock(
            &tracker_mutex
        );
    }

    close(fd);

    return NULL;
}


void run_tracker(int port)
{
    int server =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    int reuse = 1;

    setsockopt(
        server,
        SOL_SOCKET,
        SO_REUSEADDR,
        &reuse,
        sizeof(reuse)
    );

    struct sockaddr_in address;

    memset(
        &address,
        0,
        sizeof(address)
    );

    address.sin_family =
        AF_INET;

    address.sin_addr.s_addr =
        INADDR_ANY;

    address.sin_port =
        htons(port);

    if (
        bind(
            server,
            (struct sockaddr *)&address,
            sizeof(address)
        ) < 0
    ) {
        perror("bind");
        exit(1);
    }

    listen(server, 20);

    printf(
        "Tracker running on port %d\n",
        port
    );

    while (1) {

        struct sockaddr_in client_addr;

        socklen_t size =
            sizeof(client_addr);

        int client =
            accept(
                server,
                (struct sockaddr *)&client_addr,
                &size
            );

        if (client < 0)
            continue;

        int *fd =
            malloc(sizeof(int));

        *fd = client;

        pthread_t thread;

        pthread_create(
            &thread,
            NULL,
            tracker_client,
            fd
        );

        pthread_detach(thread);
    }
}


/* ---------------- PEER REGISTRATION ---------------- */

void register_peer()
{
    int fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    struct sockaddr_in server;

    memset(
        &server,
        0,
        sizeof(server)
    );

    server.sin_family =
        AF_INET;

    server.sin_port =
        htons(tracker_port);

    inet_pton(
        AF_INET,
        "127.0.0.1",
        &server.sin_addr
    );

    if (
        connect(
            fd,
            (struct sockaddr *)&server,
            sizeof(server)
        ) < 0
    ) {
        close(fd);
        return;
    }

    char message[512];

    sprintf(
        message,
        "REGISTER %s %d %s\n",
        peer_id,
        peer_port,
        info.filename
    );

    send_all(
        fd,
        message,
        strlen(message)
    );

    close(fd);
}


/* ---------------- GET PEERS ---------------- */

int get_peers(
    Peer *peers
)
{
    int fd =
        socket(
            AF_INET,
            SOCK_STREAM,
            0
        );

    struct sockaddr_in server;

    memset(
        &server,
        0,
        sizeof(server)
    );

    server.sin_family =
        AF_INET;

    server.sin_port =
        htons(tracker_port);

    inet_pton(
        AF_INET,
        "127.0.0.1",
        &server.sin_addr
    );

    if (
        connect(
            fd,
            (struct sockaddr *)&server,
            sizeof(server)
        ) < 0
    ) {
        close(fd);
        return 0;
    }

    char message[512];

    sprintf(
        message,
        "GET %s\n",
        info.filename
    );

    send_all(
        fd,
        message,
        strlen(message)
    );

    char buffer[4096];

    int n =
        recv(
            fd,
            buffer,
            sizeof(buffer) - 1,
            0
        );

    if (n <= 0) {
        close(fd);
        return 0;
    }

    buffer[n] = '\0';

    close(fd);

    int count = 0;

    char *line =
        strtok(
            buffer,
            "\n"
        );

    if (!line)
        return 0;

    int total =
        atoi(line);

    line =
        strtok(
            NULL,
            "\n"
        );

    while (
        line &&
        count < total
    ) {

        sscanf(
            line,
            "%31s %d",
            peers[count].id,
            &peers[count].port
        );

        count++;

        line =
            strtok(
                NULL,
                "\n"
            );
    }

    return count;
}


/* ---------------- MAIN ---------------- */

int main(int argc, char **argv)
{
    if (argc != 3 || strcmp(argv[1], "tracker") != 0) {

        printf(
            "Stage 1 - P2P Networking and Tracker\n\n"
            "Usage:\n"
            "./p2p tracker <port>\n"
        );

        return 0;
    }

    run_tracker(atoi(argv[2]));

    return 0;
}
