#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef enum {
    UNKNOWN,
    PCAP_FORMAT_LE_MS,
    PCAP_FORMAT_BE_MS,
    PCAP_FORMAT_LE_NS,
    PCAP_FORMAT_BE_NS,
    PCAPNG,
} PcapFormat;

#define PCAP_LE_MS_MAGIC 0xd4c3b2a1
#define PCAP_BE_MS_MAGIC 0xa1b2c3d4
#define PCAP_LE_NS_MAGIC 0x4d3cb2a1
#define PCAP_BE_NS_MAGIC 0xa1b23c4d
#define PCAPNG_MAGIC 0x0a0d0d0a

#define PCAPNG_EPB 0x00000006
#define PCAPNG_SPB 0x00000003

#define ALIGNMENT 4096
#define CHUNK_SIZE (128 * 1024 * 1024)
#define MAX_TAIL_BYTES (65536 + 64)
#define MAX_JOBS 4096

#define QUEUE_CAPACITY 32

#pragma pack(push, 1)

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} PcapGlobalHeader;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} PcapPacketHeader;

typedef struct {
    uint32_t block_type;
    uint32_t block_total_length;
} PcapngBlockHeader;

#pragma pack(pop)

typedef struct {
    pthread_mutex_t mtx;
    pthread_cond_t cond;
    bool ready;
    uint8_t leftover_buf[MAX_TAIL_BYTES];
    size_t leftover_len;
} HandoffSlot;

static HandoffSlot g_handoff_table[QUEUE_CAPACITY];

void handoff_table_init(void)
{
    for (int i = 0; i < QUEUE_CAPACITY; i++) {
        pthread_mutex_init(&g_handoff_table[i].mtx, NULL);
        pthread_cond_init(&g_handoff_table[i].cond, NULL);
        g_handoff_table[i].ready = false;
        g_handoff_table[i].leftover_len = 0;
    }
}

void handoff_table_destroy(void)
{
    for (int i = 0; i < QUEUE_CAPACITY; i++) {
        pthread_mutex_destroy(&g_handoff_table[i].mtx);
        pthread_cond_destroy(&g_handoff_table[i].cond);
    }
}

typedef struct ChunkJob {
    uint64_t job_id;
    PcapFormat format;
    uint8_t *buffer;
    size_t len;
    size_t global_base_offset;
} ChunkJob;

typedef struct {
    ChunkJob *jobs[QUEUE_CAPACITY];
    int head;
    int tail;
    int count;
    pthread_mutex_t mtx;
    pthread_cond_t cv_not_empty;
    pthread_cond_t cv_not_full;
    bool done;
} JobQueue;

void queue_init(JobQueue *q)
{
    q->head = 0;
    q->tail = 0;
    q->count = 0;
    q->done = false;
    pthread_mutex_init(&q->mtx, NULL);
    pthread_cond_init(&q->cv_not_empty, NULL);
    pthread_cond_init(&q->cv_not_full, NULL);
}

void queue_push(JobQueue *q, ChunkJob *job)
{
    pthread_mutex_lock(&q->mtx);
    while (q->count == QUEUE_CAPACITY) {
        pthread_cond_wait(&q->cv_not_full, &q->mtx);
    }
    q->jobs[q->tail] = job;
    q->tail = (q->tail + 1) % QUEUE_CAPACITY;
    q->count++;
    pthread_cond_signal(&q->cv_not_empty);
    pthread_mutex_unlock(&q->mtx);
}

bool queue_pop(JobQueue *q, ChunkJob **job)
{
    pthread_mutex_lock(&q->mtx);
    while (q->count == 0 && !q->done) {
        pthread_cond_wait(&q->cv_not_empty, &q->mtx);
    }
    if (q->count == 0 && q->done) {
        pthread_mutex_unlock(&q->mtx);
        return false;
    }
    *job = q->jobs[q->head];
    q->head = (q->head + 1) % QUEUE_CAPACITY;
    q->count--;
    pthread_cond_signal(&q->cv_not_full);
    pthread_mutex_unlock(&q->mtx);
    return true;
}

void queue_set_done(JobQueue *q)
{
    pthread_mutex_lock(&q->mtx);
    q->done = true;
    pthread_cond_broadcast(&q->cv_not_empty);
    pthread_mutex_unlock(&q->mtx);
}

void queue_destroy(JobQueue *q)
{
    pthread_mutex_destroy(&q->mtx);
    pthread_cond_destroy(&q->cv_not_empty);
    pthread_cond_destroy(&q->cv_not_full);
}

PcapFormat get_format(uint32_t magic)
{
    switch (magic) {
    case PCAP_LE_MS_MAGIC:
        return PCAP_FORMAT_LE_MS;
    case PCAP_BE_MS_MAGIC:
        return PCAP_FORMAT_BE_MS;
    case PCAP_LE_NS_MAGIC:
        return PCAP_FORMAT_LE_NS;
    case PCAP_BE_NS_MAGIC:
        return PCAP_FORMAT_BE_NS;
    case PCAPNG_MAGIC:
        return PCAPNG;
    default:
        return UNKNOWN;
    }
}

typedef struct {
    int id;
    JobQueue *job_queue;
} WorkerArgs;

void *worker_thread(void *arg)
{
    WorkerArgs *args = (WorkerArgs *)arg;
    ChunkJob *job = NULL;
    uint64_t processed_packets = 0;

    while (queue_pop(args->job_queue, &job)) {
        PcapFormat fmt = job->format;
        uint64_t id = job->job_id;
        size_t prev_leftover_len = 0;
        uint8_t prev_leftover[MAX_TAIL_BYTES];

        if (id > 0) {
            HandoffSlot *slot = &g_handoff_table[(id - 1) % QUEUE_CAPACITY];
            pthread_mutex_lock(&slot->mtx);
            while (!slot->ready) {
                pthread_cond_wait(&slot->cond, &slot->mtx);
            }
            prev_leftover_len = slot->leftover_len;
            if (prev_leftover_len > 0) {
                printf("restoring previous leftover bytes from job #%lu to job "
                       "#%lu\n",
                    id - 1, id);
                memcpy(prev_leftover, slot->leftover_buf, prev_leftover_len);
            }
            pthread_mutex_unlock(&slot->mtx);
        }

        // restore packet split from last chunk
        size_t chunk_read_offset = 0;
        if (prev_leftover_len > 0) {
            if (fmt != PCAPNG) {
                PcapPacketHeader hdr;
                size_t hdr_size = sizeof(PcapPacketHeader);

                if (prev_leftover_len >= hdr_size) {
                    memcpy(&hdr, prev_leftover, hdr_size);
                }
                else {
                    memcpy(&hdr, prev_leftover, prev_leftover_len);
                    memcpy((uint8_t *)&hdr + prev_leftover_len, job->buffer,
                        hdr_size - prev_leftover_len);
                }

                size_t total_pkt_len = hdr_size + hdr.incl_len;
                chunk_read_offset = total_pkt_len - prev_leftover_len;
                // process
                processed_packets++;
            }
            else {
                PcapngBlockHeader block;
                size_t hdr_size = sizeof(PcapngBlockHeader);

                if (prev_leftover_len >= hdr_size) {
                    memcpy(&block, prev_leftover, hdr_size);
                }
                else {
                    memcpy(&block, prev_leftover, prev_leftover_len);
                    memcpy((uint8_t *)&block + prev_leftover_len, job->buffer,
                        hdr_size - prev_leftover_len);
                }

                chunk_read_offset =
                    block.block_total_length - prev_leftover_len;
                if (block.block_type == PCAPNG_EPB ||
                    block.block_type == PCAPNG_SPB) {
                    // process
                    processed_packets++;
                }
            }
        }

        size_t local_offset = chunk_read_offset;

        if (fmt != PCAPNG) {
            while (local_offset < job->len) {
                if (local_offset + sizeof(PcapPacketHeader) > job->len)
                    break;

                const PcapPacketHeader *hdr =
                    (const PcapPacketHeader *)(job->buffer + local_offset);
                size_t pkt_len = sizeof(PcapPacketHeader) + hdr->incl_len;

                if (local_offset + pkt_len > job->len)
                    break;

                processed_packets++;
                local_offset += pkt_len;
            }
        }
        else {
            while (local_offset < job->len) {
                if (local_offset + sizeof(PcapngBlockHeader) > job->len)
                    break;

                const PcapngBlockHeader *block =
                    (const PcapngBlockHeader *)(job->buffer + local_offset);
                if (block->block_total_length < sizeof(PcapngBlockHeader) ||
                    block->block_total_length % 4 != 0)
                    break;
                if (local_offset + block->block_total_length > job->len)
                    break;

                if (block->block_type == PCAPNG_EPB ||
                    block->block_type == PCAPNG_SPB) {
                    processed_packets++;
                }

                local_offset += block->block_total_length;
            }
        }

        printf("processed packets: %lu\n", processed_packets);
        
        // handover leftover bytes for the next job
        size_t trailing_leftover = job->len - local_offset;
        HandoffSlot *my_slot = &g_handoff_table[id % QUEUE_CAPACITY];

        pthread_mutex_lock(&my_slot->mtx);
        if (trailing_leftover > 0) {
            printf("storing leftover bytes from job #%lu\n", id);
            memcpy(my_slot->leftover_buf, job->buffer + local_offset,
                trailing_leftover);
        }
        my_slot->leftover_len = trailing_leftover;
        my_slot->ready = true;
        pthread_cond_signal(&my_slot->cond);
        pthread_mutex_unlock(&my_slot->mtx);

        free(job->buffer);
        free(job);
    }

    printf("Worker Thread #%d finished. Packets counted: %lu\n", args->id,
        processed_packets);
    free(args);
    return NULL;
}

int parse_pcap(const char *filename, int cores)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file");
        return 1;
    }

    struct stat sb;
    fstat(fd, &sb);
    size_t filesize = sb.st_size;
    if (filesize < sizeof(PcapGlobalHeader)) {
        close(fd);
        return 1;
    }

    uint32_t magic;
    if (read(fd, &magic, sizeof(magic)) != sizeof(magic)) {
        close(fd);
        return 1;
    }
    PcapFormat format = get_format(magic);
    if (format == UNKNOWN) {
        fprintf(stderr, "Unknown format magic: 0x%X\n", magic);
        close(fd);
        return 1;
    }

    long num_cores = (cores == -1) ? sysconf(_SC_NPROCESSORS_ONLN) : cores;
    if (num_cores < 1)
        num_cores = 4;

    handoff_table_init();

    JobQueue *job_queue = malloc(sizeof(JobQueue));
    queue_init(job_queue);

    pthread_t *thread_pool = malloc(num_cores * sizeof(pthread_t));
    printf("Launching %ld worker threads...\n", num_cores);
    for (int i = 0; i < num_cores; ++i) {
        WorkerArgs *args = malloc(sizeof(WorkerArgs));
        args->id = i;
        args->job_queue = job_queue;
        pthread_create(&thread_pool[i], NULL, worker_thread, args);
    }

    size_t file_position = (format != PCAPNG) ? sizeof(PcapGlobalHeader) : 0;
    lseek(fd, file_position, SEEK_SET);

    uint64_t job_counter = 0;

    while (file_position < filesize) {
        uint8_t *chunk_buf = NULL;
        if (posix_memalign((void **)&chunk_buf, ALIGNMENT, CHUNK_SIZE) != 0) {
            fprintf(stderr, "Allocation failed.\n");
            break;
        }

        ssize_t bytes_read = read(fd, chunk_buf, CHUNK_SIZE);
        if (bytes_read <= 0) {
            free(chunk_buf);
            break;
        }

        printf("pushing job #%lu\n", job_counter);
        ChunkJob *job = malloc(sizeof(ChunkJob));
        assert(job != NULL);
        job->job_id = job_counter++;
        job->format = format;
        job->buffer = chunk_buf;
        job->len = (size_t)bytes_read;
        job->global_base_offset = file_position;
        queue_push(job_queue, job);

        file_position += (size_t)bytes_read;
    }

    queue_set_done(job_queue);

    for (int i = 0; i < num_cores; ++i) {
        pthread_join(thread_pool[i], NULL);
    }

    printf("All streaming jobs complete cleanly.\n");

    free(thread_pool);
    queue_destroy(job_queue);
    free(job_queue);
    handoff_table_destroy();
    close(fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <path_to_pcap>\n", argv[0]);
        return 1;
    }

    return parse_pcap(argv[1], -1);
}