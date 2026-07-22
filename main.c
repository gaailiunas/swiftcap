#include <assert.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdatomic.h>
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
    uint64_t packet_number;
    uint64_t header_offset;
} PacketRecord;

#define WRITER_QUEUE_CAPACITY (1024 * 1024)
#define WRITER_BATCH_SIZE 4096

typedef struct {
    PacketRecord ring[WRITER_QUEUE_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    pthread_mutex_t mtx;
    pthread_cond_t cv_not_empty;
    pthread_cond_t cv_not_full;
    bool done;
    int fd;
} AsyncWriter;

static AsyncWriter g_writer;

void async_writer_init(AsyncWriter *w, int output_fd)
{
    w->head = 0;
    w->tail = 0;
    w->count = 0;
    w->done = false;
    w->fd = output_fd;
    pthread_mutex_init(&w->mtx, NULL);
    pthread_cond_init(&w->cv_not_empty, NULL);
    pthread_cond_init(&w->cv_not_full, NULL);
}

void async_writer_destroy(AsyncWriter *w)
{
    pthread_mutex_destroy(&w->mtx);
    pthread_cond_destroy(&w->cv_not_empty);
    pthread_cond_destroy(&w->cv_not_full);
}

void async_writer_push_batch(
    AsyncWriter *w, const PacketRecord *records, size_t num_records)
{
    if (num_records == 0)
        return;

    pthread_mutex_lock(&w->mtx);
    while (w->count + num_records > WRITER_QUEUE_CAPACITY) {
        pthread_cond_wait(&w->cv_not_full, &w->mtx);
    }

    for (size_t i = 0; i < num_records; i++) {
        w->ring[w->tail] = records[i];
        w->tail = (w->tail + 1) % WRITER_QUEUE_CAPACITY;
    }
    w->count += num_records;

    pthread_cond_signal(&w->cv_not_empty);
    pthread_mutex_unlock(&w->mtx);
}

void async_writer_set_done(AsyncWriter *w)
{
    pthread_mutex_lock(&w->mtx);
    w->done = true;
    pthread_cond_broadcast(&w->cv_not_empty);
    pthread_mutex_unlock(&w->mtx);
}

void *writer_worker(void *arg)
{
    AsyncWriter *w = (AsyncWriter *)arg;
    PacketRecord local_batch[WRITER_BATCH_SIZE];
    size_t batch_count = 0;

    while (true) {
        pthread_mutex_lock(&w->mtx);

        while (w->count == 0 && !w->done) {
            pthread_cond_wait(&w->cv_not_empty, &w->mtx);
        }

        if (w->count == 0 && w->done) {
            pthread_mutex_unlock(&w->mtx);
            break;
        }

        while (w->count > 0 && batch_count < WRITER_BATCH_SIZE) {
            local_batch[batch_count++] = w->ring[w->head];
            w->head = (w->head + 1) % WRITER_QUEUE_CAPACITY;
            w->count--;
        }

        pthread_cond_signal(&w->cv_not_full);
        pthread_mutex_unlock(&w->mtx);

        if (batch_count > 0) {
            ssize_t written =
                write(w->fd, local_batch, batch_count * sizeof(PacketRecord));
            (void)written;
            batch_count = 0;
        }
    }

    return NULL;
}

typedef struct {
    pthread_mutex_t mtx;
    pthread_cond_t cond;
    bool ready;
    uint8_t leftover_buf[MAX_TAIL_BYTES];
    size_t leftover_len;
} HandoffSlot;

static atomic_uint_fast64_t g_total_packets = 0;
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

static inline void record_packet(AsyncWriter *w, PacketRecord *batch,
    size_t *batch_cnt, uint64_t pkt, uint64_t off)
{
    batch[*batch_cnt].packet_number = pkt;
    batch[*batch_cnt].header_offset = off;
    (*batch_cnt)++;

    if (*batch_cnt == WRITER_BATCH_SIZE) {
        async_writer_push_batch(w, batch, *batch_cnt);
        *batch_cnt = 0;
    }
}

void *worker_thread(void *arg)
{
    WorkerArgs *args = (WorkerArgs *)arg;
    ChunkJob *job = NULL;
    uint64_t processed_packets = 0;

    PacketRecord local_writer_batch[WRITER_BATCH_SIZE];
    size_t local_writer_count = 0;

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
                memcpy(prev_leftover, slot->leftover_buf, prev_leftover_len);
            }
            slot->ready = false;
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
                    size_t needed = hdr_size - prev_leftover_len;
                    if (job->len < needed) {
                        break;
                    }
                    memcpy(&hdr, prev_leftover, prev_leftover_len);
                    memcpy((uint8_t *)&hdr + prev_leftover_len, job->buffer,
                        hdr_size - prev_leftover_len);
                }

                size_t total_pkt_len = hdr_size + hdr.incl_len;
                if (total_pkt_len >= prev_leftover_len) {
                    chunk_read_offset = total_pkt_len - prev_leftover_len;
                    if (chunk_read_offset > job->len) {
                        chunk_read_offset = job->len;
                    }
                    processed_packets++;
                    uint64_t global_hdr_offset =
                        job->global_base_offset - prev_leftover_len;

                    record_packet(&g_writer, local_writer_batch,
                        &local_writer_count, processed_packets,
                        global_hdr_offset);
                }
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
                    processed_packets++;
                    uint64_t global_hdr_offset =
                        job->global_base_offset - prev_leftover_len;

                    record_packet(&g_writer, local_writer_batch,
                        &local_writer_count, processed_packets,
                        global_hdr_offset);
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
                uint64_t global_hdr_offset =
                    job->global_base_offset + local_offset;

                record_packet(&g_writer, local_writer_batch,
                    &local_writer_count, processed_packets, global_hdr_offset);

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
                    uint64_t global_hdr_offset =
                        job->global_base_offset + local_offset;

                    record_packet(&g_writer, local_writer_batch,
                        &local_writer_count, processed_packets,
                        global_hdr_offset);
                }

                local_offset += block->block_total_length;
            }
        }

        // handover leftover bytes for the next job
        size_t trailing_leftover = job->len - local_offset;
        HandoffSlot *my_slot = &g_handoff_table[id % QUEUE_CAPACITY];

        pthread_mutex_lock(&my_slot->mtx);
        if (trailing_leftover > 0) {
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

    if (local_writer_count > 0) {
        async_writer_push_batch(
            &g_writer, local_writer_batch, local_writer_count);
    }

    atomic_fetch_add_explicit(
        &g_total_packets, processed_packets, memory_order_relaxed);
    printf("Worker Thread #%d finished. Packets counted: %lu\n", args->id,
        processed_packets);
    free(args);
    return NULL;
}

int parse_pcap(const char *filename, const char *output_binary, int cores)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open input file");
        return 1;
    }

    int out_fd = open(output_binary, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0) {
        perror("Failed to open output binary file");
        close(fd);
        return 1;
    }

    struct stat sb;
    fstat(fd, &sb);
    size_t filesize = sb.st_size;
    if (filesize < sizeof(PcapGlobalHeader)) {
        close(fd);
        close(out_fd);
        return 1;
    }

    uint32_t magic;
    if (read(fd, &magic, sizeof(magic)) != sizeof(magic)) {
        close(fd);
        close(out_fd);
        return 1;
    }
    PcapFormat format = get_format(magic);
    if (format == UNKNOWN) {
        fprintf(stderr, "Unknown format magic: 0x%X\n", magic);
        close(fd);
        close(out_fd);
        return 1;
    }

    long num_cores = (cores == -1) ? sysconf(_SC_NPROCESSORS_ONLN) : cores;
    if (num_cores < 1)
        num_cores = 4;

    handoff_table_init();
    async_writer_init(&g_writer, out_fd);

    pthread_t writer_thread;
    pthread_create(&writer_thread, NULL, writer_worker, &g_writer);

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
        uint8_t *chunk_buf = aligned_alloc(ALIGNMENT, CHUNK_SIZE);
        if (chunk_buf == NULL) {
            fprintf(stderr, "Allocation failed.\n");
            break;
        }

        ssize_t bytes_read = read(fd, chunk_buf, CHUNK_SIZE);
        if (bytes_read <= 0) {
            free(chunk_buf);
            break;
        }

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

    async_writer_set_done(&g_writer);
    pthread_join(writer_thread, NULL);

    printf("All streaming jobs complete cleanly.\n");
    printf("Total packets processed and written: %lu\n",
        atomic_load(&g_total_packets));

    free(thread_pool);
    queue_destroy(job_queue);
    free(job_queue);
    handoff_table_destroy();
    async_writer_destroy(&g_writer);
    close(fd);
    close(out_fd);
    return 0;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(
            stderr, "Usage: %s <path_to_pcap> [output_binary_path]\n", argv[0]);
        return 1;
    }

    const char *out_path = (argc >= 3) ? argv[2] : "index_output.bin";
    return parse_pcap(argv[1], out_path, -1);
}