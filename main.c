#include <fcntl.h>
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
#define BATCH_SIZE 4096

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

static inline void record_packet(int out_fd, PacketRecord *batch,
    size_t *batch_cnt, uint64_t pkt, uint64_t off)
{
    batch[*batch_cnt].packet_number = pkt;
    batch[*batch_cnt].header_offset = off;
    (*batch_cnt)++;

    if (*batch_cnt == BATCH_SIZE) {
        ssize_t written =
            write(out_fd, batch, BATCH_SIZE * sizeof(PacketRecord));
        (void)written;
        *batch_cnt = 0;
    }
}

int parse_pcap(const char *filename, const char *output_binary)
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

    size_t file_position = (format != PCAPNG) ? sizeof(PcapGlobalHeader) : 0;
    lseek(fd, file_position, SEEK_SET);

    uint64_t current_packet_num = 1;
    size_t leftover_len = 0;
    uint8_t leftover_buf[MAX_TAIL_BYTES];

    PacketRecord batch[BATCH_SIZE];
    size_t batch_count = 0;

    uint8_t *chunk_buf = aligned_alloc(ALIGNMENT, CHUNK_SIZE);
    if (chunk_buf == NULL) {
        fprintf(stderr, "Allocation failed.\n");
        close(fd);
        close(out_fd);
        return 1;
    }

    while (file_position < filesize || leftover_len > 0) {
        if (leftover_len > 0) {
            memcpy(chunk_buf, leftover_buf, leftover_len);
        }

        size_t space_remaining = CHUNK_SIZE - leftover_len;
        ssize_t bytes_read =
            read(fd, chunk_buf + leftover_len, space_remaining);
        if (bytes_read < 0) {
            perror("Error reading file");
            break;
        }

        size_t total_buf_len = leftover_len + (size_t)bytes_read;
        if (total_buf_len == 0) {
            break;
        }

        size_t local_offset = 0;

        if (format != PCAPNG) {
            while (local_offset + sizeof(PcapPacketHeader) <= total_buf_len) {
                const PcapPacketHeader *hdr =
                    (const PcapPacketHeader *)(chunk_buf + local_offset);
                size_t pkt_len = sizeof(PcapPacketHeader) + hdr->incl_len;

                if (local_offset + pkt_len > total_buf_len) {
                    break;
                }

                uint64_t global_offset =
                    (file_position - leftover_len) + local_offset;
                record_packet(out_fd, batch, &batch_count, current_packet_num++,
                    global_offset);

                local_offset += pkt_len;
            }
        }
        else {
            while (local_offset + sizeof(PcapngBlockHeader) <= total_buf_len) {
                const PcapngBlockHeader *blk =
                    (const PcapngBlockHeader *)(chunk_buf + local_offset);
                if (blk->block_total_length < sizeof(PcapngBlockHeader) ||
                    blk->block_total_length % 4 != 0) {
                    break;
                }
                if (local_offset + blk->block_total_length > total_buf_len) {
                    break;
                }

                if (blk->block_type == PCAPNG_EPB ||
                    blk->block_type == PCAPNG_SPB) {
                    uint64_t global_offset =
                        (file_position - leftover_len) + local_offset;
                    record_packet(out_fd, batch, &batch_count,
                        current_packet_num++, global_offset);
                }

                local_offset += blk->block_total_length;
            }
        }

        if (bytes_read == 0) {
            local_offset = total_buf_len;
        }

        leftover_len = total_buf_len - local_offset;
        if (leftover_len > 0) {
            memcpy(leftover_buf, chunk_buf + local_offset, leftover_len);
        }

        file_position += bytes_read;
    }

    if (batch_count > 0) {
        ssize_t written =
            write(out_fd, batch, batch_count * sizeof(PacketRecord));
        (void)written;
    }

    free(chunk_buf);
    close(fd);
    close(out_fd);

    printf("Parsing complete. Total packets written: %lu\n",
        current_packet_num - 1);
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
    return parse_pcap(argv[1], out_path);
}