#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/*
TODO: implement a dynamic list for interfaces, write
interfaces to the index file at the beginning as metadata
*/

typedef enum {
    ENDIAN_UNKNOWN,
    ENDIAN_LITTLE,
    ENDIAN_BIG,
} EndianType;

typedef enum {
    TIMESTAMP_UNKNOWN,
    TIMESTAMP_MICROSECONDS,
    TIMESTAMP_NANOSECONDS,
} TimestampFormat;

typedef enum {
    UNKNOWN,
    PCAP,
    PCAPNG,
} PcapType;

#define PCAPNG_EPB 0x00000006
#define PCAPNG_SPB 0x00000003
#define PCAPNG_SHB 0x0A0D0D0A
#define PCAPNG_IDB 0x00000001

#define OPT_ENDOFOPT 0
#define IF_TSRESOL_OPT 9

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

typedef struct {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t byteorder_magic;
    uint16_t version_major;
    uint16_t version_minor;
} PcapngSHB;

typedef struct {
    uint32_t block_type;
    uint32_t block_total_length;
    uint32_t interface_id;
    uint32_t timestamp_high;
    uint32_t timestamp_low;
} PcapngEPB;

typedef struct {
    uint32_t block_type;
    uint32_t block_total_length;
    uint16_t linktype;
    uint16_t reserved;
    uint32_t snaplen;
} PcapngIDB;

typedef struct {
    uint8_t resol;
    uint16_t linktype;
} Interface;

typedef struct {
    uint16_t option_code;
    uint16_t option_length;
} PcapngOptionHeader;

#pragma pack(pop)

typedef struct {
    uint64_t header_offset;
    uint64_t timestamp_ns; // 0xffffffffffffffff if unknown
} PacketRecord;

static const uint8_t MAGIC_LE_MS[4] = {
    0xd4, 0xc3, 0xb2, 0xa1}; /* microsecond, file written LE */
static const uint8_t MAGIC_BE_MS[4] = {
    0xa1, 0xb2, 0xc3, 0xd4}; /* microsecond, file written BE */
static const uint8_t MAGIC_LE_NS[4] = {
    0x4d, 0x3c, 0xb2, 0xa1}; /* nanosecond,  file written LE */
static const uint8_t MAGIC_BE_NS[4] = {
    0xa1, 0xb2, 0x3c, 0x4d}; /* nanosecond,  file written BE */
static const uint8_t MAGIC_PCAPNG[4] = {
    0x0a, 0x0d, 0x0d, 0x0a}; /* palindromic, order-independent */

static const uint8_t NG_BYTEORDER_MAGIC_BE[4] = {0x1a, 0x2b, 0x3c, 0x4d};
static const uint8_t NG_BYTEORDER_MAGIC_LE[4] = {0x4d, 0x3c, 0x2b, 0x1a};

PcapType get_type(const uint8_t magic_bytes[4], EndianType *endian,
    TimestampFormat *timestamp_format)
{
    if (memcmp(magic_bytes, MAGIC_LE_MS, 4) == 0) {
        *endian = ENDIAN_LITTLE;
        *timestamp_format = TIMESTAMP_MICROSECONDS;
        return PCAP;
    }
    if (memcmp(magic_bytes, MAGIC_BE_MS, 4) == 0) {
        *endian = ENDIAN_BIG;
        *timestamp_format = TIMESTAMP_MICROSECONDS;
        return PCAP;
    }
    if (memcmp(magic_bytes, MAGIC_LE_NS, 4) == 0) {
        *endian = ENDIAN_LITTLE;
        *timestamp_format = TIMESTAMP_NANOSECONDS;
        return PCAP;
    }
    if (memcmp(magic_bytes, MAGIC_BE_NS, 4) == 0) {
        *endian = ENDIAN_BIG;
        *timestamp_format = TIMESTAMP_NANOSECONDS;
        return PCAP;
    }
    if (memcmp(magic_bytes, MAGIC_PCAPNG, 4) == 0) {
        return PCAPNG;
    }
    return UNKNOWN;
}

bool host_is_little_endian()
{
    int num = 1;
    return (*(char *)&num == 1);
}

uint16_t swap16(uint16_t val) { return (val << 8) | (val >> 8); }

uint32_t swap32(uint32_t val)
{
    return (val << 24) | ((val & 0x0000ff00) << 8) | ((val & 0x00ff0000) >> 8) |
           (val >> 24);
}

static inline uint16_t rd16(uint16_t val, bool need_swap)
{
    return need_swap ? swap16(val) : val;
}

static inline uint32_t rd32(uint32_t val, bool need_swap)
{
    return need_swap ? swap32(val) : val;
}

/* ticks -> nanoseconds given an if_tsresol byte (bit7 set = power-of-2) */
static uint64_t ticks_to_ns(uint64_t ticks, uint8_t resol)
{
    if (resol & 0x80) {
        uint8_t shift = resol & 0x7F;
        return (ticks * 1000000000ULL) >> shift;
    }

    uint64_t denom = 1;
    for (uint8_t i = 0; i < resol; i++) {
        denom *= 10ULL;
    }
    if (denom == 0) {
        return 0xffffffffffffffffULL;
    }
    if (denom >= 1000000000ULL) {
        return ticks / (denom / 1000000000ULL);
    }
    return ticks * (1000000000ULL / denom);
}

static inline void record_packet(int outfd, PacketRecord *batch,
    size_t *batch_cnt, uint64_t timestamp_ns, uint64_t off)
{
    static size_t current_packet_num = 0;
    // printf("Packet %zu: offset=%lu, timestamp_ns=%lu\n",
    // current_packet_num++,
    //     off, timestamp_ns);

    batch[*batch_cnt].header_offset = off;
    batch[*batch_cnt].timestamp_ns = timestamp_ns;
    (*batch_cnt)++;

    if (*batch_cnt == BATCH_SIZE) {
        ssize_t written =
            write(outfd, batch, BATCH_SIZE * sizeof(PacketRecord));
        (void)written;
        *batch_cnt = 0;
    }
}

static uint8_t parse_idb_tsresol(
    const uint8_t *body, size_t body_len, bool need_swap)
{
    uint8_t resol = 6;
    size_t off = 0;

    while (off + sizeof(PcapngOptionHeader) <= body_len) {
        const PcapngOptionHeader *opt =
            (const PcapngOptionHeader *)(body + off);
        uint16_t code = rd16(opt->option_code, need_swap);
        uint16_t len = rd16(opt->option_length, need_swap);

        if (code == OPT_ENDOFOPT && len == 0) {
            break;
        }

        size_t padded = (len + 3u) & ~3u;
        if (off + sizeof(PcapngOptionHeader) + padded > body_len) {
            break;
        }

        if (code == IF_TSRESOL_OPT && len >= 1) {
            resol = body[off + sizeof(PcapngOptionHeader)];
        }

        off += sizeof(PcapngOptionHeader) + padded;
    }

    return resol;
}

// returning a fd to the output binary file for further processing
int index_pcap(const char *filename, const char *output_binary)
{
    int fd = open(filename, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open input file");
        return -1;
    }

    int outfd = open(output_binary, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (outfd < 0) {
        perror("Failed to open output binary file");
        close(fd);
        return -1;
    }

    struct stat sb;
    fstat(fd, &sb);
    size_t filesize = sb.st_size;
    if (filesize < sizeof(PcapGlobalHeader)) {
        close(fd);
        close(outfd);
        return -1;
    }

    uint8_t magic[4];
    if (read(fd, magic, sizeof(magic)) != sizeof(magic)) {
        close(fd);
        close(outfd);
        return -1;
    }

    bool host_le = host_is_little_endian();

    EndianType endian = ENDIAN_UNKNOWN;
    TimestampFormat timestamp_format = TIMESTAMP_UNKNOWN;
    PcapType type = get_type(magic, &endian, &timestamp_format);

    if (type == UNKNOWN) {
        fprintf(stderr, "Unknown format magic: 0x%X\n", *(uint32_t *)magic);
        close(fd);
        close(outfd);
        return -1;
    }

    bool need_swap = false;

    size_t file_position = type != PCAPNG ? sizeof(PcapGlobalHeader) : 0;
    lseek(fd, file_position, SEEK_SET);

    uint64_t current_packet_num = 0;
    size_t leftover_len = 0;
    uint8_t leftover_buf[MAX_TAIL_BYTES];

    PacketRecord batch[BATCH_SIZE];
    size_t batch_count = 0;

    Interface interfaces[128]; // temporarily 128
    size_t interface_count = 0;

    uint8_t *chunk_buf = aligned_alloc(ALIGNMENT, CHUNK_SIZE);
    if (chunk_buf == NULL) {
        fprintf(stderr, "Allocation failed.\n");
        close(fd);
        close(outfd);
        return -1;
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

        if (type != PCAPNG) {
            need_swap = (endian == ENDIAN_LITTLE) != host_le;
            while (local_offset + sizeof(PcapPacketHeader) <= total_buf_len) {
                const PcapPacketHeader *hdr =
                    (const PcapPacketHeader *)(chunk_buf + local_offset);
                uint32_t incl_len = rd32(hdr->incl_len, need_swap);
                size_t pkt_len = sizeof(PcapPacketHeader) + incl_len;

                if (local_offset + pkt_len > total_buf_len) {
                    break;
                }

                uint64_t timestamp_ns = 0xffffffffffffffff; // unknown timestamp

                uint32_t ts_sec = rd32(hdr->ts_sec, need_swap);
                uint32_t ts_usec = rd32(hdr->ts_usec, need_swap);

                if (timestamp_format == TIMESTAMP_MICROSECONDS) {
                    timestamp_ns = ((uint64_t)ts_sec * 1000000000ULL) +
                                   ((uint64_t)ts_usec * 1000ULL);
                }
                else if (timestamp_format == TIMESTAMP_NANOSECONDS) {
                    timestamp_ns =
                        ((uint64_t)ts_sec * 1000000000ULL) + (uint64_t)ts_usec;
                }

                record_packet(outfd, batch, &batch_count, timestamp_ns,
                    (file_position - leftover_len) + local_offset);

                local_offset += pkt_len;
            }
        }
        else {
            while (local_offset + sizeof(PcapngBlockHeader) <= total_buf_len) {
                const PcapngBlockHeader *blk =
                    (const PcapngBlockHeader *)(chunk_buf + local_offset);

                // shb block type is polindromic, so we can use it to detect
                // endianness
                if (blk->block_type == PCAPNG_SHB) {
                    if (local_offset + sizeof(PcapngSHB) > total_buf_len) {
                        break;
                    }

                    // pcapng files can have multiple shb blocks which can
                    // change endianness
                    const PcapngSHB *shb =
                        (const PcapngSHB *)(chunk_buf + local_offset);
                    if (memcmp(&shb->byteorder_magic, NG_BYTEORDER_MAGIC_LE,
                            4) == 0) {
                        endian = ENDIAN_LITTLE;
                    }
                    else if (memcmp(&shb->byteorder_magic,
                                 NG_BYTEORDER_MAGIC_BE, 4) == 0) {
                        endian = ENDIAN_BIG;
                    }
                    else {
                        fprintf(stderr,
                            "Unknown byte order magic in PCAPNG: 0x%X\n",
                            shb->byteorder_magic);
                        goto done_parsing;
                    }

                    need_swap = (endian == ENDIAN_LITTLE) != host_le;
                    uint32_t btl = rd32(shb->block_total_length, need_swap);
                    if (btl < sizeof(PcapngSHB) || btl % 4 != 0) {
                        break;
                    }

                    local_offset += btl;
                    continue;
                }

                uint32_t btl = rd32(blk->block_total_length, need_swap);
                if (btl < sizeof(PcapngBlockHeader) || btl % 4 != 0) {
                    break;
                }

                if (local_offset + btl > total_buf_len) {
                    break;
                }

                uint32_t block_type = rd32(blk->block_type, need_swap);
                uint64_t timestamp_ns = 0xffffffffffffffff; // unknown timestamp

                if (block_type == PCAPNG_IDB) {
                    const PcapngIDB *idb =
                        (const PcapngIDB *)(chunk_buf + local_offset);

                    if (interface_count >=
                        sizeof(interfaces) / sizeof(interfaces[0])) {
                        printf("Cannot fit more interfaces in the temporary "
                               "array. "
                               "Skipping.\n");
                    }
                    else {
                        const uint8_t *options_start =
                            chunk_buf + local_offset + sizeof(PcapngIDB);
                        size_t options_len =
                            btl - sizeof(PcapngIDB) - sizeof(uint32_t);
                        uint16_t linktype = rd16(idb->linktype, need_swap);
                        uint8_t tsresol = parse_idb_tsresol(
                            options_start, options_len, need_swap);
                        printf("Interface %zu: linktype=%u, tsresol=%u\n",
                            interface_count, linktype, tsresol);
                        interfaces[interface_count].resol = tsresol;
                        interfaces[interface_count].linktype = linktype;
                        interface_count++;
                    }
                }
                else if (block_type == PCAPNG_EPB) {
                    const PcapngEPB *epb =
                        (const PcapngEPB *)(chunk_buf + local_offset);

                    uint32_t interface_id = rd32(epb->interface_id, need_swap);
                    if (interface_id >= interface_count) {
                        printf("Invalid interface_id %u in EPB. Skipping.\n",
                            interface_id);
                        local_offset += btl;
                        continue;
                    }

                    uint64_t ts_high = rd32(epb->timestamp_high, need_swap);
                    uint64_t ts_low = rd32(epb->timestamp_low, need_swap);
                    uint64_t ticks = (ts_high << 32) | ts_low;

                    timestamp_ns =
                        ticks_to_ns(ticks, interfaces[interface_id].resol);

                    record_packet(outfd, batch, &batch_count, timestamp_ns,
                        (file_position - leftover_len) + local_offset);
                }
                else if (block_type == PCAPNG_SPB) {
                    // interface id is interface_count-1
                    record_packet(outfd, batch, &batch_count, timestamp_ns,
                        (file_position - leftover_len) + local_offset);
                }

                local_offset += btl;
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

done_parsing:
    if (batch_count > 0) {
        ssize_t written =
            write(outfd, batch, batch_count * sizeof(PacketRecord));
        (void)written;
    }

    free(chunk_buf);
    close(fd);

    printf(
        "Parsing complete. Total packets written: %lu\n", current_packet_num);

    return outfd;
}

int main(int argc, char **argv)
{
    if (argc < 2) {
        fprintf(
            stderr, "Usage: %s <path_to_pcap> [output_binary_path]\n", argv[0]);
        return 1;
    }

    const char *out_path = (argc >= 3) ? argv[2] : "index_output.bin";
    int outfd = index_pcap(argv[1], out_path);
    if (outfd < 0) {
        fprintf(stderr, "Failed to index pcap file.\n");
        return 1;
    }

    close(outfd);
    return 0;
}