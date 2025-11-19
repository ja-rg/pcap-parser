#include <stdio.h>
#include "lib/pcap-master.h"


int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <file.pcap>\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    FILE *f = fopen(filename, "rb");
    if (!f)
    {
        perror("fopen");
        return 1;
    }

    pcap_global_header_t gh;
    size_t n = fread(&gh, sizeof(pcap_global_header_t), 1, f);
    if (n != 1)
    {
        fprintf(stderr, "Failed to read global header\n");
        fclose(f);
        return 1;
    }

    /* Detect file endianness based on magic number as read on this host */
    pcap_endian_t file_endian = PCAP_ENDIAN_UNKNOWN;
    if (gh.magic_number == PCAP_MAGIC_LE)
    {
        file_endian = PCAP_ENDIAN_FILE_LE;
    }
    else if (gh.magic_number == PCAP_MAGIC_BE)
    {
        file_endian = PCAP_ENDIAN_FILE_BE;
    }
    else
    {
        fprintf(stderr, "Unknown or unsupported PCAP magic number: 0x%08x\n",
                gh.magic_number);
        fclose(f);
        return 1;
    }

    int need_swap = 0;
    /* Assume host is little-endian (x86/x86_64). */
    if (file_endian == PCAP_ENDIAN_FILE_BE)
    {
        need_swap = 1;
    }

    if (need_swap)
    {
        gh.version_major = swap16(gh.version_major);
        gh.version_minor = swap16(gh.version_minor);
        gh.thiszone = (int32_t)swap32((uint32_t)gh.thiszone);
        gh.sigfigs = swap32(gh.sigfigs);
        gh.snaplen = swap32(gh.snaplen);
        gh.network = swap32(gh.network);
    }

    printf("PCAP Global Header:\n");
    printf("  Version:     %u.%u\n", gh.version_major, gh.version_minor);
    printf("  Thiszone:    %d\n", gh.thiszone);
    printf("  Sigfigs:     %u\n", gh.sigfigs);
    printf("  Snaplen:     %u\n", gh.snaplen);
    printf("  Network DLT: %u\n", gh.network);
    printf("\n");

    uint32_t packet_count = 0;
    while (1)
    {
        pcap_packet_header_t ph;

        /* Try to read the per-packet header */
        n = fread(&ph, sizeof(pcap_packet_header_t), 1, f);
        if (n != 1)
        {
            /* EOF is normal, partial read is error */
            if (feof(f))
            {
                printf("End of file reached.\n");
            }
            else
            {
                perror("fread packet header");
            }
            break;
        }

        if (need_swap)
        {
            ph.ts_sec = swap32(ph.ts_sec);
            ph.ts_usec = swap32(ph.ts_usec);
            ph.incl_len = swap32(ph.incl_len);
            ph.orig_len = swap32(ph.orig_len);
        }

        /* Basic sanity check */
        if (ph.incl_len > gh.snaplen || ph.incl_len > 10 * 1024 * 1024)
        {
            fprintf(stderr, "Suspicious incl_len (%u), aborting.\n", ph.incl_len);
            break;
        }

        /* Allocate buffer for packet data */
        uint8_t *data = (uint8_t *)malloc(ph.incl_len);
        if (!data && ph.incl_len > 0)
        {
            fprintf(stderr, "Memory allocation failed for packet of %u bytes\n",
                    ph.incl_len);
            break;
        }

        /* Read packet bytes */
        if (ph.incl_len > 0)
        {
            size_t read_bytes = fread(data, 1, ph.incl_len, f);
            if (read_bytes != ph.incl_len)
            {
                fprintf(stderr, "Failed to read packet data (expected %u, got %zu)\n",
                        ph.incl_len, read_bytes);
                free(data);
                break;
            }
        }

        packet_count++;

        printf("Packet #%u:\n", packet_count);
        printf("  Timestamp:   %u.%06u\n", ph.ts_sec, ph.ts_usec);
        printf("  Captured:    %u bytes\n", ph.incl_len);
        printf("  Original:    %u bytes\n", ph.orig_len);

        /* Example: if Ethernet, you could inspect first bytes */
        if (ph.incl_len >= 14)
        {
            printf("  First bytes: %02x %02x %02x %02x ...\n",
                   data[0], data[1], data[2], data[3]);
        }

        printf("\n");

        free(data);
    }

    printf("Total packets: %u\n", packet_count);

    fclose(f);
    return 0;
}
