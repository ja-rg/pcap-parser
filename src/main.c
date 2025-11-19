#include <stdio.h>
#include "pcap.h"

int main(int argc, char *argv[])
{
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    pcap_file_t *pcap = pcap_open(argv[1]);

    if (!pcap)
    {
        fprintf(stderr, "Failed to open PCAP file\n");
        return 1;
    }

    printf("PCAP Global Header:\n");
    printf("  Magic Number: 0x%08x\n", pcap->global_header.magic_number);
    printf("  Version: %d.%d\n", pcap->global_header.version_major, pcap->global_header.version_minor);
    printf("  Thiszone: %d\n", pcap->global_header.thiszone);
    printf("  Sigfigs: %u\n", pcap->global_header.sigfigs);
    printf("  Snaplen: %u\n", pcap->global_header.snaplen);
    printf("  Network: %u\n", pcap->global_header.network);
    printf("Total Packets: %zu\n", pcap->packet_count);
    return 0;
}
