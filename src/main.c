#include <stdio.h>
#include <assert.h>
#include <string.h>
#include "pcap.h"
#include <inttypes.h>

int main(int argc, char *argv[])
{
    if (argc < 2 || argc > 3)
    {
        fprintf(stderr, "Usage: %s <pcap_file> [ethernet|ipv4|tcp|http]\n", argv[0]);
        return 1;
    }

    const char *filename = argv[1];
    int max_layer = LAYER_HTTP; // default
    if (argc == 3)
    {
        if (strcmp(argv[2], "ethernet") == 0)
            max_layer = LAYER_ETHERNET;
        else if (strcmp(argv[2], "ipv4") == 0)
            max_layer = LAYER_IPV4;
        else if (strcmp(argv[2], "tcp") == 0)
            max_layer = LAYER_TCP;
        else if (strcmp(argv[2], "http") == 0)
            max_layer = LAYER_HTTP;
        else
        {
            fprintf(stderr, "Unknown layer '%s'\n", argv[2]);
            return 1;
        }
    }

    pcap_file_t *pcap = pcap_open(filename);

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
    for (size_t i = 0; i < pcap->packet_count; i++)
    {
        pcap_packet_t *pkt = &pcap->packets[i];
        printf("Packet %zu:\n", i + 1);
        printf("  Timestamp: %s\n", pkt->timestamp_str);
        printf("  Included Length: %u\n", pkt->header.incl_len);
        printf("  Original Length: %u\n", pkt->header.orig_len);
        pcap_packet_promoted_t prom = {0};
        int reached = pcap_packet_promote_layers(pkt, max_layer, &prom);
        printf("  Promotion reached layer: %d\n", reached);
        if (prom.has_ethernet)
        {
            char src_mac[18], dst_mac[18];
            mac_to_string(src_mac, prom.eth.src_mac);
            mac_to_string(dst_mac, prom.eth.dest_mac);
            printf("  Ethernet: %s -> %s, ethertype=0x%04x\n", src_mac, dst_mac, prom.eth.ethertype);
        }
        if (prom.has_ipv4)
        {
            uint32_t s = prom.ip.src_addr;
            uint32_t d = prom.ip.dst_addr;
            printf("  IPv4: %u.%u.%u.%u -> %u.%u.%u.%u, proto=%u\n",
                   (unsigned)((s >> 24) & 0xFF), (unsigned)((s >> 16) & 0xFF), (unsigned)((s >> 8) & 0xFF), (unsigned)(s & 0xFF),
                   (unsigned)((d >> 24) & 0xFF), (unsigned)((d >> 16) & 0xFF), (unsigned)((d >> 8) & 0xFF), (unsigned)(d & 0xFF),
                   prom.ip.protocol);
        }
        if (prom.has_tcp)
        {
            printf("  TCP: %u -> %u, payload_len=%zu\n", prom.tcp.src_port, prom.tcp.dst_port, prom.tcp.payload_len);
        }
        if (prom.has_http)
        {
            if (prom.http.type == HTTP_REQUEST)
            {
                printf("  HTTP Request: method=");
                for (size_t m = 0; m < prom.http.method_len; m++)
                    putchar(prom.http.method[m]);
                putchar('\n');
                const char *cats[] = {"UNKNOWN", "DOCUMENT", "FILE", "IMAGE", "VIDEO"};
                printf("    Inferred category: %s\n", cats[prom.http.content_category]);
            }
            else if (prom.http.type == HTTP_RESPONSE)
            {
                printf("  HTTP Response: status=%d\n", prom.http.status_code);
                if (prom.http.content_type && prom.http.content_type_len > 0)
                {
                    printf("    Content-Type: %.*s\n", (int)prom.http.content_type_len, (const char *)prom.http.content_type);
                }
                const char *cats[] = {"UNKNOWN", "DOCUMENT", "FILE", "IMAGE", "VIDEO"};
                printf("    Category: %s\n", cats[prom.http.content_category]);
            }
        }
    }
    // Free allocated memory
    pcap_close(pcap);
    return 0;
}
