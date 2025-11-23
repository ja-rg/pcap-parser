#include <stdio.h>
#include <assert.h>
#include "ethernet.h"

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
    for (size_t i = 0; i < pcap->packet_count; i++)
    {
        pcap_packet_t *pkt = &pcap->packets[i];
        printf("Packet %zu:\n", i + 1);
        printf("  Timestamp: %s\n", pkt->timestamp_str);
        printf("  Included Length: %u\n", pkt->header.incl_len);
        printf("  Original Length: %u\n", pkt->header.orig_len);

        ethernet_header_t eth;
        assert(parse_ethernet_header(pkt->data, pkt->header.incl_len, &eth) && "Failed to parse Ethernet header");

        // Ahora puedes inspeccionar:
        switch (eth.frame_type)
        {
        case ETH_FRAME_ETHERNET_II:
            // eth.ethertype es válido: IPv4, ARP, IPv6, etc.
            break;

        case ETH_FRAME_VLAN:
            // eth.vlan_id / eth.ethertype
            printf("  VLAN Frame, VLAN ID: %u, Ethertype: 0x%04x\n", eth.vlan_id, eth.ethertype);
            break;

        case ETH_FRAME_8023_LLC:
            // no tienes ethertype, viene LLC/SNAP después del header
            printf("  802.3 LLC Frame\n");
            break;

        default:
            break;
        }

        /* const uint8_t *l3_data = packet_data + eth.header_length;
        size_t l3_len = packet_length - eth.header_length;

        // Ejemplo: parsear IPv4 si aplica
        if ((eth.frame_type == ETH_FRAME_ETHERNET_II || eth.frame_type == ETH_FRAME_VLAN) &&
            eth.ethertype == ETHERTYPE_IPV4 &&
            l3_len >= 20)
        {
            // Aquí podrías llamar a parse_ipv4_header(l3_data, l3_len, ...);
        } */
    }
    // Free allocated memory
    pcap_close(pcap);
    return 0;
}
