#include "pcap.h"
#include <stdio.h>
#include <string.h>

static uint16_t swap16(uint16_t x)
{
    return (uint16_t)((x >> 8) | (x << 8));
}

static uint32_t swap32(uint32_t x)
{
    return ((x & 0x000000FFU) << 24) |
           ((x & 0x0000FF00U) << 8) |
           ((x & 0x00FF0000U) >> 8) |
           ((x & 0xFF000000U) >> 24);
}

static pcap_endian_t detect_pcap_endianness(uint32_t magic_number)
{
    if (magic_number == PCAP_MAGIC_LE)
    {
        return PCAP_ENDIAN_FILE_LE;
    }
    else if (magic_number == PCAP_MAGIC_BE)
    {
        return PCAP_ENDIAN_FILE_BE;
    }
    else
    {
        return PCAP_ENDIAN_UNKNOWN;
    }
}

static void swap_pcap_global_header(pcap_global_header_t* gh)
{
    gh->version_major = swap16(gh->version_major);
    gh->version_minor = swap16(gh->version_minor);
    gh->thiszone = (int32_t)swap32((uint32_t)gh->thiszone);
    gh->sigfigs = swap32(gh->sigfigs);
    gh->snaplen = swap32(gh->snaplen);
    gh->network = swap32(gh->network);
}

static void swap_pcap_packet_header(pcap_packet_header_t* ph)
{
    ph->ts_sec = swap32(ph->ts_sec);
    ph->ts_usec = swap32(ph->ts_usec);
    ph->incl_len = swap32(ph->incl_len);
    ph->orig_len = swap32(ph->orig_len);
}

// timestamp conversion to (YYYY-MM-DD HH:MM:SS.MICROSECONDS)
#include <time.h>
#include <inttypes.h>
static void format_timestamp(uint32_t ts_sec, uint32_t ts_usec, char* buffer, size_t buflen)
{
    time_t rawtime = (time_t)ts_sec;
    struct tm* timeinfo = gmtime(&rawtime);
    snprintf(buffer, buflen, "%04d-%02d-%02d %02d:%02d:%02d.%06" PRIu32,
             timeinfo->tm_year + 1900,
             timeinfo->tm_mon + 1,
             timeinfo->tm_mday,
             timeinfo->tm_hour,
             timeinfo->tm_min,
             timeinfo->tm_sec,
             ts_usec);
}


pcap_file_t* pcap_open(const char* filename)
{
    // Filename sanity check
    if (!filename)
    {
        fprintf(stderr, "Invalid filename\n");
        return NULL;
    }
    // Filename sanity check for buffer overflow
    if (strlen(filename) > 255)
    {
        fprintf(stderr, "Filename too long\n");
        return NULL;
    }

    FILE* f = fopen(filename, "rb");
    if (!f)
    {
        perror("fopen");
        return NULL;
    }
    pcap_global_header_t gh;
    size_t n = fread(&gh, sizeof(pcap_global_header_t), 1, f);
    if (n != 1)
    {
        fprintf(stderr, "Failed to read global header\n");
        fclose(f);
        return NULL;
    }
    pcap_endian_t file_endian = detect_pcap_endianness(gh.magic_number);
    if (file_endian == PCAP_ENDIAN_UNKNOWN)
    {
        fprintf(stderr, "Unknown or unsupported PCAP magic number: 0x%08x\n",
                gh.magic_number);
        fclose(f);
        return NULL;
    }

    int need_swap = file_endian == PCAP_ENDIAN_FILE_BE;
    if (need_swap)
    {
        swap_pcap_global_header(&gh);
    }

    pcap_file_t* pcap = (pcap_file_t*)malloc(sizeof(pcap_file_t));
    if (!pcap)
    {
        fprintf(stderr, "Memory allocation failed for pcap_file_t\n");
        fclose(f);
        return NULL;
    }
    
    pcap->global_header = gh;
    pcap->file_endianness = file_endian;
    pcap->packets = NULL;
    pcap->packet_count = 0;

    size_t capacity = 1024;
    pcap->packets = (pcap_packet_t*)malloc(capacity * sizeof(pcap_packet_t));
    if (!pcap->packets)
    {
        fprintf(stderr, "Memory allocation failed for packets\n");
        free(pcap);
        fclose(f);
        return NULL;
    }

    while (1)
    {
        pcap_packet_header_t ph;
        n = fread(&ph, sizeof(pcap_packet_header_t), 1, f);
        if (n != 1)
        {
            break; // End of file or read error
        }
        if (need_swap)
        {
            swap_pcap_packet_header(&ph);
        }
        if (pcap->packet_count >= capacity)
        {
            capacity *= 2;
            pcap_packet_t* new_packets = (pcap_packet_t*)realloc(pcap->packets, capacity * sizeof(pcap_packet_t));
            if (!new_packets)
            {
                fprintf(stderr, "Memory reallocation failed for packets\n");
                break;
            }
            pcap->packets = new_packets;
        }
        pcap_packet_t* pkt = &pcap->packets[pcap->packet_count];
        pkt->header = ph;
        format_timestamp(ph.ts_sec, ph.ts_usec, pkt->timestamp_str, sizeof(pkt->timestamp_str));
        pkt->data = (uint8_t*)malloc(ph.incl_len);
        if (!pkt->data && ph.incl_len > 0)
        {
            fprintf(stderr, "Memory allocation failed for packet data\n");
            break;
        }
        size_t read_bytes = fread(pkt->data, 1, ph.incl_len, f);
        if (read_bytes != ph.incl_len)
        {
            fprintf(stderr, "Failed to read packet data\n");
            free(pkt->data);
            break;
        }
        pcap->packet_count++;
    }

    fclose(f);
    return pcap;
}

void pcap_close(pcap_file_t* pcap)
{
    if (!pcap)
    {
        return;
    }
    for (size_t i = 0; i < pcap->packet_count; i++)
    {
        free(pcap->packets[i].data);
    }
    free(pcap->packets);
    free(pcap);
}

// --- Promotion functions ---
#include "pcap.h"

int pcap_packet_promote_to_ethernet(pcap_packet_t *pkt, ethernet_header_t *out)
{
    if (!pkt || !pkt->data || !out) return -1;
    if (!parse_ethernet_header(pkt->data, pkt->header.incl_len, out)) return -2;
    return 0;
}

int pcap_packet_promote_to_ipv4(pcap_packet_t *pkt, ipv4_header_t *out)
{
    if (!pkt || !pkt->data || !out) return -1;
    ethernet_header_t eth;
    int r = pcap_packet_promote_to_ethernet(pkt, &eth);
    if (r != 0) return r;
    if (!(eth.frame_type == ETH_FRAME_ETHERNET_II || eth.frame_type == ETH_FRAME_VLAN)) return -3;
    if (eth.ethertype != ETHERTYPE_IPV4) return -3;
    const uint8_t *l3 = (const uint8_t *)eth.siguiente_capa;
    size_t l3_len = 0;
    if (pkt->header.incl_len < eth.header_length) return -2;
    l3_len = pkt->header.incl_len - eth.header_length;
    if (!parse_ipv4_header(l3, l3_len, out)) return -2;
    return 0;
}

int pcap_packet_promote_to_tcp(pcap_packet_t *pkt, tcp_header_t *out)
{
    if (!pkt || !pkt->data || !out) return -1;
    ipv4_header_t ip;
    int r = pcap_packet_promote_to_ipv4(pkt, &ip);
    if (r != 0) return r;
    if (ip.protocol != 6) return -3; // Not TCP
    if (!parse_tcp_header(ip.payload, ip.payload_len, out)) return -2;
    return 0;
}

int pcap_packet_promote_to_http(pcap_packet_t *pkt, http_info_t *out)
{
    if (!pkt || !pkt->data || !out) return -1;
    tcp_header_t tcp;
    int r = pcap_packet_promote_to_tcp(pkt, &tcp);
    if (r != 0) return r;
    if (tcp.payload_len == 0) return -3;
    if (!parse_http_payload(tcp.payload, tcp.payload_len, out)) return -2;
    return 0;
}

int pcap_packet_promote_layers(pcap_packet_t *pkt, int max_layer, pcap_packet_promoted_t *out)
{
    if (!pkt || !pkt->data) return -1;
    int achieved = LAYER_NONE;
    if (max_layer >= LAYER_ETHERNET)
    {
        ethernet_header_t eth;
        if (pcap_packet_promote_to_ethernet(pkt, &eth) == 0)
        {
            achieved = LAYER_ETHERNET;
            if (out) { out->has_ethernet = true; out->eth = eth; }
        }
        else return -2;
    }
    if (max_layer >= LAYER_IPV4 && achieved >= LAYER_ETHERNET)
    {
        ipv4_header_t ip;
        if (pcap_packet_promote_to_ipv4(pkt, &ip) == 0)
        {
            achieved = LAYER_IPV4;
            if (out) { out->has_ipv4 = true; out->ip = ip; }
        }
        else return achieved; // return highest reached
    }
    if (max_layer >= LAYER_TCP && achieved >= LAYER_IPV4)
    {
        tcp_header_t tcp;
        if (pcap_packet_promote_to_tcp(pkt, &tcp) == 0)
        {
            achieved = LAYER_TCP;
            if (out) { out->has_tcp = true; out->tcp = tcp; }
        }
        else return achieved;
    }
    if (max_layer >= LAYER_HTTP && achieved >= LAYER_TCP)
    {
        http_info_t http;
        if (pcap_packet_promote_to_http(pkt, &http) == 0)
        {
            achieved = LAYER_HTTP;
            if (out) { out->has_http = true; out->http = http; }
        }
        else return achieved;
    }
    return achieved;
}