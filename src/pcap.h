#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#ifndef PCAP_H
#define PCAP_H
#pragma pack(push, 1) // Ensure no padding in structures

/* Global PCAP header: 24 bytes */
typedef struct
{
    uint32_t magic_number;  /* magic number: They are used to detect the file format and endianness */
    uint16_t version_major; /* major version number: This number indicates the major version of the pcap file format */
    uint16_t version_minor; /* minor version number: This number indicates the minor version of the pcap file format */
    int32_t thiszone;       /* GMT to local correction: This field is used to adjust timestamps to the local timezone */
    uint32_t sigfigs;       /* accuracy of timestamps: This field indicates the accuracy of the timestamps in the capture */
    uint32_t snaplen;       /* max length of captured packets, in octets: This field specifies the maximum number of bytes captured from each packet */
    uint32_t network;       /* data link type: This field specifies the type of data link layer used in the capture (e.g., Ethernet, Wi-Fi) */
} pcap_global_header_t;

/* Per-packet header: 16 bytes */
typedef struct
{
    uint32_t ts_sec;   /* timestamp seconds */
    uint32_t ts_usec;  /* timestamp microseconds */
    uint32_t incl_len; /* number of octets of packet saved in file */
    uint32_t orig_len; /* actual length of packet */
} pcap_packet_header_t;

#pragma pack(pop)

/* Magic numbers (classic pcap, microsecond resolution) */
#define PCAP_MAGIC_LE 0xa1b2c3d4U /* file in little-endian */
#define PCAP_MAGIC_BE 0xd4c3b2a1U /* file in big-endian   */

typedef enum
{
    PCAP_ENDIAN_UNKNOWN = 0,
    PCAP_ENDIAN_FILE_LE,
    PCAP_ENDIAN_FILE_BE
} pcap_endian_t;

typedef struct
{
    pcap_packet_header_t header;
    uint8_t *data;
    char timestamp_str[84]; // Formatted timestamp string
} pcap_packet_t;

typedef struct
{
    pcap_global_header_t global_header;
    pcap_packet_t *packets;
    size_t packet_count;
    pcap_endian_t file_endianness;
} pcap_file_t;

// --- Promotion API types & prototypes ---

#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "http.h"

typedef enum
{
    LAYER_NONE = 0,
    LAYER_ETHERNET,
    LAYER_IPV4,
    LAYER_TCP,
    LAYER_HTTP
} packet_layer_t;

typedef struct
{
    bool has_ethernet;
    ethernet_header_t eth;
    bool has_ipv4;
    ipv4_header_t ip;
    bool has_tcp;
    tcp_header_t tcp;
    bool has_http;
    http_info_t http;
} pcap_packet_promoted_t;

// Promotion functions. Devuelven 0 en éxito, <0 en error (-1 argumentos inválidos, -2 truncado, -3 tipo inaplicable)
int pcap_packet_promote_to_ethernet(pcap_packet_t *pkt, ethernet_header_t *out);
int pcap_packet_promote_to_ipv4(pcap_packet_t *pkt, ipv4_header_t *out);
int pcap_packet_promote_to_tcp(pcap_packet_t *pkt, tcp_header_t *out);
int pcap_packet_promote_to_http(pcap_packet_t *pkt, http_info_t *out);

// Encadenador: promueve hasta max_layer (use packet_layer_t values). Rellena `out` si no es NULL.
int pcap_packet_promote_layers(pcap_packet_t *pkt, int max_layer, pcap_packet_promoted_t *out);

pcap_file_t *pcap_open(const char *filename);
void pcap_close(pcap_file_t *pcap);
#endif // PCAP_H