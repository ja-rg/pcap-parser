#include <stdint.h>
#include <stdlib.h>

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

/* Endianness handling */

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

/* Magic numbers (classic pcap, microsecond resolution) */
#define PCAP_MAGIC_LE 0xa1b2c3d4U /* file in little-endian */
#define PCAP_MAGIC_BE 0xd4c3b2a1U /* file in big-endian   */

typedef enum
{
    PCAP_ENDIAN_UNKNOWN = 0,
    PCAP_ENDIAN_FILE_LE,
    PCAP_ENDIAN_FILE_BE
} pcap_endian_t;

// Function to detect PCAP file endianness based on magic number
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
// End of lib/pcap-master.h