#include "ip.h"
#include <string.h>

static uint16_t be16_read(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

bool parse_ipv4_header(const uint8_t *data, size_t len, ipv4_header_t *out)
{
    if (!data || !out || len < 20)
        return false;

    uint8_t ver_ihl = data[0];
    uint8_t version = ver_ihl >> 4;
    uint8_t ihl = ver_ihl & 0x0F;
    if (version != 4) return false;
    size_t header_len = (size_t)ihl * 4;
    if (header_len < 20 || len < header_len) return false;

    ipv4_header_t h;
    memset(&h, 0, sizeof(h));
    h.version = version;
    h.ihl = ihl;
    h.total_length = be16_read(data + 2);
    h.protocol = data[9];
    // src/dst
    h.src_addr = (uint32_t)((data[12] << 24) | (data[13] << 16) | (data[14] << 8) | data[15]);
    h.dst_addr = (uint32_t)((data[16] << 24) | (data[17] << 16) | (data[18] << 8) | data[19]);
    h.header_length = header_len;

    // payload
    if (h.total_length < header_len) return false;
    size_t payload_len = (size_t)h.total_length - header_len;
    if (len < header_len + payload_len) payload_len = len - header_len; // available bytes
    h.payload = data + header_len;
    h.payload_len = payload_len;

    *out = h;
    return true;
}
