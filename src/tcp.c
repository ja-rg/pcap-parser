#include "tcp.h"
#include <string.h>

static uint16_t be16_read(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t be32_read(const uint8_t *p)
{
    return (uint32_t)((p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]);
}

bool parse_tcp_header(const uint8_t *data, size_t len, tcp_header_t *out)
{
    if (!data || !out || len < 20) return false;

    tcp_header_t h;
    memset(&h, 0, sizeof(h));
    h.src_port = be16_read(data);
    h.dst_port = be16_read(data + 2);
    h.seq = be32_read(data + 4);
    h.ack = be32_read(data + 8);
    uint8_t data_off_reserved = data[12];
    h.data_offset = data_off_reserved >> 4;
    if (h.data_offset < 5) return false; // minimum
    h.header_length = (size_t)h.data_offset * 4;
    if (len < h.header_length) return false;
    h.flags = data[13];

    size_t payload_len = len - h.header_length;
    h.payload = data + h.header_length;
    h.payload_len = payload_len;

    *out = h;
    return true;
}
