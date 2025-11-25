#ifndef IP_H
#define IP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint8_t version;      // 4 for IPv4
    uint8_t ihl;          // Internet Header Length (words)
    uint16_t total_length;
    uint8_t protocol;     // e.g., 6 for TCP
    uint32_t src_addr;    // network byte order
    uint32_t dst_addr;    // network byte order
    size_t header_length; // bytes (ihl * 4)

    // payload pointer (apunta dentro del buffer original)
    const uint8_t *payload;
    size_t payload_len;
} ipv4_header_t;

// Parsea un header IPv4 desde `data` de longitud `len`.
// Devuelve true si se pudo parsear y rellena `out` (no realiza malloc).
bool parse_ipv4_header(const uint8_t *data, size_t len, ipv4_header_t *out);

#ifdef __cplusplus
}
#endif

#endif // IP_H

