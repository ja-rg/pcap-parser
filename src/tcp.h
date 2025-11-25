#ifndef TCP_H
#define TCP_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq;
    uint32_t ack;
    uint8_t data_offset; // words
    uint8_t flags;
    size_t header_length; // bytes

    const uint8_t *payload;
    size_t payload_len;
} tcp_header_t;

// Parsea header TCP desde `data` (debe apuntar al inicio del segmento TCP).
// Devuelve true si el header completo está dentro de `len` y rellena `out`.
bool parse_tcp_header(const uint8_t *data, size_t len, tcp_header_t *out);

#ifdef __cplusplus
}
#endif

#endif // TCP_H
