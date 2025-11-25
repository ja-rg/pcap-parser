#ifndef HTTP_H
#define HTTP_H

#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef enum { HTTP_NONE = 0, HTTP_REQUEST, HTTP_RESPONSE } http_type_t;

typedef enum {
    HTTP_CAT_UNKNOWN = 0,
    HTTP_CAT_DOCUMENT,
    HTTP_CAT_FILE,
    HTTP_CAT_IMAGE,
    HTTP_CAT_VIDEO
} http_content_category_t;

typedef struct
{
    http_type_t type;
    // Pointer into TCP payload (start of message)
    const uint8_t *data;
    size_t data_len;

    // For requests: method token (pointer into data) and length
    const uint8_t *method;
    size_t method_len;

    // For responses: status code if available (e.g., 200)
    int status_code;

    // Content-Type header value (pointer into data) and length (excludes parameters)
    const uint8_t *content_type;
    size_t content_type_len;
    http_content_category_t content_category;
} http_info_t;

// Detección HTTP mejorada: reconoce requests/responses, parsea headers hasta CRLFCRLF
// y extrae `Content-Type` (si existe) para clasificar el contenido en:
// DOCUMENT (text/html, application/xhtml+xml), IMAGE (image/*), VIDEO (video/*), FILE (otros binarios), UNKNOWN.
// Devuelve true si el payload parece HTTP (request o response). No realiza malloc; los punteros apuntan dentro de `data`.
bool parse_http_payload(const uint8_t *data, size_t len, http_info_t *out);

#ifdef __cplusplus
}
#endif

#endif // HTTP_H
#include "ethernet.h"
