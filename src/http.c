#include "http.h"
#include <string.h>
#include <ctype.h>

static int prefix_cmp(const uint8_t *data, size_t len, const char *prefix)
{
    size_t pl = strlen(prefix);
    if (len < pl) return 0;
    return memcmp(data, (const uint8_t*)prefix, pl) == 0;
}

static size_t trim_right(const uint8_t *data, size_t len)
{
    while (len > 0 && (data[len-1] == '\r' || data[len-1] == '\n' || data[len-1] == ' ' || data[len-1] == '\t')) len--;
    return len;
}

static int iequals_header_name(const uint8_t *data, size_t len, const char *name)
{
    size_t nl = strlen(name);
    if (len != nl) return 0;
    for (size_t i = 0; i < nl; i++)
    {
        if (tolower((unsigned char)data[i]) != tolower((unsigned char)name[i])) return 0;
    }
    return 1;
}

// helper: compare header name at start of line (case-insensitive)
static int header_name_equals(const uint8_t *line, size_t line_len, const char *name)
{
    // find ':'
    for (size_t i = 0; i < line_len; i++)
    {
        if (line[i] == ':')
        {
            size_t name_len = i;
            // trim spaces on name end
            while (name_len > 0 && (line[name_len-1] == ' ' || line[name_len-1] == '\t')) name_len--;
            return iequals_header_name(line, name_len, name);
        }
    }
    return 0;
}

bool parse_http_payload(const uint8_t *data, size_t len, http_info_t *out)
{
    if (!data || !out || len == 0) return false;
    memset(out, 0, sizeof(*out));
    out->data = data;
    out->data_len = len;

    // Detect request or response by first token
    if (prefix_cmp(data, len, "HTTP/"))
    {
        // Response: status-line = HTTP/VERSION SP STATUS_CODE SP REASON CRLF
        out->type = HTTP_RESPONSE;
        // find end of status line
        size_t pos = 0;
        while (pos < len && data[pos] != '\n') pos++;
        size_t line_end = pos < len ? pos : len;
        // parse status code
        // find first space after HTTP/...
        size_t p = 0;
        while (p < line_end && data[p] != ' ') p++;
        if (p < line_end) {
            // skip spaces
            while (p < line_end && data[p] == ' ') p++;
            int code = 0;
            while (p < line_end && isdigit((unsigned char)data[p])) { code = code*10 + (data[p]-'0'); p++; }
            out->status_code = code;
        }
        // continue to headers
        size_t headers_start = (pos < len) ? pos+1 : pos;
        size_t i = headers_start;
        // iterate header lines until empty line
        while (i < len)
        {
            // find line end
            size_t j = i;
            while (j < len && data[j] != '\n') j++;
            size_t line_len = (j < len) ? (j - i) : (len - i);
            // trimmed length
            size_t tlen = trim_right(data + i, line_len);
            if (tlen == 0) { /* empty line -> end headers */ break; }
            // check Content-Type header
            if (header_name_equals(data + i, line_len, "Content-Type"))
            {
                // find ':'
                size_t k = 0;
                while (k < line_len && data[i+k] != ':') k++;
                if (k < line_len)
                {
                    size_t vstart = k + 1;
                    // skip spaces
                    while (vstart < line_len && (data[i+vstart] == ' ' || data[i+vstart] == '\t')) vstart++;
                    // value end is until ';' or CRLF
                    size_t vend = vstart;
                    while (vend < line_len && data[i+vend] != ';' && data[i+vend] != '\r' && data[i+vend] != '\n') vend++;
                    out->content_type = data + i + vstart;
                    out->content_type_len = vend - vstart;
                    // classify
                    if (out->content_type_len >= 9 && strncasecmp((const char*)out->content_type, "text/html", out->content_type_len) == 0) {
                        out->content_category = HTTP_CAT_DOCUMENT;
                    } else if (out->content_type_len >= 19 && strncasecmp((const char*)out->content_type, "application/xhtml+xml", out->content_type_len) == 0) {
                        out->content_category = HTTP_CAT_DOCUMENT;
                    } else if (out->content_type_len >= 6 && strncasecmp((const char*)out->content_type, "image/", 6) == 0) {
                        out->content_category = HTTP_CAT_IMAGE;
                    } else if (out->content_type_len >= 6 && strncasecmp((const char*)out->content_type, "video/", 6) == 0) {
                        out->content_category = HTTP_CAT_VIDEO;
                    } else {
                        out->content_category = HTTP_CAT_FILE;
                    }
                }
            }
            i = (j < len) ? j+1 : j;
        }
        return true;
    }
    else
    {
        // Possibly a request: METHOD SP TARGET SP HTTP/VERSION
        // Recognize common methods
        const char *methods[] = {"GET","POST","PUT","DELETE","HEAD","OPTIONS","PATCH"};
        size_t mcount = sizeof(methods)/sizeof(methods[0]);
        for (size_t mi = 0; mi < mcount; mi++)
        {
            size_t ml = strlen(methods[mi]);
            if (len > ml && memcmp(data, methods[mi], ml) == 0 && data[ml] == ' ')
            {
                out->type = HTTP_REQUEST;
                out->method = data;
                // method_len
                out->method_len = ml;
                // parse request-target
                size_t p = ml + 1;
                size_t start = p;
                while (p < len && data[p] != ' ' && data[p] != '\r' && data[p] != '\n') p++;
                size_t target_len = p - start;
                // attempt to infer from extension in target
                // find last '.' in target
                for (size_t k = 0; k + 1 < target_len; k++) {}
                if (target_len > 4)
                {
                    // simple check for common extensions
                    const uint8_t *t = data + start;
                    // lowercased comparison helper
                    // check .html .htm
                    if (target_len >= 5 && (strncasecmp((const char*)(t + target_len - 5), ".html", 5) == 0)) out->content_category = HTTP_CAT_DOCUMENT;
                    else if (target_len >= 4 && (strncasecmp((const char*)(t + target_len - 4), ".htm", 4) == 0)) out->content_category = HTTP_CAT_DOCUMENT;
                    else if (target_len >= 4 && (strncasecmp((const char*)(t + target_len - 4), ".pdf", 4) == 0)) out->content_category = HTTP_CAT_FILE;
                    else if (target_len >= 4 && (strncasecmp((const char*)(t + target_len - 4), ".jpg", 4) == 0)) out->content_category = HTTP_CAT_IMAGE;
                    else if (target_len >= 5 && (strncasecmp((const char*)(t + target_len - 5), ".jpeg", 5) == 0)) out->content_category = HTTP_CAT_IMAGE;
                    else if (target_len >= 4 && (strncasecmp((const char*)(t + target_len - 4), ".png", 4) == 0)) out->content_category = HTTP_CAT_IMAGE;
                    else if (target_len >= 4 && (strncasecmp((const char*)(t + target_len - 4), ".mp4", 4) == 0)) out->content_category = HTTP_CAT_VIDEO;
                    else out->content_category = HTTP_CAT_UNKNOWN;
                }
                return true;
            }
        }
    }
    return false;
}
