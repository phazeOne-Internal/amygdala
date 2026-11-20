#include <string.h>
#include "app.h"

#define MIN_INTERVAL_MS   (10000u)
#define MAX_INTERVAL_MS   (3600000u)

/* Parses "interval=<ms>" (ASCII, not NUL-terminated). Returns 0 on success. */
int cmd_parse(const uint8_t *buf, size_t len, uint32_t *interval_ms)
{
    static const char key[] = "interval=";
    const size_t klen = sizeof(key) - 1u;
    if (buf == NULL || interval_ms == NULL || len <= klen || len > klen + 7u) {
        return -1;
    }
    if (memcmp(buf, key, klen) != 0) {
        return -1;
    }
    uint32_t v = 0;
    for (size_t i = klen; i < len; i++) {
        if (buf[i] < '0' || buf[i] > '9') {
            return -1;
        }
        v = v * 10u + (uint32_t)(buf[i] - '0');   /* max 7 digits: cannot overflow */
    }
    if (v < MIN_INTERVAL_MS || v > MAX_INTERVAL_MS) {
        return -1;
    }
    *interval_ms = v;
    return 0;
}
