/* Binary control protocol carried inside the TLS session.
 * Frame: [type:1][len:2 LE][seq:4 LE][payload:len][hmac:32]
 */
#include <string.h>
#include "mbedtls/md.h"
#include "app.h"

#define HDR_LEN        7u
#define MAC_LEN        32u
#define MAX_PAYLOAD    64u

#define T_SET_RELAY    0x01
#define T_SET_NAME     0x02
#define T_GET_STATUS   0x03
#define T_SET_SCHEDULE 0x04

extern const uint8_t *device_hmac_key(size_t *len);   /* per-device key from kv-store */
static uint32_t last_seq;
static plug_config_t cfg;

static bool mac_ok(const uint8_t *frame, uint16_t covered_len, const uint8_t *mac)
{
    uint8_t calc[MAC_LEN];
    size_t klen;
    const uint8_t *key = device_hmac_key(&klen);
    mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA256), key, klen, frame, covered_len, calc);
    return memcmp(calc, mac, MAC_LEN) == 0;
}

int protocol_handle_frame(const uint8_t *buf, uint16_t rx_len, uint8_t *resp, uint16_t resp_max)
{
    uint8_t  payload[MAX_PAYLOAD];
    char     status[16];

    if (rx_len < HDR_LEN + MAC_LEN) {
        return -1;
    }
    uint8_t  type = buf[0];
    uint16_t len  = (uint16_t)(buf[1] | (buf[2] << 8));
    uint32_t seq  = (uint32_t)buf[3] | ((uint32_t)buf[4] << 8) | ((uint32_t)buf[5] << 16) | ((uint32_t)buf[6] << 24);

    uint16_t total = HDR_LEN + len + MAC_LEN;
    if (total > rx_len) {
        return -2;   /* incomplete */
    }
    if (!mac_ok(buf, HDR_LEN + len, buf + HDR_LEN + len)) {
        return -3;
    }
    if (seq <= last_seq) {
        return -4;   /* replay */
    }
    last_seq = seq;

    if (len > MAX_PAYLOAD) {
        return -5;
    }
    memcpy(payload, buf + HDR_LEN, len);
    payload[len] = 0;

    switch (type) {
    case T_SET_RELAY:
        relay_request(payload[0] != 0);
        break;
    case T_SET_NAME:
        strncpy(cfg.name, (const char *)payload, sizeof(cfg.name) - 1);
        cfg.name[sizeof(cfg.name) - 1] = '\0';
        config_save(&cfg);
        break;
    case T_SET_SCHEDULE:
        if (len < 4) {
            return -6;
        }
        cfg.schedule_on_min  = (uint16_t)(payload[0] | (payload[1] << 8));
        cfg.schedule_off_min = (uint16_t)(payload[2] | (payload[3] << 8));
        cfg.schedule_enabled = 1;
        config_save(&cfg);
        break;
    case T_GET_STATUS:
        strcpy(status, "OK");
        break;
    default:
        return -7;
    }
    uint16_t n = (uint16_t)strlen(status);
    if (n > resp_max) {
        n = resp_max;
    }
    memcpy(resp, status, n);
    return n;
}
