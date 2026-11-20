#include <string.h>
#include <stdio.h>
#include "cyhal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cy_wcm.h"
#include "cy_secure_sockets.h"
#include "mtb_kvstore.h"
#include "app.h"

#define SERVER_HOST         "plug.acme-cloud.example"
#define SERVER_PORT         8443
#define BACKOFF_START_MS    1000u
#define RX_BUF_LEN          256u
#define TELEMETRY_PERIOD_MS 60000u

extern mtb_kvstore_t kvstore;   /* initialised by board support code */
static uint8_t hmac_key[32];
static size_t  hmac_key_len;

const uint8_t *device_hmac_key(size_t *len) { *len = hmac_key_len; return hmac_key; }

static cy_rslt_t connect_tls(cy_socket_t *s)
{
    cy_socket_sockaddr_t addr = { 0 };
    int verify = CY_SOCKET_TLS_VERIFY_REQUIRED;
    cy_rslt_t r = cy_socket_gethostbyname(SERVER_HOST, CY_SOCKET_IP_VER_V4, &addr.ip_address);
    if (r != CY_RSLT_SUCCESS) return r;
    addr.port = SERVER_PORT;
    r = cy_socket_create(CY_SOCKET_DOMAIN_AF_INET, CY_SOCKET_TYPE_STREAM, CY_SOCKET_IPPROTO_TLS, s);
    if (r != CY_RSLT_SUCCESS) return r;
    cy_socket_setsockopt(*s, CY_SOCKET_SOL_TLS, CY_SOCKET_SO_TLS_AUTH_MODE, &verify, sizeof(verify));
    cy_socket_setsockopt(*s, CY_SOCKET_SOL_TLS, CY_SOCKET_SO_SERVER_NAME_INDICATION, SERVER_HOST, strlen(SERVER_HOST));
    return cy_socket_connect(*s, &addr, sizeof(addr));
}

void net_task(void *arg)
{
    (void)arg;
    uint8_t   rx[RX_BUF_LEN];
    uint8_t   resp[32];
    uint32_t  backoff = BACKOFF_START_MS;
    uint32_t  rd = sizeof(hmac_key);

    if (mtb_kvstore_read(&kvstore, "hmac", hmac_key, &rd) != CY_RSLT_SUCCESS) {
        app_fatal_error(0x10);
    }
    hmac_key_len = rd;

    for (;;) {
        cy_socket_t sock;
        if (connect_tls(&sock) != CY_RSLT_SUCCESS) {
            wdt_checkin(WDT_TASK_NET);
            vTaskDelay(pdMS_TO_TICKS(backoff));
            backoff *= 2;
            continue;
        }
        backoff = BACKOFF_START_MS;
        TickType_t last_tx = xTaskGetTickCount();

        for (;;) {
            uint32_t got = 0;
            cy_rslt_t r = cy_socket_recv(sock, rx, sizeof(rx), CY_SOCKET_FLAGS_NONE, &got);
            if (r == CY_RSLT_SUCCESS && got > 0) {
                int n = protocol_handle_frame(rx, (uint16_t)got, resp, sizeof(resp));
                if (n > 0) {
                    uint32_t sent;
                    cy_socket_send(sock, resp, (uint32_t)n, CY_SOCKET_FLAGS_NONE, &sent);
                }
            } else if (r != CY_RSLT_MODULE_SECURE_SOCKETS_TIMEOUT) {
                break;   /* connection lost */
            }
            if ((TickType_t)(xTaskGetTickCount() - last_tx) >= pdMS_TO_TICKS(TELEMETRY_PERIOD_MS)) {
                char t[48];
                snprintf(t, sizeof(t), "{\"e\":%lu}", (unsigned long)(relay_energy_mws() / 1000u));
                uint32_t sent;
                cy_socket_send(sock, t, (uint32_t)strlen(t), CY_SOCKET_FLAGS_NONE, &sent);
                last_tx = xTaskGetTickCount();
            }
            wdt_checkin(WDT_TASK_NET);
        }
        cy_socket_disconnect(sock, 0);
        cy_socket_delete(sock);
    }
}
