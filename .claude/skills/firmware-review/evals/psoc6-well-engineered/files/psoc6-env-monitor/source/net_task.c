#include <string.h>
#include <stdio.h>
#include "cyhal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cy_wcm.h"
#include "cy_mqtt_api.h"
#include "cy_ota_api.h"
#include "mtb_kvstore.h"
#include "app.h"

#define BACKOFF_START_MS  (1000u)
#define BACKOFF_MAX_MS    (300000u)
#define CRED_MAX          (2048u)

extern mtb_kvstore_t kvstore;
static char     client_id[32];
static char     cert[CRED_MAX], key[CRED_MAX];
static uint32_t publish_interval_ms = 60000u;
static uint8_t  net_buf[2048];
static cy_mqtt_t mqtt;
static volatile bool mqtt_up;

static bool load_cred(const char *name, char *dst, size_t cap)
{
    uint32_t n = (uint32_t)(cap - 1u);
    if (mtb_kvstore_read(&kvstore, name, (uint8_t *)dst, &n) != CY_RSLT_SUCCESS || n == 0u) {
        return false;
    }
    dst[n] = '\0';
    return true;
}

static void mqtt_cb(cy_mqtt_t h, cy_mqtt_event_t ev, void *ud)
{
    (void)h; (void)ud;
    if (ev.type == CY_MQTT_EVENT_TYPE_DISCONNECT) {
        mqtt_up = false;
    } else if (ev.type == CY_MQTT_EVENT_TYPE_SUBSCRIPTION_MESSAGE_RECEIVE) {
        const cy_mqtt_publish_info_t *m = &ev.data.pub_msg.received_message;
        uint32_t v;
        if (cmd_parse((const uint8_t *)m->payload, m->payload_len, &v) == 0) {
            publish_interval_ms = v;
        }
    }
}

static bool mqtt_bring_up(void)
{
    cy_awsport_ssl_credentials_t sec = { 0 };
    sec.client_cert = cert;  sec.client_cert_size = strlen(cert) + 1u;
    sec.private_key = key;   sec.private_key_size = strlen(key) + 1u;
    sec.root_ca_verify_mode = CY_AWS_ROOTCA_VERIFY_REQUIRED;
    sec.root_ca_location    = CY_AWS_ROOTCA_LOCATION_SECURE_STORAGE;
    sec.sni_host_name       = "iot.acme.example";
    sec.sni_host_name_size  = sizeof("iot.acme.example");
    cy_mqtt_broker_info_t broker = { .hostname = "iot.acme.example", .hostname_len = sizeof("iot.acme.example") - 1u, .port = 8883 };
    if (cy_mqtt_create(net_buf, sizeof(net_buf), &sec, &broker, mqtt_cb, NULL, &mqtt) != CY_RSLT_SUCCESS) {
        return false;
    }
    cy_mqtt_connect_info_t ci = { .client_id = client_id, .client_id_len = (uint16_t)strlen(client_id),
                                  .keep_alive_sec = 120, .clean_session = false };
    if (cy_mqtt_connect(mqtt, &ci) != CY_RSLT_SUCCESS) {
        cy_mqtt_delete(mqtt);
        return false;
    }
    char topic[64];
    snprintf(topic, sizeof(topic), "acme/env/%s/cmd", client_id);
    cy_mqtt_subscribe_info_t sub = { .qos = CY_MQTT_QOS1, .topic = topic, .topic_len = (uint16_t)strlen(topic) };
    if (cy_mqtt_subscribe(mqtt, &sub, 1) != CY_RSLT_SUCCESS) {
        cy_mqtt_disconnect(mqtt);
        cy_mqtt_delete(mqtt);
        return false;
    }
    mqtt_up = true;
    return true;
}

void net_task(void *arg)
{
    (void)arg;
    if (!load_cred("dev_id", client_id, sizeof(client_id)) || !load_cred("dev_cert", cert, sizeof(cert)) ||
        !load_cred("dev_key", key, sizeof(key))) {
        app_fatal_error(0x30u);   /* unprovisioned unit: refuse to run with defaults */
    }
    if (cy_mqtt_init() != CY_RSLT_SUCCESS) {
        app_fatal_error(0x31u);
    }
    uint32_t backoff = BACKOFF_START_MS;
    TickType_t last_pub = xTaskGetTickCount();
    bool boot_report_sent = false;

    for (;;) {
        if (!mqtt_up) {
            if (!mqtt_bring_up()) {
                wdt_checkin(WDT_TASK_NET);
                vTaskDelay(pdMS_TO_TICKS(backoff));
                backoff = (backoff >= BACKOFF_MAX_MS / 2u) ? BACKOFF_MAX_MS : backoff * 2u;
                continue;
            }
            backoff = BACKOFF_START_MS;
            ota_confirm_if_healthy(true);
            if (ota_start() != 0) {
                /* OTA agent failed to start; retried on the next reconnect */
            }
        }
        if (!boot_report_sent) {
            char b[96];
            snprintf(b, sizeof(b), "{\"fw\":\"%d.%d.%d\",\"rst\":%lu,\"crash\":%lu}", APP_VERSION_MAJOR,
                     APP_VERSION_MINOR, APP_VERSION_BUILD, (unsigned long)app_last_reset_reason(),
                     (unsigned long)app_last_crash_reason());
            cy_mqtt_publish_info_t p = { .qos = CY_MQTT_QOS1, .topic = "acme/env/boot", .topic_len = 13, .payload = b,
                                         .payload_len = strlen(b) };
            boot_report_sent = (cy_mqtt_publish(mqtt, &p) == CY_RSLT_SUCCESS);
        }
        if ((TickType_t)(xTaskGetTickCount() - last_pub) >= pdMS_TO_TICKS(publish_interval_ms)) {
            int16_t c; uint16_t rh;
            if (sensor_latest(&c, &rh)) {
                char j[64];
                snprintf(j, sizeof(j), "{\"t\":%d,\"rh\":%u}", c, rh);
                cy_mqtt_publish_info_t p = { .qos = CY_MQTT_QOS1, .topic = "acme/env/data", .topic_len = 13,
                                             .payload = j, .payload_len = strlen(j) };
                (void)cy_mqtt_publish(mqtt, &p);   /* QoS1; a lost sample is acceptable */
            }
            last_pub = xTaskGetTickCount();
        }
        wdt_checkin(WDT_TASK_NET);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
}
