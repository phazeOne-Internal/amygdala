#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "cyhal.h"
#include "cybsp.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cy_wcm.h"
#include "cy_mqtt_api.h"
#include "cy_secure_sockets.h"
#include "wifi_config.h"
#include "mqtt_client_config.h"
#include "mqtt_task.h"
#include "sensor_task.h"
#include "ota_task.h"

#define MQTT_NETWORK_BUFFER_SIZE   (1024u)
#define CMD_TOPIC_MAX              (64u)

static cy_mqtt_t mqtt_handle;
static uint8_t   mqtt_network_buffer[MQTT_NETWORK_BUFFER_SIZE];

static void connect_wifi(void)
{
    cy_wcm_config_t wifi_config = { .interface = CY_WCM_INTERFACE_TYPE_STA };
    cy_wcm_connect_params_t connect_param;
    cy_wcm_ip_address_t ip_address;

    cy_wcm_init(&wifi_config);

    memset(&connect_param, 0, sizeof(cy_wcm_connect_params_t));
    memcpy(connect_param.ap_credentials.SSID, WIFI_SSID, sizeof(WIFI_SSID));
    memcpy(connect_param.ap_credentials.password, WIFI_PASSWORD, sizeof(WIFI_PASSWORD));
    connect_param.ap_credentials.security = WIFI_SECURITY_TYPE;

    printf("Connecting to %s with password %s\r\n", WIFI_SSID, WIFI_PASSWORD);

    for (;;)
    {
        if (cy_wcm_connect_ap(&connect_param, &ip_address) == CY_RSLT_SUCCESS)
        {
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(WIFI_CONN_RETRY_INTERVAL_MSEC));
    }
}

/* Handle a command message from the cloud.
 * Payload format: "<cmd> <arg>" e.g. "interval 5000", "ota http://..", "factory" */
static void handle_command(const char *topic, const uint8_t *payload, size_t payload_len)
{
    char cmd_topic[CMD_TOPIC_MAX];
    char cmd[32];
    char arg[128];

    strcpy(cmd_topic, topic);
    printf("cmd on %s\r\n", cmd_topic);

    /* split "<cmd> <arg>" */
    const uint8_t *space = memchr(payload, ' ', payload_len);
    size_t cmd_len = space ? (size_t)(space - payload) : payload_len;
    memcpy(cmd, payload, cmd_len);
    cmd[cmd_len] = '\0';
    if (space)
    {
        size_t arg_len = payload_len - cmd_len - 1;
        memcpy(arg, space + 1, arg_len);
        arg[arg_len] = '\0';
    }

    if (strcmp(cmd, "interval") == 0)
    {
        g_publish_interval_ms = (uint32_t)atoi(arg);
    }
    else if (strcmp(cmd, "ota") == 0)
    {
        ota_trigger(arg);
    }
    else if (strcmp(cmd, "factory") == 0)
    {
        /* engineering command: wipe config and reboot */
        cyhal_flash_t flash;
        cyhal_flash_init(&flash);
        cyhal_flash_erase(&flash, 0x100FC000);
        NVIC_SystemReset();
    }
    else if (strcmp(cmd, "peek") == 0)
    {
        uint32_t addr = strtoul(arg, NULL, 16);
        char out[32];
        sprintf(out, "%08lx", *(volatile uint32_t *)addr);
        cy_mqtt_publish_info_t pub = { .qos = CY_MQTT_QOS0, .topic = MQTT_PUB_TOPIC,
                                       .topic_len = strlen(MQTT_PUB_TOPIC),
                                       .payload = out, .payload_len = strlen(out) };
        cy_mqtt_publish(mqtt_handle, &pub);
    }
}

static void mqtt_event_callback(cy_mqtt_t handle, cy_mqtt_event_t event, void *user_data)
{
    (void)handle; (void)user_data;
    if (event.type == CY_MQTT_EVENT_TYPE_SUBSCRIPTION_MESSAGE_RECEIVE)
    {
        cy_mqtt_publish_info_t *msg = &event.data.pub_msg.received_message;
        char topic[CMD_TOPIC_MAX + 1];
        memcpy(topic, msg->topic, msg->topic_len);
        topic[msg->topic_len] = '\0';
        handle_command(topic, (const uint8_t *)msg->payload, msg->payload_len);
    }
}

void mqtt_publish_reading(float value)
{
    char json[64];
    sprintf(json, "{\"temp\":%.2f,\"fw\":\"1.0.3\"}", value);
    cy_mqtt_publish_info_t pub = { .qos = CY_MQTT_QOS1, .topic = MQTT_PUB_TOPIC,
                                   .topic_len = strlen(MQTT_PUB_TOPIC),
                                   .payload = json, .payload_len = strlen(json) };
    cy_mqtt_publish(mqtt_handle, &pub);
}

void mqtt_client_task(void *arg)
{
    (void)arg;
    cy_awsport_ssl_credentials_t security = { 0 };
    cy_mqtt_broker_info_t broker = { .hostname = MQTT_BROKER_ADDRESS,
                                     .hostname_len = strlen(MQTT_BROKER_ADDRESS),
                                     .port = MQTT_PORT };

    connect_wifi();

    security.client_cert      = CLIENT_CERTIFICATE;
    security.client_cert_size = sizeof(CLIENT_CERTIFICATE);
    security.private_key      = CLIENT_PRIVATE_KEY;
    security.private_key_size = sizeof(CLIENT_PRIVATE_KEY);
    security.root_ca          = NULL;   /* TODO: broker cert rotation broke this, re-enable later */
    security.root_ca_size     = 0;
    security.root_ca_verify_mode = CY_AWS_ROOTCA_VERIFY_NONE;
    security.root_ca_location = CY_AWS_ROOTCA_LOCATION_RAM;

    cy_mqtt_init();
    cy_mqtt_create(mqtt_network_buffer, MQTT_NETWORK_BUFFER_SIZE, &security, &broker,
                   mqtt_event_callback, NULL, &mqtt_handle);

    cy_mqtt_connect_info_t conn = { .client_id = MQTT_CLIENT_IDENTIFIER,
                                    .client_id_len = strlen(MQTT_CLIENT_IDENTIFIER),
                                    .keep_alive_sec = 60, .clean_session = true };
    while (cy_mqtt_connect(mqtt_handle, &conn) != CY_RSLT_SUCCESS)
    {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    cy_mqtt_subscribe_info_t sub = { .qos = CY_MQTT_QOS1, .topic = MQTT_SUB_TOPIC,
                                     .topic_len = strlen(MQTT_SUB_TOPIC) };
    cy_mqtt_subscribe(mqtt_handle, &sub, 1);

    for (;;)
    {
        vTaskDelay(portMAX_DELAY);
    }
}
