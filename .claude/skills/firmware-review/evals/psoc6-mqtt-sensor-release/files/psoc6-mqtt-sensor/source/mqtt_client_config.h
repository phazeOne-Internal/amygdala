#ifndef MQTT_CLIENT_CONFIG_H_
#define MQTT_CLIENT_CONFIG_H_
#include "cy_mqtt_api.h"

#define MQTT_BROKER_ADDRESS               "a1b2c3d4e5f6g7-ats.iot.eu-west-1.amazonaws.com"
#define MQTT_PORT                         8883
#define MQTT_SECURE_CONNECTION            ( 1 )
#define MQTT_CLIENT_IDENTIFIER            "acme-sensor"
#define MQTT_SUB_TOPIC                    "acme/sensor/cmd"
#define MQTT_PUB_TOPIC                    "acme/sensor/data"

/* Device credentials (same for all units - provisioning TBD) */
#define CLIENT_CERTIFICATE \
"-----BEGIN CERTIFICATE-----\n" \
"MIIDWTCCAkGgAwIBAgIUQ0R4kQ2Jm8e6f0hb5wqgF3F7xH0wDQYJKoZIhvcNAQEL\n" \
"-----END CERTIFICATE-----\n"

#define CLIENT_PRIVATE_KEY \
"-----BEGIN RSA PRIVATE KEY-----\n" \
"MIIEpAIBAAKCAQEAu7e3n5bM0k5fP2bT3r8Y9vK2aQx1m4L0x7m3J9dY2Fh8W1kQ\n" \
"-----END RSA PRIVATE KEY-----\n"

#define ROOT_CA_CERTIFICATE \
"-----BEGIN CERTIFICATE-----\n" \
"MIIDQTCCAimgAwIBAgITBmyfz5m/jAo54vB4ikPmljZbyjANBgkqhkiG9w0BAQsF\n" \
"-----END CERTIFICATE-----\n"
#endif
