#ifndef WIFI_CONFIG_H_
#define WIFI_CONFIG_H_
#include "cy_wcm.h"

#define WIFI_SSID                         "AcmeFactory-5G"
#define WIFI_PASSWORD                     "Acme$ensor2024!"
#define WIFI_SECURITY_TYPE                CY_WCM_SECURITY_WPA2_AES_PSK
#define MAX_WIFI_CONN_RETRIES             (10u)
#define WIFI_CONN_RETRY_INTERVAL_MSEC     (100u)
#endif
