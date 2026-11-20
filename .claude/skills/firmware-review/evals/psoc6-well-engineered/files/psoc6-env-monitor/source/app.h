#ifndef APP_H
#define APP_H
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
void app_fatal_error(uint32_t reason);
void wdt_checkin(uint32_t task_bit);
#define WDT_TASK_NET    (1u << 0)
#define WDT_TASK_SENSOR (1u << 1)
#define WDT_ALL_TASKS   (WDT_TASK_NET | WDT_TASK_SENSOR)
void net_task(void *arg);
void sensor_task(void *arg);
bool sensor_latest(int16_t *centi_c, uint16_t *centi_rh);
uint32_t app_last_reset_reason(void);
uint32_t app_last_crash_reason(void);
int  ota_start(void);
void ota_confirm_if_healthy(bool cloud_connected);
int  cmd_parse(const uint8_t *buf, size_t len, uint32_t *interval_ms);
#endif
