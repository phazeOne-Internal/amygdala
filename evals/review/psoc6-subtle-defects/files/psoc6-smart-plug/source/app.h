#ifndef APP_H
#define APP_H
#include <stdint.h>
#include <stdbool.h>
#define FW_VERSION_STRING "2.3.0"
void app_fatal_error(uint32_t reason);
void wdt_checkin(uint32_t task_bit);
#define WDT_TASK_NET    (1u << 0)
#define WDT_TASK_RELAY  (1u << 1)
#define WDT_ALL_TASKS   (WDT_TASK_NET | WDT_TASK_RELAY)
void net_task(void *arg);
void relay_task(void *arg);
void relay_init(void);
void relay_request(bool on);
uint64_t relay_energy_mws(void);
int  protocol_handle_frame(const uint8_t *buf, uint16_t rx_len, uint8_t *resp, uint16_t resp_max);
typedef struct { uint32_t magic; uint8_t relay_on; uint8_t schedule_enabled; uint16_t schedule_on_min; uint16_t schedule_off_min; char name[24]; } plug_config_t;
bool config_load(plug_config_t *cfg);
bool config_save(const plug_config_t *cfg);
bool trng_get_bytes(uint8_t *out, size_t len);
#endif
