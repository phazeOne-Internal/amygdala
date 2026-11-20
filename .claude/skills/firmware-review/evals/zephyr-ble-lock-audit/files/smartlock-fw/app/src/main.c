#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include "lock.h"

LOG_MODULE_REGISTER(main, LOG_LEVEL_DBG);

#define FW_VERSION "0.9.1"
#define AUTO_RELOCK_MS 10000

extern uint32_t g_unlocked_at;
extern bool g_unlocked;

int main(void)
{
    LOG_INF("AcmeLock %s", FW_VERSION);
    storage_init();
    motor_init();

    if (bt_enable(NULL)) {
        LOG_ERR("bt_enable failed");
        while (1) { }
    }
    bt_passkey_set(123456);
    lock_service_init();

    while (1) {
        /* auto relock */
        if (g_unlocked && k_uptime_get_32() > g_unlocked_at + AUTO_RELOCK_MS && !g_door_open) {
            motor_lock();
            g_unlocked = false;
        }
        k_msleep(100);
    }
    return 0;
}
