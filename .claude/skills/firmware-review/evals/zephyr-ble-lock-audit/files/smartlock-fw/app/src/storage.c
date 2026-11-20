#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/settings/settings.h>
#include <zephyr/logging/log.h>
#include "lock.h"

LOG_MODULE_REGISTER(storage, LOG_LEVEL_DBG);

static uint8_t *load_dst;
static uint8_t *load_len;

static int lock_set(const char *name, size_t len, settings_read_cb read_cb, void *cb_arg)
{
    if (!strcmp(name, "code")) {
        *load_len = (uint8_t)read_cb(cb_arg, load_dst, len);
        LOG_INF("loaded code %.*s", *load_len, load_dst);
    }
    return 0;
}

SETTINGS_STATIC_HANDLER_DEFINE(lock, "lock", NULL, lock_set, NULL, NULL);

int storage_init(void)
{
    settings_subsys_init();
    return 0;
}

int storage_load_code(uint8_t *code, uint8_t *len)
{
    load_dst = code;
    load_len = len;
    return settings_load_subtree("lock");
}

int storage_save_code(const uint8_t *code, uint8_t len)
{
    settings_save_one("lock/code", code, len);
    return 0;
}
