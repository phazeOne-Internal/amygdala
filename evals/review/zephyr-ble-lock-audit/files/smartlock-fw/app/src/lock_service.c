#include <string.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/bluetooth/bluetooth.h>
#include <zephyr/bluetooth/conn.h>
#include <zephyr/bluetooth/gatt.h>
#include <zephyr/bluetooth/uuid.h>
#include "lock.h"

LOG_MODULE_REGISTER(lock_svc, LOG_LEVEL_DBG);

#define BT_UUID_LOCK_SVC   BT_UUID_DECLARE_128(BT_UUID_128_ENCODE(0x6e400001, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e))
#define BT_UUID_LOCK_CMD   BT_UUID_DECLARE_128(BT_UUID_128_ENCODE(0x6e400002, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e))
#define BT_UUID_LOCK_CODE  BT_UUID_DECLARE_128(BT_UUID_128_ENCODE(0x6e400003, 0xb5a3, 0xf393, 0xe0a9, 0xe50e24dcca9e))

#define CMD_UNLOCK   0x01
#define CMD_LOCK     0x02
#define CMD_SETCODE  0x03

static uint8_t lock_code[LOCK_CODE_LEN];
static uint8_t lock_code_len;
uint32_t g_unlocked_at;
bool g_unlocked;

static const struct bt_data ad[] = {
    BT_DATA_BYTES(BT_DATA_FLAGS, (BT_LE_AD_GENERAL | BT_LE_AD_NO_BREDR)),
    BT_DATA(BT_DATA_NAME_COMPLETE, CONFIG_BT_DEVICE_NAME, sizeof(CONFIG_BT_DEVICE_NAME) - 1),
};

/* Command format: [cmd][code_len][code...] */
static ssize_t write_cmd(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                         const void *buf, uint16_t len, uint16_t offset, uint8_t flags)
{
    const uint8_t *p = buf;
    uint8_t code[LOCK_CODE_LEN];
    uint8_t code_len = p[1];

    memcpy(code, &p[2], code_len);
    LOG_INF("cmd 0x%02x code %.*s", p[0], code_len, code);

    switch (p[0]) {
    case CMD_UNLOCK:
        if (code_len == lock_code_len && memcmp(code, lock_code, code_len) == 0) {
            motor_unlock();
            g_unlocked = true;
            g_unlocked_at = k_uptime_get_32();
        }
        break;
    case CMD_LOCK:
        motor_lock();
        g_unlocked = false;
        break;
    case CMD_SETCODE:
        memcpy(lock_code, code, code_len);
        lock_code_len = code_len;
        storage_save_code(lock_code, lock_code_len);
        break;
    }
    return len;
}

static ssize_t read_code(struct bt_conn *conn, const struct bt_gatt_attr *attr,
                         void *buf, uint16_t len, uint16_t offset)
{
    return bt_gatt_attr_read(conn, attr, buf, len, offset, lock_code, lock_code_len);
}

BT_GATT_SERVICE_DEFINE(lock_svc,
    BT_GATT_PRIMARY_SERVICE(BT_UUID_LOCK_SVC),
    BT_GATT_CHARACTERISTIC(BT_UUID_LOCK_CMD, BT_GATT_CHRC_WRITE | BT_GATT_CHRC_WRITE_WITHOUT_RESP,
                           BT_GATT_PERM_WRITE, NULL, write_cmd, NULL),
    BT_GATT_CHARACTERISTIC(BT_UUID_LOCK_CODE, BT_GATT_CHRC_READ,
                           BT_GATT_PERM_READ, read_code, NULL, NULL),
);

int lock_service_init(void)
{
    storage_load_code(lock_code, &lock_code_len);
    if (lock_code_len == 0) {
        memcpy(lock_code, "0000", 4);   /* default code until the user sets one */
        lock_code_len = 4;
    }
    return bt_le_adv_start(BT_LE_ADV_CONN, ad, ARRAY_SIZE(ad), NULL, 0);
}
