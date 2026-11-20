#include "cyhal.h"
#include "cybsp.h"
#include "FreeRTOS.h"
#include "task.h"
#include "app.h"

#define SHT_ADDR          (0x44u)
#define SAMPLE_PERIOD_MS  (5000u)
#define I2C_RETRIES       (3u)

static cyhal_i2c_t i2c;
static volatile bool    have_sample;
static int16_t          last_c;
static uint16_t         last_rh;

static uint8_t crc8(const uint8_t *d, size_t n)
{
    uint8_t crc = 0xFF;
    for (size_t i = 0; i < n; i++) {
        crc ^= d[i];
        for (int b = 0; b < 8; b++) {
            crc = (uint8_t)((crc & 0x80u) ? (uint8_t)((crc << 1) ^ 0x31u) : (uint8_t)(crc << 1));
        }
    }
    return crc;
}

static bool read_sht(int16_t *c, uint16_t *rh)
{
    static const uint8_t cmd[2] = { 0x24, 0x00 };
    uint8_t rx[6];
    if (cyhal_i2c_master_write(&i2c, SHT_ADDR, cmd, sizeof(cmd), 0, true) != CY_RSLT_SUCCESS) {
        return false;
    }
    vTaskDelay(pdMS_TO_TICKS(20));
    if (cyhal_i2c_master_read(&i2c, SHT_ADDR, rx, sizeof(rx), 0, true) != CY_RSLT_SUCCESS) {
        return false;
    }
    if (crc8(&rx[0], 2) != rx[2] || crc8(&rx[3], 2) != rx[5]) {
        return false;
    }
    uint32_t raw_t  = ((uint32_t)rx[0] << 8) | rx[1];
    uint32_t raw_rh = ((uint32_t)rx[3] << 8) | rx[4];
    *c  = (int16_t)(-4500 + (int32_t)((17500u * raw_t) / 65535u));
    *rh = (uint16_t)((10000u * raw_rh) / 65535u);
    return true;
}

bool sensor_latest(int16_t *centi_c, uint16_t *centi_rh)
{
    taskENTER_CRITICAL();
    bool ok = have_sample;
    *centi_c  = last_c;
    *centi_rh = last_rh;
    taskEXIT_CRITICAL();
    return ok;
}

void sensor_task(void *arg)
{
    (void)arg;
    cyhal_i2c_cfg_t cfg = { .is_slave = false, .address = 0, .frequencyhal_hz = 100000 };
    if (cyhal_i2c_init(&i2c, CYBSP_I2C_SDA, CYBSP_I2C_SCL, NULL) != CY_RSLT_SUCCESS ||
        cyhal_i2c_configure(&i2c, &cfg) != CY_RSLT_SUCCESS) {
        app_fatal_error(0x20u);
    }
    TickType_t wake = xTaskGetTickCount();
    for (;;) {
        int16_t c; uint16_t rh;
        bool ok = false;
        for (uint32_t i = 0; i < I2C_RETRIES && !ok; i++) {
            ok = read_sht(&c, &rh);
        }
        taskENTER_CRITICAL();
        have_sample = ok;
        if (ok) { last_c = c; last_rh = rh; }
        taskEXIT_CRITICAL();
        wdt_checkin(WDT_TASK_SENSOR);
        vTaskDelayUntil(&wake, pdMS_TO_TICKS(SAMPLE_PERIOD_MS));
    }
}
