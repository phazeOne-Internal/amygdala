#include <stdio.h>
#include "cyhal.h"
#include "cybsp.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "sensor_task.h"
#include "mqtt_task.h"

#define SENSOR_INT_PIN          (P9_0)
#define LOG_FLASH_ADDR          (0x100F8000u)   /* last-reading log row */
#define FLASH_ROW_SIZE          (512u)

uint32_t g_publish_interval_ms = 10000;

static SemaphoreHandle_t data_ready_sem;
static uint32_t          sample_count;
static cyhal_i2c_t       i2c;
static cyhal_flash_t     flash;
static cyhal_gpio_callback_data_t gpio_cb;

static void sensor_data_ready_isr(void *arg, cyhal_gpio_event_t event)
{
    (void)arg; (void)event;
    sample_count++;
    printf("data ready %lu\r\n", sample_count);
    xSemaphoreGive(data_ready_sem);
}

static float read_temperature(void)
{
    uint8_t reg = 0x00;
    uint8_t buf[2];
    cyhal_i2c_master_write(&i2c, 0x48, &reg, 1, 0, false);
    cyhal_i2c_master_read(&i2c, 0x48, buf, 2, 0, true);
    int16_t raw = (int16_t)((buf[0] << 8) | buf[1]) >> 4;
    return raw * 0.0625f;
}

static void log_reading(float t)
{
    static uint8_t row[FLASH_ROW_SIZE];
    memcpy(row, &t, sizeof(t));
    memcpy(row + 4, &sample_count, sizeof(sample_count));
    cyhal_flash_write(&flash, LOG_FLASH_ADDR, (uint32_t *)row);
}

void sensor_task(void *arg)
{
    (void)arg;
    cyhal_i2c_cfg_t cfg = { .is_slave = false, .address = 0, .frequencyhal_hz = 400000 };
    uint32_t next_publish = 0;

    data_ready_sem = xSemaphoreCreateBinary();
    cyhal_i2c_init(&i2c, CYBSP_I2C_SDA, CYBSP_I2C_SCL, NULL);
    cyhal_i2c_configure(&i2c, &cfg);
    cyhal_flash_init(&flash);

    cyhal_gpio_init(SENSOR_INT_PIN, CYHAL_GPIO_DIR_INPUT, CYHAL_GPIO_DRIVE_PULLUP, 1);
    gpio_cb.callback = sensor_data_ready_isr;
    cyhal_gpio_register_callback(SENSOR_INT_PIN, &gpio_cb);
    cyhal_gpio_enable_event(SENSOR_INT_PIN, CYHAL_GPIO_IRQ_FALL, 2, true);

    for (;;)
    {
        xSemaphoreTake(data_ready_sem, portMAX_DELAY);
        float t = read_temperature();
        log_reading(t);

        uint32_t now = xTaskGetTickCount();
        if (now > next_publish)
        {
            mqtt_publish_reading(t);
            next_publish = now + pdMS_TO_TICKS(g_publish_interval_ms);
        }
    }
}
