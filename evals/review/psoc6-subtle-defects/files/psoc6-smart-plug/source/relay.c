#include "cyhal.h"
#include "cybsp.h"
#include "FreeRTOS.h"
#include "task.h"
#include "semphr.h"
#include "queue.h"
#include "app.h"

#define RELAY_PIN       (P9_1)
#define ZERO_CROSS_PIN  (P9_2)
#define ZC_ISR_PRIORITY (6u)   /* below configMAX_SYSCALL_INTERRUPT_PRIORITY */

static SemaphoreHandle_t relay_mutex;
static QueueHandle_t     relay_q;
static volatile bool     pending_state;
static volatile bool     switch_pending;
static uint64_t          energy_mws;      /* accumulated in zero-cross ISR */
static uint32_t          power_mw = 1200; /* updated by metering (not shown) */
static cyhal_gpio_callback_data_t zc_cb;

static void relay_apply(bool on)
{
    xSemaphoreTake(relay_mutex, portMAX_DELAY);
    cyhal_gpio_write(RELAY_PIN, on);
    xSemaphoreGive(relay_mutex);
}

/* Zero-cross detector, 100/120 Hz: switch the relay at the zero crossing to protect contacts,
 * and integrate energy. */
static void zero_cross_isr(void *arg, cyhal_gpio_event_t ev)
{
    (void)arg; (void)ev;
    energy_mws += power_mw / 100u;
    if (switch_pending) {
        switch_pending = false;
        relay_apply(pending_state);
    }
}

uint64_t relay_energy_mws(void)
{
    return energy_mws;
}

void relay_request(bool on)
{
    xQueueSend(relay_q, &on, 0);
}

void relay_init(void)
{
    plug_config_t cfg;
    relay_mutex = xSemaphoreCreateMutex();
    relay_q     = xQueueCreate(4, sizeof(bool));
    bool initial = false;
    if (config_load(&cfg)) {
        initial = cfg.relay_on;
    }
    cyhal_gpio_init(RELAY_PIN, CYHAL_GPIO_DIR_OUTPUT, CYHAL_GPIO_DRIVE_STRONG, initial);
    cyhal_gpio_init(ZERO_CROSS_PIN, CYHAL_GPIO_DIR_INPUT, CYHAL_GPIO_DRIVE_NONE, 0);
    zc_cb.callback = zero_cross_isr;
    cyhal_gpio_register_callback(ZERO_CROSS_PIN, &zc_cb);
    cyhal_gpio_enable_event(ZERO_CROSS_PIN, CYHAL_GPIO_IRQ_RISE, ZC_ISR_PRIORITY, true);
}

void relay_task(void *arg)
{
    (void)arg;
    bool on;
    for (;;) {
        if (xQueueReceive(relay_q, &on, pdMS_TO_TICKS(500)) == pdTRUE) {
            pending_state  = on;
            switch_pending = true;
        }
        wdt_checkin(WDT_TASK_RELAY);
    }
}
