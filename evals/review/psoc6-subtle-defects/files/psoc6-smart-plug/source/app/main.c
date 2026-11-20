#include "cyhal.h"
#include "cybsp.h"
#include "FreeRTOS.h"
#include "task.h"
#include "event_groups.h"
#include "app.h"

#define WDT_TIMEOUT_MS       (8000u)
#define SUPERVISOR_PERIOD_MS (1000u)

CY_SECTION(".cy_sharedmem") static volatile uint32_t crash_reason;   /* survives soft reset */
static cyhal_wdt_t      wdt;
static cyhal_trng_t     trng;
static EventGroupHandle_t checkin_group;

void app_fatal_error(uint32_t reason)
{
    crash_reason = reason;
    NVIC_SystemReset();
}

void wdt_checkin(uint32_t task_bit)
{
    xEventGroupSetBits(checkin_group, task_bit);
}

bool trng_get_bytes(uint8_t *out, size_t len)
{
    for (size_t i = 0; i < len; i += 4) {
        uint32_t r = cyhal_trng_generate(&trng);
        size_t n = (len - i) < 4 ? (len - i) : 4;
        memcpy(&out[i], &r, n);
    }
    return true;
}

/* Feeds the WDT only when every critical task has checked in this period. */
static void supervisor_task(void *arg)
{
    (void)arg;
    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(checkin_group, WDT_ALL_TASKS, pdTRUE, pdTRUE,
                                               pdMS_TO_TICKS(SUPERVISOR_PERIOD_MS * 4));
        if ((bits & WDT_ALL_TASKS) == WDT_ALL_TASKS) {
            cyhal_wdt_kick(&wdt);
        }
    }
}

int main(void)
{
    if (cybsp_init() != CY_RSLT_SUCCESS) {
        app_fatal_error(1);
    }
    __enable_irq();

    cyhal_reset_reason_t why = cyhal_system_get_reset_reason();
    cyhal_system_clear_reset_reason();
    (void)why;   /* reported in the first telemetry frame by net_task */

    CY_ASSERT(cyhal_trng_init(&trng) == CY_RSLT_SUCCESS);

    if (cyhal_wdt_init(&wdt, WDT_TIMEOUT_MS) != CY_RSLT_SUCCESS) {
        app_fatal_error(2);
    }

    checkin_group = xEventGroupCreate();
    relay_init();

    xTaskCreate(supervisor_task, "SUP",   256, NULL, configMAX_PRIORITIES - 2, NULL);
    xTaskCreate(relay_task,      "RELAY", 512, NULL, 4, NULL);
    xTaskCreate(net_task,        "NET",  2048, NULL, 2, NULL);
    vTaskStartScheduler();
    app_fatal_error(3);
}

void vApplicationStackOverflowHook(TaskHandle_t t, char *name) { (void)t; (void)name; app_fatal_error(4); }
void vApplicationMallocFailedHook(void) { app_fatal_error(5); }
