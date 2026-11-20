#include "cyhal.h"
#include "cybsp.h"
#include "FreeRTOS.h"
#include "task.h"
#include "event_groups.h"
#include "app.h"

#define WDT_TIMEOUT_MS       (8000u)
#define SUPERVISOR_PERIOD_MS (1000u)

/* .noinit is excluded from startup zeroing in our linker script, so this survives a soft reset. */
__attribute__((section(".noinit"))) static volatile uint32_t crash_reason;
__attribute__((section(".noinit"))) static volatile uint32_t crash_magic;
#define CRASH_MAGIC 0xC0FFEE01u

static cyhal_wdt_t        wdt;
static EventGroupHandle_t checkin_group;
static uint32_t           reset_reason;
static uint32_t           last_crash;

void app_fatal_error(uint32_t reason)
{
    __disable_irq();
    crash_reason = reason;
    crash_magic  = CRASH_MAGIC;
    NVIC_SystemReset();
}

uint32_t app_last_reset_reason(void) { return reset_reason; }
uint32_t app_last_crash_reason(void) { return last_crash; }

void wdt_checkin(uint32_t task_bit)
{
    xEventGroupSetBits(checkin_group, task_bit);
}

/* The WDT is only fed when every critical task has checked in within the window. */
static void supervisor_task(void *arg)
{
    (void)arg;
    for (;;) {
        EventBits_t bits = xEventGroupWaitBits(checkin_group, WDT_ALL_TASKS, pdTRUE, pdTRUE,
                                               pdMS_TO_TICKS(SUPERVISOR_PERIOD_MS * 4u));
        if ((bits & WDT_ALL_TASKS) == WDT_ALL_TASKS) {
            cyhal_wdt_kick(&wdt);
        }
    }
}

int main(void)
{
    if (cybsp_init() != CY_RSLT_SUCCESS) {
        app_fatal_error(1u);
    }
    __enable_irq();

    reset_reason = (uint32_t)cyhal_system_get_reset_reason();
    cyhal_system_clear_reset_reason();
    if (crash_magic == CRASH_MAGIC) {
        last_crash = crash_reason;
    }
    crash_magic = 0u;

    if (cyhal_wdt_init(&wdt, WDT_TIMEOUT_MS) != CY_RSLT_SUCCESS) {
        app_fatal_error(2u);
    }
    checkin_group = xEventGroupCreate();
    if (checkin_group == NULL) {
        app_fatal_error(3u);
    }
    if (xTaskCreate(supervisor_task, "SUP", 256, NULL, configMAX_PRIORITIES - 2, NULL) != pdPASS ||
        xTaskCreate(sensor_task, "SENS", 512, NULL, 3, NULL) != pdPASS ||
        xTaskCreate(net_task, "NET", 2048, NULL, 2, NULL) != pdPASS) {
        app_fatal_error(4u);
    }
    vTaskStartScheduler();
    app_fatal_error(5u);
    return 0;
}

void vApplicationStackOverflowHook(TaskHandle_t t, char *name) { (void)t; (void)name; app_fatal_error(6u); }
void vApplicationMallocFailedHook(void) { app_fatal_error(7u); }

void HardFault_Handler(void)
{
    /* Record the fault and reset; the reason is published in the next boot report. */
    app_fatal_error(0xFA000000u | (SCB->CFSR & 0x00FFFFFFu));
}
