#include "cyhal.h"
#include "cybsp.h"
#include "cy_retarget_io.h"
#include "FreeRTOS.h"
#include "task.h"
#include "mqtt_task.h"
#include "sensor_task.h"
#include "ota_task.h"
#include "app_version.h"

#define WDT_TIMEOUT_MS     (4000u)
#define WDT_KICK_PERIOD_HZ (1u)

static cyhal_wdt_t   wdt_obj;
static cyhal_timer_t wdt_kick_timer;

/* Kick the watchdog once a second from a hardware timer so it never fires
 * during long Wi-Fi joins or OTA flash erases. */
static void wdt_kick_timer_cb(void *arg, cyhal_timer_event_t event)
{
    (void)arg; (void)event;
    cyhal_wdt_kick(&wdt_obj);
}

static void watchdog_init(void)
{
    cy_rslt_t result = cyhal_wdt_init(&wdt_obj, WDT_TIMEOUT_MS);
    CY_ASSERT(CY_RSLT_SUCCESS == result);

    const cyhal_timer_cfg_t cfg = {
        .compare_value = 0, .period = 9999, .direction = CYHAL_TIMER_DIR_UP,
        .is_compare = false, .is_continuous = true, .value = 0
    };
    cyhal_timer_init(&wdt_kick_timer, NC, NULL);
    cyhal_timer_configure(&wdt_kick_timer, &cfg);
    cyhal_timer_set_frequency(&wdt_kick_timer, 10000);
    cyhal_timer_register_callback(&wdt_kick_timer, wdt_kick_timer_cb, NULL);
    cyhal_timer_enable_event(&wdt_kick_timer, CYHAL_TIMER_IRQ_TERMINAL_COUNT, 3, true);
    cyhal_timer_start(&wdt_kick_timer);
}

int main(void)
{
    cy_rslt_t result;

    result = cybsp_init();
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }
    __enable_irq();

    result = cy_retarget_io_init(CYBSP_DEBUG_UART_TX, CYBSP_DEBUG_UART_RX, CY_RETARGET_IO_BAUDRATE);
    if (result != CY_RSLT_SUCCESS)
    {
        CY_ASSERT(0);
    }

    printf("\x1b[2J\x1b[;H");
    printf("Acme sensor FW %s\r\n", FW_VERSION_STRING);

    watchdog_init();

    xTaskCreate(mqtt_client_task, "MQTT", 1024, NULL, 2, NULL);
    xTaskCreate(sensor_task,      "SENSOR", 512, NULL, 3, NULL);
    xTaskCreate(ota_task,         "OTA",   1024, NULL, 1, NULL);

    vTaskStartScheduler();

    /* Should never get here */
    CY_ASSERT(0);
}

void HardFault_Handler(void)
{
    while (1);
}
