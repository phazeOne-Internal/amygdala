#include <stdio.h>
#include <string.h>
#include "cyhal.h"
#include "FreeRTOS.h"
#include "task.h"
#include "cy_ota_api.h"
#include "ota_task.h"

static char ota_url[256];
static TaskHandle_t ota_handle;
static cy_ota_context_ptr ota_ctx;

void ota_trigger(const char *url)
{
    strcpy(ota_url, url);
    xTaskNotifyGive(ota_handle);
}

void ota_task(void *arg)
{
    (void)arg;
    ota_handle = xTaskGetCurrentTaskHandle();
    for (;;)
    {
        ulTaskNotifyTake(pdTRUE, portMAX_DELAY);
        printf("OTA from %s\r\n", ota_url);

        cy_ota_network_params_t net = { 0 };
        net.initial_connection = CY_OTA_CONNECTION_HTTP;
        net.http.file = ota_url;
        net.use_get_job_flow = CY_OTA_DIRECT_FLOW;
        net.http.credentials = NULL;       /* plain HTTP from our update server */

        cy_ota_agent_params_t agent = { 0 };
        agent.validate_after_reboot = 0;   /* TODO: enable signature/validation once signing pipeline exists */
        agent.reboot_upon_completion = 1;

        cy_ota_agent_start(&net, &agent, NULL, &ota_ctx);
    }
}
