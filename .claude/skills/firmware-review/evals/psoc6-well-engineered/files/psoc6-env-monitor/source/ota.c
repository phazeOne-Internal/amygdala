/* OTA via Infineon ota-update + MCUboot (swap mode, signed images, downgrade prevention
 * enabled in the bootloader build). The new image boots in test mode and is only
 * confirmed after it has reconnected to the cloud (see ota_confirm_if_healthy). */
#include <string.h>
#include "cy_ota_api.h"
#include "app.h"

static cy_ota_context_ptr ota_ctx;

static cy_ota_callback_results_t ota_cb(cy_ota_cb_struct_t *cb)
{
    (void)cb;
    return CY_OTA_CB_RSLT_OTA_CONTINUE;
}

int ota_start(void)
{
    cy_ota_network_params_t net = { 0 };
    net.initial_connection  = CY_OTA_CONNECTION_MQTT;
    net.use_get_job_flow    = CY_OTA_JOB_FLOW;          /* job document from our backend, over the TLS MQTT session */
    net.mqtt.broker.host.name = "iot.acme.example";
    net.mqtt.broker.host.port = 8883;
    net.mqtt.credentials.root_ca_verify_mode = CY_AWS_ROOTCA_VERIFY_REQUIRED;

    cy_ota_agent_params_t agent = { 0 };
    agent.cb_func                = ota_cb;
    agent.reboot_upon_completion = 1;
    agent.validate_after_reboot  = 1;                   /* test-boot, confirm after health check */

    return cy_ota_agent_start(&net, &agent, NULL, &ota_ctx) == CY_RSLT_SUCCESS ? 0 : -1;
}

void ota_confirm_if_healthy(bool cloud_connected)
{
    if (cloud_connected) {
        (void)cy_ota_validated();
    }
}
