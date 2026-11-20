#include <string.h>
#include "cyhal.h"
#include "app.h"

#define CONFIG_MAGIC     (0x504C5547u)   /* "PLUG" */
#define CONFIG_ROW_ADDR  (0x100FFE00u)   /* last row of user flash */
#define FLASH_ROW_SIZE   (512u)

/* Config is only written when the user changes a setting (a few times a year),
 * so a single raw row is fine for wear. */
bool config_load(plug_config_t *cfg)
{
    memcpy(cfg, (const void *)CONFIG_ROW_ADDR, sizeof(*cfg));
    return cfg->magic == CONFIG_MAGIC;
}

bool config_save(const plug_config_t *cfg)
{
    static uint32_t row[FLASH_ROW_SIZE / 4];
    cyhal_flash_t flash;
    plug_config_t c = *cfg;
    c.magic = CONFIG_MAGIC;
    memset(row, 0xFF, sizeof(row));
    memcpy(row, &c, sizeof(c));
    if (cyhal_flash_init(&flash) != CY_RSLT_SUCCESS) {
        return false;
    }
    cyhal_flash_erase(&flash, CONFIG_ROW_ADDR);
    cy_rslt_t r = cyhal_flash_program(&flash, CONFIG_ROW_ADDR, row);
    cyhal_flash_free(&flash);
    return r == CY_RSLT_SUCCESS;
}
