#include <string.h>
#include "cyhal.h"
#include "mbedtls/entropy.h"

static cyhal_trng_t trng;
static bool trng_ready;

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len, size_t *olen)
{
    (void)data;
    if (!trng_ready) {
        if (cyhal_trng_init(&trng) != CY_RSLT_SUCCESS) {
            *olen = 0;
            return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
        }
        trng_ready = true;
    }
    size_t i = 0;
    while (i < len) {
        uint32_t r = cyhal_trng_generate(&trng);
        size_t n = (len - i) < sizeof(r) ? (len - i) : sizeof(r);
        memcpy(&output[i], &r, n);
        i += n;
    }
    *olen = len;
    return 0;
}
