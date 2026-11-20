#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H
#define MBEDTLS_ENTROPY_HARDWARE_ALT          /* mbedtls_hardware_poll() in trng_port.c, PSoC 6 TRNG */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_SSL_MAX_CONTENT_LEN 4096
#endif
