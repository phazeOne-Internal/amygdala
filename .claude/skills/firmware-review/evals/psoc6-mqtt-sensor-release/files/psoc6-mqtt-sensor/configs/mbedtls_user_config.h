#ifndef MBEDTLS_USER_CONFIG_H
#define MBEDTLS_USER_CONFIG_H
/* Entropy: hardware TRNG not wired up yet, use platform default */
#define MBEDTLS_NO_PLATFORM_ENTROPY
#undef  MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_SSL_MAX_CONTENT_LEN 4096
#endif
