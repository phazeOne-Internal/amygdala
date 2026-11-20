/* Copyright (c) 2026 Acme Ltd. Proprietary and confidential. */
#include <readline/readline.h>
#include <openssl/ssl.h>
int main(void) { char *l = readline("acme> "); (void)l; return 0; }
