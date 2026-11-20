/* Copyright (c) 2026 Acme Ltd. Proprietary. */
#include <linux/module.h>
#include <linux/gpio/consumer.h>
static int __init acme_led_init(void) { return 0; }
module_init(acme_led_init);
MODULE_LICENSE("Proprietary");
MODULE_AUTHOR("Acme Ltd");
