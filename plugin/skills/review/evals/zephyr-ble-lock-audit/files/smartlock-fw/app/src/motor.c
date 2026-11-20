#include <zephyr/kernel.h>
#include <zephyr/drivers/gpio.h>
#include <zephyr/logging/log.h>
#include "lock.h"

LOG_MODULE_REGISTER(motor, LOG_LEVEL_DBG);

static const struct gpio_dt_spec motor = GPIO_DT_SPEC_GET(DT_NODELABEL(motor_en), gpios);
static const struct gpio_dt_spec door  = GPIO_DT_SPEC_GET(DT_NODELABEL(door), gpios);
static struct gpio_callback door_cb;
static K_MUTEX_DEFINE(motor_lock_mtx);

bool g_door_open;

static void drive_motor(int ms)
{
    k_mutex_lock(&motor_lock_mtx, K_FOREVER);
    gpio_pin_set_dt(&motor, 1);
    k_msleep(ms);
    gpio_pin_set_dt(&motor, 0);
    k_mutex_unlock(&motor_lock_mtx);
}

void motor_unlock(void) { drive_motor(400); }
void motor_lock(void)   { drive_motor(400); }

static void door_changed(const struct device *dev, struct gpio_callback *cb, uint32_t pins)
{
    g_door_open = gpio_pin_get_dt(&door);
    LOG_DBG("door %s", g_door_open ? "open" : "closed");
    if (!g_door_open) {
        /* door closed: relock immediately */
        motor_lock();
    }
}

void motor_init(void)
{
    gpio_pin_configure_dt(&motor, GPIO_OUTPUT_INACTIVE);
    gpio_pin_configure_dt(&door, GPIO_INPUT);
    gpio_pin_interrupt_configure_dt(&door, GPIO_INT_EDGE_BOTH);
    gpio_init_callback(&door_cb, door_changed, BIT(door.pin));
    gpio_add_callback(door.port, &door_cb);
}
