#ifndef SENSOR_TASK_H_
#define SENSOR_TASK_H_
#include <stdint.h>
void sensor_task(void *arg);
extern uint32_t g_publish_interval_ms;
#endif
