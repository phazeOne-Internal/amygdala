#ifndef FREERTOS_CONFIG_H
#define FREERTOS_CONFIG_H
#include "cy_utils.h"
#define configUSE_PREEMPTION                    1
#define configCPU_CLOCK_HZ                      SystemCoreClock
#define configTICK_RATE_HZ                      1000u
#define configMAX_PRIORITIES                    7
#define configMINIMAL_STACK_SIZE                128
#define configTOTAL_HEAP_SIZE                   (64 * 1024)
#define configUSE_MUTEXES                       1
#define configUSE_TIMERS                        1
#define configTIMER_TASK_PRIORITY               (configMAX_PRIORITIES - 1)
#define configTIMER_QUEUE_LENGTH                10
#define configTIMER_TASK_STACK_DEPTH            256
#define configCHECK_FOR_STACK_OVERFLOW          2
#define configUSE_MALLOC_FAILED_HOOK            1
#define configPRIO_BITS                         3
#define configLIBRARY_LOWEST_INTERRUPT_PRIORITY 7
#define configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY 5
#define configKERNEL_INTERRUPT_PRIORITY         (configLIBRARY_LOWEST_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))
#define configMAX_SYSCALL_INTERRUPT_PRIORITY    (configLIBRARY_MAX_SYSCALL_INTERRUPT_PRIORITY << (8 - configPRIO_BITS))
extern void app_fatal_error(uint32_t reason);
#define configASSERT(x) do { if (!(x)) { app_fatal_error(0xA55E0000u | __LINE__); } } while (0)
#define INCLUDE_vTaskDelay                      1
#define INCLUDE_xTaskGetCurrentTaskHandle       1
#endif
