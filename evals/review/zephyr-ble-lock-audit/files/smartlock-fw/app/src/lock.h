#ifndef LOCK_H
#define LOCK_H
#include <stdint.h>
#include <stdbool.h>
#define LOCK_CODE_LEN 16
int  lock_service_init(void);
void motor_init(void);
void motor_unlock(void);
void motor_lock(void);
int  storage_init(void);
int  storage_load_code(uint8_t *code, uint8_t *len);
int  storage_save_code(const uint8_t *code, uint8_t len);
extern bool g_door_open;
#endif
