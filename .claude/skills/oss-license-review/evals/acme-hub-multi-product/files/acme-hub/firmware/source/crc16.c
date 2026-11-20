/*
 * crc16.c - CRC16 (Modbus) routines
 * Copyright (C) 2003 Some Developer <dev@example.org>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */
#include <stdint.h>
uint16_t crc16_modbus(const uint8_t *d, unsigned n)
{
    uint16_t crc = 0xFFFF;
    while (n--) { crc ^= *d++; for (int i = 0; i < 8; i++) crc = (crc & 1) ? (crc >> 1) ^ 0xA001 : crc >> 1; }
    return crc;
}
