/* hal.h - register access used by the policy manager.
 * Backends: hal_mmio.c (memory-mapped hardware) and hal_host.c (native host model + MMIO log). */
#ifndef HAL_H
#define HAL_H

#include <stdint.h>

void     hal_write32(uint32_t off, uint32_t value);
uint32_t hal_read32(uint32_t off);
/* Wait until (reg & mask) == value. Returns 0 on success, -1 on timeout. */
int      hal_poll32(uint32_t off, uint32_t mask, uint32_t value, uint32_t max_polls);

#endif
