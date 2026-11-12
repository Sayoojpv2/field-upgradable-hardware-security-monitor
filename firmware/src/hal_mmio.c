/* hal_mmio.c - memory-mapped backend for a real SoC integration (built for RV32 by
 * `make firmware-size`; not executed in this simulation-only project). */
#include <stdint.h>
#include "hal.h"

#ifndef HSM_BASE_ADDR
#define HSM_BASE_ADDR 0x40010000u   /* placeholder: set by the SoC memory map */
#endif

#define HSM_REG(off) (*(volatile uint32_t *)(uintptr_t)(HSM_BASE_ADDR + (off)))

void hal_write32(uint32_t off, uint32_t value) { HSM_REG(off) = value; }

uint32_t hal_read32(uint32_t off) { return HSM_REG(off); }

int hal_poll32(uint32_t off, uint32_t mask, uint32_t value, uint32_t max_polls)
{
    while (max_polls--)
        if ((HSM_REG(off) & mask) == value) return 0;
    return -1;
}
