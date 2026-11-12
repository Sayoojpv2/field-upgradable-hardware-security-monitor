/* device_config.h - trusted device configuration (provisioned at manufacture, read-only).
 * The values are generated into build/gen/device_config.c by tools/policy_signer.py keygen. */
#ifndef DEVICE_CONFIG_H
#define DEVICE_CONFIG_H

#include <stdint.h>

#define HSM_NUM_KEYS 4u   /* index 0 CPU, 1 DMA, 2 DIAG, 3 provisioning ROOT */

extern const uint32_t hsm_device_id;
extern const uint8_t  hsm_trusted_keys[HSM_NUM_KEYS][32];

#endif
