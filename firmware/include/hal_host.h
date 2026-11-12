/* hal_host.h - host-only controls of the register-level hardware model (hal_host.c). */
#ifndef HAL_HOST_H
#define HAL_HOST_H

#include <stdio.h>

void hal_host_reset(void);            /* hardware reset (power-on / power loss): volatile state lost */
void hal_host_set_log(FILE *f);       /* record every access for RTL replay (NULL = off) */
void hal_host_log_marker(unsigned id);

#endif
