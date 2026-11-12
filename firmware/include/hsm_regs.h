/* hsm_regs.h - register map of security_monitor_top (MODE 2). Mirrors rtl/hsm_defs.svh;
 * tests/test_constants.py checks that both files agree. */
#ifndef HSM_REGS_H
#define HSM_REGS_H

#include <stdint.h>

#define HSM_NRULES       8u
#define HSM_NUM_OWNERS   3u
#define HSM_OWNER_ROOT   0x0Fu

/* Register offsets */
#define HSM_REG_CMD            0x00u
#define HSM_REG_STATUS         0x04u
#define HSM_REG_REQ_OWNER      0x08u
#define HSM_REG_CAND_VERSION   0x0Cu
#define HSM_REG_RULE_COUNT     0x10u
#define HSM_REG_ACTIVE_VERSION 0x14u
#define HSM_REG_PREV_VERSION   0x18u
#define HSM_REG_HW_INFO        0x1Cu
#define HSM_REG_RULE_BASE      0x40u
#define HSM_REG_RULE(slot, f)  (HSM_REG_RULE_BASE + 16u * (slot) + 4u * (f))   /* f: 0 start, 1 end, 2 attr */

/* ATTR word */
#define HSM_ATTR_VALID         (1u << 31)
#define HSM_ATTR_OWNER(o)      (((uint32_t)(o) & 0xFu) << 16)
#define HSM_ATTR_PRIV          (1u << 10)
#define HSM_ATTR_W             (1u << 9)
#define HSM_ATTR_R             (1u << 8)
#define HSM_ATTR_RSVD_MASK     0x7FF0F800u

/* STATUS fields */
#define HSM_ST_STATE(s)        ((s) & 0xFu)
#define HSM_ST_BUSY            (1u << 4)
#define HSM_ST_ACTIVE_BANK     (1u << 5)
#define HSM_ST_BOOT_WINDOW     (1u << 6)
#define HSM_ST_REVERT_AVAIL    (1u << 7)
#define HSM_ST_ERR(s)          (((s) >> 8) & 0xFFu)
#define HSM_ST_ERR_SLOT(s)     (((s) >> 16) & 0x7u)

enum hsm_state { HSM_S_IDLE = 0, HSM_S_RECEIVE = 1, HSM_S_VALIDATE = 2, HSM_S_READY = 3,
                 HSM_S_WAIT_IDLE = 4, HSM_S_SWITCH = 5, HSM_S_COMPLETE = 6,
                 HSM_S_ROLLBACK = 7, HSM_S_ERROR = 8 };

enum hsm_cmd { HSM_C_BEGIN = 1, HSM_C_VALIDATE = 2, HSM_C_ACTIVATE = 3, HSM_C_CONFIRM = 4,
               HSM_C_REVERT = 5, HSM_C_ABORT = 6, HSM_C_LOCK = 7 };

enum hsm_err { HSM_E_NONE = 0, HSM_E_AUTH = 1, HSM_E_COUNT = 2, HSM_E_MALFORMED = 3,
               HSM_E_OWNER_ID = 4, HSM_E_RANGE = 5, HSM_E_ADDR_ESCAPE = 6, HSM_E_PERM_ESC = 7,
               HSM_E_PRIV_FLOOR = 8, HSM_E_BURST_ESC = 9, HSM_E_FOREIGN = 10,
               HSM_E_OVERLAP = 11, HSM_E_VERSION = 12 };

#endif
