/* policy_manager.h - authenticated policy installation, boot restore and recovery. */
#ifndef POLICY_MANAGER_H
#define POLICY_MANAGER_H

#include <stddef.h>
#include <stdint.h>
#include "policy_pkg.h"
#include "pstore.h"

typedef enum {
    PM_OK = 0,
    PM_ERR_PACKAGE,        /* parse / authentication failed, see last_pkg_err */
    PM_ERR_AUTHORITY,      /* ROOT packages only via pm_provision; owner packages only via pm_install */
    PM_ERR_VERSION,        /* not newer than the committed version, or wrong predecessor */
    PM_ERR_HW_REJECT,      /* hardware validator rejected the candidate, see last_hw_err/slot */
    PM_ERR_HW_STATE,       /* hardware not in the expected state / timeout */
    PM_ERR_STORE,          /* persistent store write failed (update reverted) */
    PM_ERR_NO_POLICY       /* nothing committed or committed image invalid: monitor stays default-deny */
} pm_status_t;

/* Points where tests inject a power loss. */
typedef enum {
    PM_FP_NONE = 0,
    PM_FP_PACKAGE_STORED,    /* candidate package written to the pending store slot */
    PM_FP_RULES_PARTIAL,     /* half of the candidate rules loaded into the inactive bank */
    PM_FP_VALIDATING,        /* VALIDATE issued */
    PM_FP_READY,             /* hardware validated the candidate */
    PM_FP_SWITCH_REQUESTED,  /* ACTIVATE issued */
    PM_FP_ACTIVATED,         /* bank switched, not yet committed to the store */
    PM_FP_COMMITTED,         /* committed to the store, CONFIRM not yet issued */
    PM_FP_COUNT
} pm_fault_point_t;

typedef struct {
    pstore_t  *store;
    void     (*fault_hook)(pm_fault_point_t fp);   /* NULL in production */
    pkg_err_t  last_pkg_err;
    uint8_t    last_hw_err, last_hw_slot;
} pm_t;

/* Factory provisioning: store a ROOT-signed image as the committed policy. */
pm_status_t pm_provision(pm_t *pm, const uint8_t *pkg, size_t len);
/* After reset: re-authenticate the committed image and restore it through the boot window. */
pm_status_t pm_boot(pm_t *pm);
/* Runtime update by a component owner. */
pm_status_t pm_install(pm_t *pm, const uint8_t *pkg, size_t len);

uint32_t    pm_active_version(void);
const char *pm_status_str(pm_status_t s);
const char *hsm_err_str(uint8_t e);

#endif
