/* policy_manager.c - install / boot-restore flows. Authenticity, versioning and persistence are
 * enforced here; authority (what the rules may contain) is enforced by the hardware validator. */
#include "policy_manager.h"
#include "hal.h"
#include "hsm_regs.h"

#define MAX_POLLS 100000u

static void fault_point(pm_t *pm, pm_fault_point_t fp)
{
    if (pm->fault_hook) pm->fault_hook(fp);
}

static int wait_not_busy(uint32_t *status)
{
    if (hal_poll32(HSM_REG_STATUS, HSM_ST_BUSY, 0, MAX_POLLS) != 0) return -1;
    *status = hal_read32(HSM_REG_STATUS);
    return 0;
}

static pm_status_t hw_reject(pm_t *pm, uint32_t st)
{
    pm->last_hw_err = (uint8_t)HSM_ST_ERR(st);
    pm->last_hw_slot = (uint8_t)HSM_ST_ERR_SLOT(st);
    if (HSM_ST_STATE(st) == HSM_S_ERROR) hal_write32(HSM_REG_CMD, HSM_C_ABORT);   /* back to IDLE */
    return PM_ERR_HW_REJECT;
}

/* Load the candidate into the inactive bank and let the hardware validate it. */
static pm_status_t hw_stage(pm_t *pm, const policy_t *p, uint8_t requester)
{
    uint32_t st;
    pm->last_hw_err = HSM_E_NONE;
    pm->last_hw_slot = 0;
    hal_write32(HSM_REG_REQ_OWNER, requester);
    hal_write32(HSM_REG_CAND_VERSION, p->version);
    hal_write32(HSM_REG_RULE_COUNT, p->rule_count);
    hal_write32(HSM_REG_CMD, HSM_C_BEGIN);
    st = hal_read32(HSM_REG_STATUS);
    if (HSM_ST_STATE(st) != HSM_S_RECEIVE) return hw_reject(pm, st);

    for (uint8_t i = 0; i < p->rule_count; i++) {
        const pkg_rule_t *r = &p->rules[i];
        if (i == p->rule_count / 2) fault_point(pm, PM_FP_RULES_PARTIAL);
        hal_write32(HSM_REG_RULE(r->slot, 0), r->start);
        hal_write32(HSM_REG_RULE(r->slot, 1), r->end);
        hal_write32(HSM_REG_RULE(r->slot, 2), pkg_rule_attr(r));
    }
    hal_write32(HSM_REG_CMD, HSM_C_VALIDATE);
    fault_point(pm, PM_FP_VALIDATING);
    if (wait_not_busy(&st) != 0) return PM_ERR_HW_STATE;
    if (HSM_ST_STATE(st) != HSM_S_READY) return hw_reject(pm, st);
    fault_point(pm, PM_FP_READY);
    return PM_OK;
}

/* Request the atomic bank switch; hardware waits for a transaction-idle boundary. */
static pm_status_t hw_activate(pm_t *pm)
{
    uint32_t st;
    hal_write32(HSM_REG_CMD, HSM_C_ACTIVATE);
    fault_point(pm, PM_FP_SWITCH_REQUESTED);
    if (wait_not_busy(&st) != 0) {
        /* Bus never went idle: WAIT_IDLE holds all new transactions, so give up the switch.
         * If the switch slipped in after the timeout, ABORT is ignored and we revert instead. */
        hal_write32(HSM_REG_CMD, HSM_C_ABORT);
        if (wait_not_busy(&st) == 0 && HSM_ST_STATE(st) == HSM_S_COMPLETE) {
            hal_write32(HSM_REG_CMD, HSM_C_REVERT);
            (void)wait_not_busy(&st);
        }
        return PM_ERR_HW_STATE;
    }
    if (HSM_ST_STATE(st) != HSM_S_COMPLETE) return PM_ERR_HW_STATE;
    return PM_OK;
}

pm_status_t pm_provision(pm_t *pm, const uint8_t *pkg, size_t len)
{
    policy_t p;
    pm->last_pkg_err = pkg_parse_verify(pkg, len, &p);
    if (pm->last_pkg_err != PKG_OK) return PM_ERR_PACKAGE;
    if (p.requester != HSM_OWNER_ROOT) return PM_ERR_AUTHORITY;
    if (p.version == 0) return PM_ERR_VERSION;      /* the hardware requires version > 0 at boot */
    if (pstore_write_slot(pm->store, 0, pkg, len) != 0 || pstore_commit(pm->store, 0, p.version, (uint32_t)len) != 0)
        return PM_ERR_STORE;
    pstore_raise_floor(pm->store, p.version);
    return PM_OK;
}

pm_status_t pm_boot(pm_t *pm)
{
    pm_status_t s = PM_ERR_NO_POLICY;
    ps_meta_t m;
    policy_t p;
    if (pstore_committed(pm->store, &m) == 0) {
        /* Re-authenticate: the store is outside the trust boundary of the monitor. */
        pm->last_pkg_err = pkg_parse_verify(pm->store->slot[m.slot], m.len, &p);
        /* Authentic is not enough: an older signed image still in the store must not come back. */
        if (pm->last_pkg_err == PKG_OK && p.version == m.version && m.version < pm->store->version_floor)
            s = PM_ERR_VERSION;
        else if (pm->last_pkg_err == PKG_OK && p.version == m.version) {
            s = hw_stage(pm, &p, HSM_OWNER_ROOT);     /* boot window: whole image, envelopes still checked */
            if (s == PM_OK) s = hw_activate(pm);
            if (s == PM_OK) {
                hal_write32(HSM_REG_CMD, HSM_C_CONFIRM);
                pstore_raise_floor(pm->store, m.version);   /* heals a loss between commit and raise */
            }
        }
    }
    hal_write32(HSM_REG_CMD, HSM_C_LOCK);            /* fail-secure: window closes even if restore failed */
    return s;
}

pm_status_t pm_install(pm_t *pm, const uint8_t *pkg, size_t len)
{
    policy_t p;
    ps_meta_t m;
    pm_status_t s;

    pm->last_pkg_err = pkg_parse_verify(pkg, len, &p);
    if (pm->last_pkg_err != PKG_OK) return PM_ERR_PACKAGE;
    if (p.requester == HSM_OWNER_ROOT) return PM_ERR_AUTHORITY;
    if (pstore_committed(pm->store, &m) != 0) return PM_ERR_NO_POLICY;
    if (p.version <= m.version || p.prev_version != m.version) return PM_ERR_VERSION;   /* anti-rollback, chain */
    if (hal_read32(HSM_REG_ACTIVE_VERSION) != m.version) return PM_ERR_HW_STATE;

    uint32_t pending = m.slot ^ 1u;                 /* never overwrite the committed image */
    if (pstore_write_slot(pm->store, pending, pkg, len) != 0) return PM_ERR_STORE;
    fault_point(pm, PM_FP_PACKAGE_STORED);

    if ((s = hw_stage(pm, &p, p.requester)) != PM_OK) return s;
    if ((s = hw_activate(pm)) != PM_OK) return s;
    fault_point(pm, PM_FP_ACTIVATED);

    if (pstore_commit(pm->store, pending, p.version, (uint32_t)len) != 0) {
        uint32_t st;
        hal_write32(HSM_REG_CMD, HSM_C_REVERT);    /* previous policy is still in the other bank */
        (void)wait_not_busy(&st);
        return PM_ERR_STORE;
    }
    pstore_raise_floor(pm->store, p.version);
    fault_point(pm, PM_FP_COMMITTED);
    hal_write32(HSM_REG_CMD, HSM_C_CONFIRM);
    return PM_OK;
}

uint32_t pm_active_version(void) { return hal_read32(HSM_REG_ACTIVE_VERSION); }

const char *pm_status_str(pm_status_t s)
{
    static const char *t[] = {"OK", "PACKAGE", "AUTHORITY", "VERSION", "HW_REJECT", "HW_STATE", "STORE", "NO_POLICY"};
    return (unsigned)s < sizeof t / sizeof t[0] ? t[s] : "?";
}

const char *hsm_err_str(uint8_t e)
{
    static const char *t[] = {"NONE", "AUTH", "COUNT", "MALFORMED", "OWNER_ID", "RANGE", "ADDR_ESCAPE",
                              "PERM_ESC", "PRIV_FLOOR", "BURST_ESC", "FOREIGN", "OVERLAP", "VERSION"};
    return e < sizeof t / sizeof t[0] ? t[e] : "?";
}
