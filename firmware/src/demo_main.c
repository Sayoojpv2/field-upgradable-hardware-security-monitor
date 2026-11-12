/* demo_main.c - end-to-end update workflow on the host hardware model.
 * usage: fw_demo <pkg_dir> [mmio_log_out]   (the log is replayed into the RTL by `make demo`) */
#include <setjmp.h>
#include <stdio.h>
#include <string.h>
#include "hal.h"
#include "hal_host.h"
#include "hsm_regs.h"
#include "policy_manager.h"

static const char *dir;
static pstore_t store;
static pm_t pm;
static jmp_buf power_jmp;

static size_t load(const char *name, uint8_t *buf, size_t cap)
{
    char path[512];
    snprintf(path, sizeof path, "%s/%s.hsmp", dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) return 0;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return n;
}

static void power_loss(void) { longjmp(power_jmp, 1); }
static void cut_after_activation(pm_fault_point_t fp) { if (fp == PM_FP_ACTIVATED) power_loss(); }

static pm_status_t step(const char *what, const char *name)
{
    uint8_t buf[PKG_MAX_SIZE + 16];
    size_t n = load(name, buf, sizeof buf);
    pm_status_t s = pm_install(&pm, buf, n);
    printf("  %-24s %-34s -> %-9s", name, what, pm_status_str(s));
    if (s == PM_ERR_HW_REJECT) printf(" hw=%s slot %u", hsm_err_str(pm.last_hw_err), pm.last_hw_slot);
    if (s == PM_ERR_PACKAGE) printf(" pkg=%s", pkg_err_str(pm.last_pkg_err));
    printf("  [active v%u]\n", (unsigned)pm_active_version());
    return s;
}

static void interrupted_step(const char *what, const char *name)
{
    if (setjmp(power_jmp) == 0) (void)step(what, name);   /* returns here via longjmp on power loss */
}

int main(int argc, char **argv)
{
    uint8_t buf[PKG_MAX_SIZE + 16];
    int bad = 0;
    if (argc < 2) { fprintf(stderr, "usage: %s <pkg_dir> [mmio_log]\n", argv[0]); return 2; }
    dir = argv[1];
    FILE *log = argc > 2 ? fopen(argv[2], "w") : NULL;
    hal_host_set_log(log);

    pstore_init_blank(&store);
    store.power_loss = power_loss;
    pm.store = &store;
    hal_host_reset();
    size_t n = load("policy_v1", buf, sizeof buf);
    printf("[1] factory provisioning + first boot\n");
    bad |= pm_provision(&pm, buf, n) != PM_OK;
    bad |= pm_boot(&pm) != PM_OK;
    printf("  policy_v1 restored through the boot window -> active v%u, window closed: %s\n",
           (unsigned)pm_active_version(), (hal_read32(HSM_REG_STATUS) & HSM_ST_BOOT_WINDOW) ? "no" : "yes");

    printf("[2] owner-signed updates (each validated in hardware, switched atomically)\n");
    bad |= step("scenario 1: DMA narrows its window", "policy_v2") != PM_OK;
    bad |= step("scenario 2: CPU privileges peripheral", "policy_v3") != PM_OK;

    printf("[3] power loss after the bank switch, before the store commit\n");
    pm.fault_hook = cut_after_activation;
    printf("  policy_v4                scenario 3: DMA lowers burst       -> power lost after ACTIVATE\n");
    interrupted_step("scenario 3: DMA lowers burst", "policy_v4");
    pm.fault_hook = NULL;
    hal_host_reset();
    bad |= pm_boot(&pm) != PM_OK;
    printf("  reboot -> active v%u (uncommitted v4 discarded)\n", (unsigned)pm_active_version());
    bad |= pm_active_version() != 3;
    bad |= step("scenario 3 retried", "policy_v4") != PM_OK;

    printf("[4] authorised owners trying to exceed their authority (must all be rejected)\n");
    const char *atk[][2] = {
        {"atk_dma_expand", "DMA widens beyond its envelope"}, {"atk_dma_burst", "DMA raises burst above max"},
        {"atk_diag_write", "DIAG grants itself write"},       {"atk_diag_unpriv", "DIAG drops privilege floor"},
        {"atk_dma_foreign_modify", "DMA edits a CPU rule"},   {"atk_dma_foreign_delete", "DMA deletes a CPU rule"},
        {"atk_dma_claim_slot", "DMA creates a DIAG rule"},    {"atk_dma_overlap", "DMA adds an overlapping rule"},
        {"neg_root_runtime", "ROOT-signed update at runtime"}, {"neg_wrong_key", "DMA policy, CPU signature"},
        {"neg_wrong_device", "package for another device"},   {"policy_v2", "replay of an old package"},
    };
    for (size_t i = 0; i < sizeof atk / sizeof atk[0]; i++) bad |= step(atk[i][1], atk[i][0]) == PM_OK;

    ps_meta_t m = {0};
    (void)pstore_committed(&store, &m);
    printf("final: active policy v%u, committed v%u\n", (unsigned)pm_active_version(), (unsigned)m.version);
    bad |= pm_active_version() != 4 || m.version != 4;
    if (log) fclose(log);
    printf("DEMO_RESULT %s\n", bad ? "FAIL" : "PASS");
    return bad;
}
