/* test_firmware.c - native tests: crypto interoperability, package-parsing safety, owner-bounded
 * installs on the host hardware model, fault injection and recovery.
 * usage: test_firmware <pkg_dir> [mmio_log_out] [fault_json_out] */
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "hal.h"
#include "hal_host.h"
#include "hsm_regs.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"
#include "policy_manager.h"

static int checks, failures;
#define CHECK(c) do { checks++; if (!(c)) { failures++; printf("FAIL %s:%d: %s\n", __FILE__, __LINE__, #c); } } while (0)
#define CHECK_EQ(a, b) do { long _a = (long)(a), _b = (long)(b); checks++; if (_a != _b) { failures++; \
    printf("FAIL %s:%d: %s == %ld, expected %ld\n", __FILE__, __LINE__, #a, _a, _b); } } while (0)

typedef struct { uint8_t b[PKG_MAX_SIZE + 64]; size_t n; } blob_t;
static const char *pkg_dir;

static blob_t load(const char *name)
{
    blob_t x = {{0}, 0};
    char path[512];
    snprintf(path, sizeof path, "%s/%s.hsmp", pkg_dir, name);
    FILE *f = fopen(path, "rb");
    if (!f) { printf("missing package %s\n", path); exit(2); }
    x.n = fread(x.b, 1, sizeof x.b, f);
    fclose(f);
    return x;
}

static FILE *cur_log;
static FILE *hal_host_set_log_tmp(FILE *f) { FILE *o = cur_log; hal_host_set_log(f); return o; }

static pstore_t store;
static pm_t pm;
static jmp_buf power_jmp;
static pm_fault_point_t armed;

static void power_loss(void) { longjmp(power_jmp, 1); }
static void hook(pm_fault_point_t fp) { if (fp == armed) power_loss(); }

static pm_status_t install(const char *name) { blob_t x = load(name); return pm_install(&pm, x.b, x.n); }

/* Install with a power loss armed; returns 1 if the power loss happened. Keeping setjmp in its
 * own function means no caller local can be clobbered by longjmp. */
static int install_interrupted(const char *name)
{
    if (setjmp(power_jmp) == 0) { (void)install(name); return 0; }
    return 1;
}

/* Fresh device: blank store, provision the factory image, power on. */
static void fresh_device(void)
{
    pstore_init_blank(&store);
    store.power_loss = power_loss;
    memset(&pm, 0, sizeof pm);
    pm.store = &store;
    hal_host_reset();
    blob_t v1 = load("policy_v1");
    CHECK_EQ(pm_provision(&pm, v1.b, v1.n), PM_OK);
    CHECK_EQ(pm_boot(&pm), PM_OK);
    CHECK_EQ(pm_active_version(), 1);
}

static uint32_t committed_version(void)
{
    ps_meta_t m;
    return pstore_committed(&store, &m) == 0 ? m.version : 0;
}

/* ----------------------------------------------------------------------------------------- */
static void test_crypto_vectors(void)
{
    /* RFC 8032 section 7.1, TEST 1 (empty message) */
    static const uint8_t pk[32] = {0xd7,0x5a,0x98,0x01,0x82,0xb1,0x0a,0xb7,0xd5,0x4b,0xfe,0xd3,0xc9,0x64,0x07,0x3a,
                                   0x0e,0xe1,0x72,0xf3,0xda,0xa6,0x23,0x25,0xaf,0x02,0x1a,0x68,0xf7,0x07,0x51,0x1a};
    static const uint8_t sig[64] = {0xe5,0x56,0x43,0x00,0xc3,0x60,0xac,0x72,0x90,0x86,0xe2,0xcc,0x80,0x6e,0x82,0x8a,
                                    0x84,0x87,0x7f,0x1e,0xb8,0xe5,0xd9,0x74,0xd8,0x73,0xe0,0x65,0x22,0x49,0x01,0x55,
                                    0x5f,0xb8,0x82,0x15,0x90,0xa3,0x3b,0xac,0xc6,0x1e,0x39,0x70,0x1c,0xf9,0xb4,0x6b,
                                    0xd2,0x5b,0xf5,0xf0,0x59,0x5b,0xbe,0x24,0x65,0x51,0x41,0x43,0x8e,0x7a,0x10,0x0b};
    uint8_t bad[64];
    CHECK_EQ(crypto_ed25519_check(sig, pk, (const uint8_t *)"", 0), 0);
    memcpy(bad, sig, 64); bad[0] ^= 1;
    CHECK(crypto_ed25519_check(bad, pk, (const uint8_t *)"", 0) != 0);
}

static void test_packages(void)
{
    policy_t p;
    const char *ok[] = {"policy_v1", "policy_v2", "policy_v3", "policy_v4", "atk_dma_expand", "cand_v5_dma_reopen"};
    for (size_t i = 0; i < sizeof ok / sizeof ok[0]; i++) {          /* Python-signed, C-verified */
        blob_t x = load(ok[i]);
        CHECK_EQ(pkg_parse_verify(x.b, x.n, &p), PKG_OK);
    }
    blob_t v3 = load("policy_v3");
    CHECK_EQ(pkg_parse_verify(v3.b, v3.n, &p), PKG_OK);
    CHECK_EQ(p.requester, 0); CHECK_EQ(p.version, 3); CHECK_EQ(p.prev_version, 2); CHECK_EQ(p.rule_count, 5);
    CHECK_EQ(p.rules[4].slot, 4); CHECK_EQ(p.rules[4].start, 0xF000); CHECK_EQ(pkg_rule_attr(&p.rules[4]), 0x80000704);

    struct { const char *name; pkg_err_t want; } neg[] = {
        {"neg_wrong_key", PKG_ERR_SIGNATURE}, {"neg_wrong_device", PKG_ERR_DEVICE},
        {"neg_unknown_owner", PKG_ERR_OWNER}, {"neg_count9", PKG_ERR_LENGTH},
        {"neg_dup_slot", PKG_ERR_RULE},       {"neg_bad_flags", PKG_ERR_RULE},
    };
    for (size_t i = 0; i < sizeof neg / sizeof neg[0]; i++) {
        blob_t x = load(neg[i].name);
        pkg_err_t e = pkg_parse_verify(x.b, x.n, &p);
        if (e != neg[i].want) printf("  %s -> %s\n", neg[i].name, pkg_err_str(e));
        CHECK_EQ(e, neg[i].want);
    }

    blob_t x = load("policy_v2"), y;
    y = x; y.b[0] ^= 0xFF;                  CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_MAGIC);
    y = x; y.b[16] ^= 0x01;                 CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_SIGNATURE); /* version */
    /* Owner relabel: a valid DMA-signed package presented as CPU or DIAG must fail, because the
     * requester byte is signed and selects the verifying key from device configuration. */
    CHECK_EQ(x.b[12], 1);
    y = x; y.b[12] = 0;                     CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_SIGNATURE);
    y = x; y.b[12] = 2;                     CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_SIGNATURE);
    y = x; y.b[12] = HSM_OWNER_ROOT;        CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_SIGNATURE);
    y = x; y.b[70] ^= 0x01;                 CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_SIGNATURE); /* signature */
    y = x; y.b[PKG_HDR_SIZE + 4] ^= 0x01;   CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_DIGEST);    /* payload */
    y = x; y.n += 1;                        CHECK_EQ(pkg_parse_verify(y.b, y.n, &p), PKG_ERR_LENGTH);
    CHECK_EQ(pkg_parse_verify(NULL, 0, &p), PKG_ERR_TRUNCATED);
    int trunc_ok = 1;
    for (size_t n = 0; n < x.n; n++) trunc_ok &= pkg_parse_verify(x.b, n, &p) == PKG_ERR_TRUNCATED;
    CHECK(trunc_ok);

    /* Deterministic corruption fuzz: no mutated package may ever verify. */
    uint32_t s = 0x12345678u;
    int accepted = 0;
    for (int it = 0; it < 3000; it++) {
        y = x;
        int flips = 1 + (int)(s % 4u);
        for (int f = 0; f < flips; f++) {
            s ^= s << 13; s ^= s >> 17; s ^= s << 5;
            y.b[s % x.n] ^= (uint8_t)(1u << ((s >> 8) % 8u));
        }
        if (memcmp(x.b, y.b, x.n) != 0 && pkg_parse_verify(y.b, y.n, &p) == PKG_OK) accepted++;
    }
    CHECK_EQ(accepted, 0);
}

/* Expected hardware outcome per attack package, computed by the Python reference model. */
static void test_owner_bounded_updates(void)
{
    fresh_device();
    uint32_t st = hal_read32(HSM_REG_STATUS);
    CHECK((st & HSM_ST_BOOT_WINDOW) == 0);                 /* boot window closed after restore */
    CHECK_EQ(hal_read32(HSM_REG_HW_INFO), 0x48020308);

    blob_t v2 = load("policy_v2");
    CHECK_EQ(pm_provision(&pm, v2.b, v2.n), PM_ERR_AUTHORITY);  /* owners cannot use the factory path */
    CHECK_EQ(install("policy_v1"), PM_ERR_AUTHORITY);          /* ROOT cannot update at runtime */
    CHECK_EQ(install("policy_v3"), PM_ERR_VERSION);            /* wrong predecessor */
    CHECK_EQ(install("policy_v2"), PM_OK);  CHECK_EQ(pm_active_version(), 2);
    CHECK_EQ(install("policy_v2"), PM_ERR_VERSION);            /* replay */
    CHECK_EQ(install("policy_v3"), PM_OK);  CHECK_EQ(pm_active_version(), 3);
    CHECK_EQ(install("policy_v4"), PM_OK);  CHECK_EQ(pm_active_version(), 4);
    CHECK_EQ(install("policy_v3"), PM_ERR_VERSION);            /* older version */
    CHECK_EQ(hal_read32(HSM_REG_PREV_VERSION), 3);

    char path[512], name[64];
    unsigned err, slot, n = 0;
    snprintf(path, sizeof path, "%s/expected_hw.txt", pkg_dir);
    FILE *f = fopen(path, "r");
    CHECK(f != NULL);
    while (f && fscanf(f, "%63s %u %u", name, &err, &slot) == 3) {
        uint32_t act_sel = hal_read32(HSM_REG_STATUS) & HSM_ST_ACTIVE_BANK;
        pm_status_t s = install(name);
        if (s != PM_ERR_HW_REJECT || pm.last_hw_err != err || pm.last_hw_slot != slot)
            printf("  %s -> %s hw=%s slot %u (expected %s slot %u)\n", name, pm_status_str(s),
                   hsm_err_str(pm.last_hw_err), pm.last_hw_slot, hsm_err_str((uint8_t)err), slot);
        CHECK_EQ(s, PM_ERR_HW_REJECT);
        CHECK_EQ(pm.last_hw_err, err);
        CHECK_EQ(pm.last_hw_slot, slot);
        CHECK_EQ(pm_active_version(), 4);                       /* active policy untouched */
        CHECK_EQ(hal_read32(HSM_REG_STATUS) & HSM_ST_ACTIVE_BANK, act_sel);
        CHECK_EQ(HSM_ST_STATE(hal_read32(HSM_REG_STATUS)), HSM_S_IDLE);
        CHECK_EQ(committed_version(), 4);
        n++;
    }
    if (f) fclose(f);
    CHECK_EQ(n, 8);
    CHECK_EQ(install("neg_root_runtime"), PM_ERR_AUTHORITY);
    CHECK_EQ(install("neg_wrong_key"), PM_ERR_PACKAGE); CHECK_EQ(pm.last_pkg_err, PKG_ERR_SIGNATURE);
    CHECK_EQ(pm_active_version(), 4);

    /* Store failure after activation: hardware reverts to the retained previous bank. */
    store.fail_commit = 1;
    CHECK_EQ(install("cand_v5_dma_reopen"), PM_ERR_STORE);
    store.fail_commit = 0;
    CHECK_EQ(pm_active_version(), 4);
    CHECK_EQ(committed_version(), 4);
    CHECK_EQ(HSM_ST_STATE(hal_read32(HSM_REG_STATUS)), HSM_S_IDLE);
}

/* ----------------------------------------------------------------------------------------- */
static const char *fp_name[PM_FP_COUNT] = {"none", "package_stored", "rules_partial", "validating",
                                           "ready", "switch_requested", "activated", "committed"};
static FILE *fault_json;

static void reboot(void)
{
    pm.fault_hook = NULL;
    store.fault_after_bytes = -1;
    hal_host_reset();
    (void)pm_boot(&pm);
}

static void test_fault_points(void)
{
    for (int fp = PM_FP_PACKAGE_STORED; fp < PM_FP_COUNT; fp++) {
        fresh_device();
        CHECK_EQ(install("policy_v2"), PM_OK);
        armed = (pm_fault_point_t)fp;
        pm.fault_hook = hook;
        int interrupted = install_interrupted("policy_v3");
        reboot();
        uint32_t want = fp == PM_FP_COMMITTED ? 3u : 2u;   /* committed state wins, never a partial one */
        uint32_t got = pm_active_version();
        CHECK(interrupted);
        CHECK_EQ(got, want);
        CHECK_EQ(committed_version(), want);
        CHECK((hal_read32(HSM_REG_STATUS) & HSM_ST_BOOT_WINDOW) == 0);
        int retry_ok = want == 3 || install("policy_v3") == PM_OK;  /* device stays updatable */
        CHECK(retry_ok);
        if (fault_json)
            fprintf(fault_json, "%s{\"fault_point\":\"%s\",\"expected\":%u,\"restored\":%u,\"retry_ok\":%d}",
                    fp == PM_FP_PACKAGE_STORED ? "" : ",", fp_name[fp], want, got, retry_ok);
    }
}

static void test_torn_writes(int *runs, int *ok)
{
    blob_t v3 = load("policy_v3");
    size_t total = v3.n + sizeof(ps_meta_t);
    for (size_t n = 0; n <= total; n++) {
        fresh_device();
        CHECK_EQ(install("policy_v2"), PM_OK);
        store.fault_after_bytes = (long)n;
        (void)install_interrupted("policy_v3");
        reboot();
        uint32_t want = n == total ? 3u : 2u;              /* only a fully written commit counts */
        int good = pm_active_version() == want && committed_version() == want;
        CHECK(good);
        (*runs)++; *ok += good;
    }
}

static void test_store_corruption(void)
{
    fresh_device();
    CHECK_EQ(install("policy_v2"), PM_OK);
    ps_meta_t m;
    CHECK_EQ(pstore_committed(&store, &m), 0);
    store.slot[m.slot][PKG_HDR_SIZE + 3] ^= 0x40;          /* bit flip in the committed image */
    hal_host_reset();
    CHECK_EQ(pm_boot(&pm), PM_ERR_NO_POLICY);
    CHECK_EQ(pm.last_pkg_err, PKG_ERR_DIGEST);
    CHECK_EQ(pm_active_version(), 0);                        /* fail-secure: default deny */
    CHECK((hal_read32(HSM_REG_STATUS) & HSM_ST_BOOT_WINDOW) == 0);

    pstore_init_blank(&store);                               /* never provisioned */
    hal_host_reset();
    CHECK_EQ(pm_boot(&pm), PM_ERR_NO_POLICY);
    CHECK_EQ(pm_active_version(), 0);
    CHECK_EQ(install("policy_v2"), PM_ERR_NO_POLICY);
}

/* Storage rollback: an attacker who can write the store re-points the metadata at the older,
 * still correctly signed image. Signature checks alone would restore it; the counter must not. */
static void test_storage_rollback(void)
{
    fresh_device();
    CHECK_EQ(install("policy_v2"), PM_OK);
    CHECK_EQ(install("policy_v3"), PM_OK);
    CHECK_EQ(store.version_floor, 3);
    ps_meta_t m, f;
    policy_t p;
    CHECK_EQ(pstore_committed(&store, &m), 0);
    f = m;
    f.slot = m.slot ^ 1u;                          /* the other slot still holds signed v2 */
    f.version = 2;
    f.len = (uint32_t)load("policy_v2").n;
    f.seq = m.seq + 1u;
    f.crc = pstore_crc32((const uint8_t *)&f, 5 * sizeof(uint32_t));
    store.meta[0] = store.meta[1] = f;
    CHECK_EQ(pkg_parse_verify(store.slot[f.slot], f.len, &p), PKG_OK);   /* the forged target is authentic */
    hal_host_reset();
    CHECK_EQ(pm_boot(&pm), PM_ERR_VERSION);
    CHECK_EQ(pm_active_version(), 0);                                    /* fail-secure, not v2 */
    CHECK((hal_read32(HSM_REG_STATUS) & HSM_ST_BOOT_WINDOW) == 0);
}

/* Bus never idle during ACTIVATE: the firmware must not leave the controller holding traffic. */
static void test_activation_timeout(void)
{
    fresh_device();
    CHECK_EQ(install("policy_v2"), PM_OK);
    FILE *log = hal_host_set_log_tmp(NULL);       /* the RTL replay bench always has an idle bus */
    hal_host_set_bus_idle(0);
    CHECK_EQ(install("policy_v3"), PM_ERR_HW_STATE);
    uint32_t st = hal_read32(HSM_REG_STATUS);
    CHECK_EQ(HSM_ST_STATE(st), HSM_S_IDLE);        /* WAIT_IDLE released: transactions flow again */
    CHECK((st & HSM_ST_BUSY) == 0);
    CHECK_EQ(pm_active_version(), 2);
    CHECK_EQ(committed_version(), 2);
    hal_host_set_bus_idle(1);
    hal_host_set_log(log);
    CHECK_EQ(install("policy_v3"), PM_OK);        /* the update can simply be retried */
    CHECK_EQ(pm_active_version(), 3);
}

int main(int argc, char **argv)
{
    if (argc < 2) { fprintf(stderr, "usage: %s <pkg_dir> [mmio_log] [fault_json]\n", argv[0]); return 2; }
    pkg_dir = argv[1];
    FILE *log = argc > 2 ? fopen(argv[2], "w") : NULL;
    hal_host_set_log(log);
    fault_json = argc > 3 ? fopen(argv[3], "w") : NULL;
    int torn_runs = 0, torn_ok = 0;

    test_crypto_vectors();
    test_packages();
    hal_host_log_marker(1); test_owner_bounded_updates();
    if (fault_json) fprintf(fault_json, "{\"fault_points\":[");
    hal_host_log_marker(2); test_fault_points();
    hal_host_log_marker(3); test_torn_writes(&torn_runs, &torn_ok);
    hal_host_log_marker(4); test_store_corruption();
    hal_host_log_marker(5); test_storage_rollback();
    hal_host_log_marker(6); test_activation_timeout();
    if (fault_json) {
        fprintf(fault_json, "],\"torn_write_runs\":%d,\"torn_write_recovered\":%d}\n", torn_runs, torn_ok);
        fclose(fault_json);
    }
    if (log) fclose(log);
    printf("torn-write sweep: %d/%d interrupted installs recovered to the committed policy\n", torn_ok, torn_runs);
    printf("C_TEST_RESULT checks=%d failures=%d %s\n", checks, failures, failures ? "FAIL" : "PASS");
    return failures ? 1 : 0;
}
