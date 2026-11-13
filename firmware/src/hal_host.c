/* hal_host.c - native host backend: a register-level model of security_monitor_top (MODE 2).
 *
 * The model mirrors the RTL register semantics (same state machine, same validation order,
 * same STATUS word) but completes VALIDATE/ACTIVATE/REVERT instantly. Every access can be
 * logged; tb/tb_mmio_replay.sv replays the log into the RTL and checks every read-back, so
 * any disagreement between this model and the RTL fails `make sim-rtl`.
 * Log line: "<op> <addr> <data> <mask>" in hex; op 1 write, 2 read, 3 poll, 4 reset, 5 marker.
 */
#include <stdint.h>
#include <stdio.h>
#include "hal.h"
#include "hal_host.h"
#include "hsm_regs.h"

typedef struct { uint8_t valid, owner; uint32_t start, end; uint16_t attr; } mrule_t;

static struct {
    mrule_t  bank[2][HSM_NRULES];
    unsigned sel, state, req, count, boot_window, malformed, last_err, err_slot;
    uint32_t cand_ver, act_ver, prev_ver;
} m;
static FILE *log_fp;
static unsigned bus_idle = 1;

/* Mirror of the immutable authority table in rtl/hsm_defs.svh */
static const struct { uint32_t lo, hi; unsigned r, w, burst, pf; } env[HSM_NUM_OWNERS] = {
    {0x00000000u, 0x0000FFFFu, 1, 1, 16, 0},
    {0x10000000u, 0x1000FFFFu, 1, 1, 64, 0},
    {0x20000000u, 0x2000FFFFu, 1, 0, 4, 1},
};

void hal_host_set_log(FILE *f) { log_fp = f; }
void hal_host_set_bus_idle(int idle) { bus_idle = idle != 0; }
void hal_host_log_marker(unsigned id) { if (log_fp) fprintf(log_fp, "5 %08X 00000000 00000000\n", id); }

void hal_host_reset(void)
{
    for (int b = 0; b < 2; b++)
        for (unsigned k = 0; k < HSM_NRULES; k++) m.bank[b][k].valid = 0;   /* payload is not reset, like the RTL */
    m.sel = 0; m.state = HSM_S_IDLE; m.req = 0; m.count = 0; m.boot_window = 1;
    m.malformed = 0; m.last_err = 0; m.err_slot = 0; m.cand_ver = m.act_ver = m.prev_ver = 0;
    if (log_fp) fprintf(log_fp, "4 00000000 00000000 00000000\n");
}

static uint32_t status(void)
{
    unsigned busy = (m.state == HSM_S_WAIT_IDLE);   /* the only state the model can linger in */
    return m.state | (busy << 4) | (m.sel << 5) | (m.boot_window << 6) |
           ((unsigned)(m.state == HSM_S_COMPLETE) << 7) | (m.last_err << 8) | (m.err_slot << 16);
}

static int same(const mrule_t *a, const mrule_t *c)
{
    return a->owner == c->owner && a->start == c->start && a->end == c->end && a->attr == c->attr;
}

static unsigned validate(unsigned *slot)
{
    const mrule_t *c = m.bank[m.sel ^ 1u], *a = m.bank[m.sel];
    unsigned root = (m.req == HSM_OWNER_ROOT), cnt = 0;
    *slot = 0;
    if (m.malformed) return HSM_E_MALFORMED;
    if (m.cand_ver <= m.act_ver) return HSM_E_VERSION;
    for (unsigned i = 0; i < HSM_NRULES; i++) {
        unsigned foreign = !root && ((a[i].valid && a[i].owner != m.req) || (c[i].valid && c[i].owner != m.req));
        *slot = i;
        if (foreign && !(a[i].valid && c[i].valid && same(&a[i], &c[i]))) return HSM_E_FOREIGN;
        if (c[i].valid) {
            unsigned o = c[i].owner, burst = c[i].attr & 0xFFu;
            unsigned r = (c[i].attr >> 8) & 1u, w = (c[i].attr >> 9) & 1u, p = (c[i].attr >> 10) & 1u;
            if (o >= HSM_NUM_OWNERS) return HSM_E_OWNER_ID;
            if (burst == 0) return HSM_E_MALFORMED;
            if (c[i].start > c[i].end) return HSM_E_RANGE;
            if (c[i].start < env[o].lo || c[i].end > env[o].hi) return HSM_E_ADDR_ESCAPE;
            if ((r && !env[o].r) || (w && !env[o].w)) return HSM_E_PERM_ESC;
            if (env[o].pf && !p) return HSM_E_PRIV_FLOOR;
            if (burst > env[o].burst) return HSM_E_BURST_ESC;
        }
        cnt += c[i].valid;
    }
    for (unsigned i = 0; i < HSM_NRULES; i++)
        for (unsigned j = i + 1; j < HSM_NRULES; j++)
            if (c[i].valid && c[j].valid && c[i].start <= c[j].end && c[j].start <= c[i].end) {
                *slot = j;
                return HSM_E_OVERLAP;
            }
    *slot = 0;
    return cnt != m.count ? HSM_E_COUNT : HSM_E_NONE;
}

static void command(unsigned c)
{
    unsigned slot, e;
    switch (m.state) {
    case HSM_S_IDLE:
    case HSM_S_ERROR:
        if (c == HSM_C_BEGIN) {
            unsigned req_ok = m.req < HSM_NUM_OWNERS || (m.req == HSM_OWNER_ROOT && m.boot_window);
            m.err_slot = 0;
            if (!req_ok) { m.state = HSM_S_ERROR; m.last_err = HSM_E_AUTH; }
            else if (m.count == 0 || m.count > HSM_NRULES) { m.state = HSM_S_ERROR; m.last_err = HSM_E_COUNT; }
            else {
                for (unsigned k = 0; k < HSM_NRULES; k++) m.bank[m.sel ^ 1u][k].valid = 0;
                m.state = HSM_S_RECEIVE; m.last_err = HSM_E_NONE; m.malformed = 0;
            }
        } else if (c == HSM_C_ABORT && m.state == HSM_S_ERROR) m.state = HSM_S_IDLE;
        else if (c == HSM_C_LOCK && m.state == HSM_S_IDLE) m.boot_window = 0;
        break;
    case HSM_S_RECEIVE:
        if (c == HSM_C_VALIDATE) {
            e = validate(&slot);
            if (e == HSM_E_NONE) m.state = HSM_S_READY;
            else { m.state = HSM_S_ERROR; m.last_err = e; m.err_slot = slot; }
        } else if (c == HSM_C_ABORT) m.state = HSM_S_IDLE;
        break;
    case HSM_S_READY:
        if (c == HSM_C_ACTIVATE && !bus_idle) m.state = HSM_S_WAIT_IDLE;
        else if (c == HSM_C_ACTIVATE) {     /* idle bus: WAIT_IDLE and SWITCH collapse */
            m.prev_ver = m.act_ver; m.act_ver = m.cand_ver; m.boot_window = 0;
            m.sel ^= 1u; m.state = HSM_S_COMPLETE;
        } else if (c == HSM_C_ABORT) m.state = HSM_S_IDLE;
        break;
    case HSM_S_WAIT_IDLE:
        if (c == HSM_C_ABORT) m.state = HSM_S_IDLE;
        break;
    case HSM_S_COMPLETE:
        if (c == HSM_C_CONFIRM) m.state = HSM_S_IDLE;
        else if (c == HSM_C_REVERT) { m.sel ^= 1u; m.act_ver = m.prev_ver; m.state = HSM_S_IDLE; }
        break;
    default:
        break;
    }
}

static void model_write(uint32_t off, uint32_t v)
{
    unsigned cfg_open = (m.state == HSM_S_IDLE || m.state == HSM_S_ERROR);
    if (cfg_open) {
        if (off == HSM_REG_REQ_OWNER) m.req = v & 0xFu;
        if (off == HSM_REG_CAND_VERSION) m.cand_ver = v;
        if (off == HSM_REG_RULE_COUNT) m.count = v & 0xFu;
    }
    if (off >= HSM_REG_RULE_BASE && off < HSM_REG_RULE_BASE + 0x80u && m.state == HSM_S_RECEIVE) {
        uint32_t ro = off - HSM_REG_RULE_BASE, slot = (ro >> 4) & 7u, field = (ro >> 2) & 3u;
        if (slot >= HSM_NRULES || field == 3 || (off & 3u) || (field == 2 && (v & HSM_ATTR_RSVD_MASK)))
            m.malformed = 1;
        else {
            mrule_t *r = &m.bank[m.sel ^ 1u][slot];
            if (field == 0) r->start = v;
            else if (field == 1) r->end = v;
            else { r->owner = (v >> 16) & 0xFu; r->attr = (uint16_t)(v & 0x7FFu); r->valid = (uint8_t)(v >> 31); }
        }
    }
    if (off == HSM_REG_CMD) command(v & 0xFu);
}

static uint32_t model_read(uint32_t off)
{
    switch (off) {
    case HSM_REG_STATUS: return status();
    case HSM_REG_REQ_OWNER: return m.req;
    case HSM_REG_CAND_VERSION: return m.cand_ver;
    case HSM_REG_RULE_COUNT: return m.count;
    case HSM_REG_ACTIVE_VERSION: return m.act_ver;
    case HSM_REG_PREV_VERSION: return m.prev_ver;
    case HSM_REG_HW_INFO: return 0x48000000u | (2u << 16) | (HSM_NUM_OWNERS << 8) | HSM_NRULES;
    default: return 0;
    }
}

void hal_write32(uint32_t off, uint32_t value)
{
    off &= 0xFFu;                                   /* 8-bit register address, as in the RTL */
    if (log_fp) fprintf(log_fp, "1 %08X %08X 00000000\n", (unsigned)off, (unsigned)value);
    model_write(off, value);
}

uint32_t hal_read32(uint32_t off)
{
    off &= 0xFFu;
    uint32_t v = model_read(off);
    if (log_fp) fprintf(log_fp, "2 %08X %08X 00000000\n", (unsigned)off, (unsigned)v);
    return v;
}

int hal_poll32(uint32_t off, uint32_t mask, uint32_t value, uint32_t max_polls)
{
    (void)max_polls;
    off &= 0xFFu;
    if (log_fp) fprintf(log_fp, "3 %08X %08X %08X\n", (unsigned)off, (unsigned)value, (unsigned)mask);
    return (model_read(off) & mask) == value ? 0 : -1;
}
