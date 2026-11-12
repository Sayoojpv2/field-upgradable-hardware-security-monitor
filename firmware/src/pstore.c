/* pstore.c - simulated persistent policy store with torn-write fault injection. */
#include <string.h>
#include "pstore.h"

uint32_t pstore_crc32(const uint8_t *p, size_t n)
{
    uint32_t c = 0xFFFFFFFFu;
    while (n--) {
        c ^= *p++;
        for (int k = 0; k < 8; k++) c = (c >> 1) ^ (0xEDB88320u & (0u - (c & 1u)));
    }
    return ~c;
}

void pstore_init_blank(pstore_t *ps)
{
    memset(ps, 0xFF, sizeof *ps);          /* erased flash */
    ps->fault_after_bytes = -1;
    ps->power_loss = NULL;
    ps->fail_commit = 0;
    ps->bytes_programmed = 0;
}

/* Program bytes one at a time so a simulated power loss can tear any write. */
static void program(pstore_t *ps, uint8_t *dst, const uint8_t *src, size_t n)
{
    for (size_t i = 0; i < n; i++) {
        if (ps->fault_after_bytes == 0 && ps->power_loss) {
            ps->fault_after_bytes = -1;
            ps->power_loss();
        }
        if (ps->fault_after_bytes > 0) ps->fault_after_bytes--;
        dst[i] = src[i];
        ps->bytes_programmed++;
    }
}

static int meta_ok(const ps_meta_t *m)
{
    return m->magic == PS_META_MAGIC && m->slot < 2 && m->len <= PS_SLOT_SIZE &&
           m->crc == pstore_crc32((const uint8_t *)m, 5 * sizeof(uint32_t));
}

static int winner(const pstore_t *ps)
{
    int a = meta_ok(&ps->meta[0]), b = meta_ok(&ps->meta[1]);
    if (a && b) return ps->meta[1].seq > ps->meta[0].seq ? 1 : 0;
    return a ? 0 : (b ? 1 : -1);
}

int pstore_write_slot(pstore_t *ps, uint32_t slot, const uint8_t *data, size_t len)
{
    if (slot > 1 || len > PS_SLOT_SIZE) return -1;
    program(ps, ps->slot[slot], data, len);
    return 0;
}

int pstore_commit(pstore_t *ps, uint32_t slot, uint32_t version, uint32_t len)
{
    if (ps->fail_commit) return -1;
    int w = winner(ps);
    ps_meta_t m = {PS_META_MAGIC, w < 0 ? 1u : ps->meta[w].seq + 1u, slot, version, len, 0};
    m.crc = pstore_crc32((const uint8_t *)&m, 5 * sizeof(uint32_t));
    program(ps, (uint8_t *)&ps->meta[w < 0 ? 0 : w ^ 1], (const uint8_t *)&m, sizeof m);  /* never the live copy */
    return 0;
}

int pstore_committed(const pstore_t *ps, ps_meta_t *out)
{
    int w = winner(ps);
    if (w < 0) return -1;
    *out = ps->meta[w];
    return 0;
}
