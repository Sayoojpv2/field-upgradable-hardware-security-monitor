/* policy_pkg.c - package parsing and authentication (Ed25519 + BLAKE2b from Monocypher). */
#include <string.h>
#include "policy_pkg.h"
#include "device_config.h"
#include "hsm_regs.h"
#include "monocypher.h"
#include "monocypher-ed25519.h"

static uint16_t rd16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static uint32_t rd32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

/* The trusted key comes from device configuration, selected by the requester field. */
static int key_index(uint8_t requester)
{
    if (requester < HSM_NUM_OWNERS) return requester;
    if (requester == HSM_OWNER_ROOT) return 3;
    return -1;
}

pkg_err_t pkg_parse_verify(const uint8_t *buf, size_t len, policy_t *out)
{
    if (buf == NULL || len < PKG_HDR_SIZE) return PKG_ERR_TRUNCATED;
    if (rd32(buf) != PKG_MAGIC) return PKG_ERR_MAGIC;
    if (rd16(buf + 4) != PKG_FORMAT || rd16(buf + 6) != PKG_HDR_SIZE) return PKG_ERR_FORMAT;

    uint8_t  count = buf[13];
    uint16_t plen  = rd16(buf + 14);
    if (count == 0 || count > PKG_MAX_RULES || plen != count * PKG_RULE_SIZE) return PKG_ERR_LENGTH;
    if (len < (size_t)PKG_HDR_SIZE + plen) return PKG_ERR_TRUNCATED;
    if (len > (size_t)PKG_HDR_SIZE + plen) return PKG_ERR_LENGTH;

    int k = key_index(buf[12]);
    if (k < 0) return PKG_ERR_OWNER;
    if (crypto_ed25519_check(buf + PKG_HDR_SIGNED, hsm_trusted_keys[k], buf, PKG_HDR_SIGNED) != 0)
        return PKG_ERR_SIGNATURE;

    uint8_t digest[32];
    crypto_blake2b(digest, sizeof digest, buf + PKG_HDR_SIZE, plen);
    if (crypto_verify32(digest, buf + 24) != 0) return PKG_ERR_DIGEST;
    if (rd32(buf + 8) != hsm_device_id) return PKG_ERR_DEVICE;

    /* Encoding checks only. Authority (envelopes, ownership, overlap) is the hardware's job. */
    policy_t p;
    memset(&p, 0, sizeof p);
    uint32_t seen = 0;
    for (uint8_t i = 0; i < count; i++) {
        const uint8_t *r = buf + PKG_HDR_SIZE + i * PKG_RULE_SIZE;
        pkg_rule_t *d = &p.rules[i];
        d->start = rd32(r);
        d->end = rd32(r + 4);
        d->slot = r[8];
        d->owner = r[9];
        d->flags = r[10];
        d->max_burst = r[11];
        /* owner > 15 would alias onto a real owner in the 4-bit hardware field */
        if ((d->flags & ~7u) || d->slot >= PKG_MAX_RULES || d->owner > 0xF || (seen & (1u << d->slot)))
            return PKG_ERR_RULE;
        seen |= 1u << d->slot;
    }
    p.device_id = rd32(buf + 8);
    p.requester = buf[12];
    p.rule_count = count;
    p.version = rd32(buf + 16);
    p.prev_version = rd32(buf + 20);
    *out = p;
    return PKG_OK;
}

uint32_t pkg_rule_attr(const pkg_rule_t *r)
{
    return HSM_ATTR_VALID | HSM_ATTR_OWNER(r->owner) | ((r->flags & 4u) ? HSM_ATTR_PRIV : 0) |
           ((r->flags & 2u) ? HSM_ATTR_W : 0) | ((r->flags & 1u) ? HSM_ATTR_R : 0) | r->max_burst;
}

const char *pkg_err_str(pkg_err_t e)
{
    static const char *s[] = {"OK", "TRUNCATED", "MAGIC", "FORMAT", "LENGTH", "OWNER",
                              "SIGNATURE", "DIGEST", "DEVICE", "RULE"};
    return (unsigned)e < sizeof s / sizeof s[0] ? s[e] : "?";
}
