/* policy_pkg.h - signed policy package: format, parsing and authentication.
 *
 * Layout (little-endian, fixed width):
 *   0   u32  magic "HSMP"           16  u32 policy_version
 *   4   u16  format_version (1)     20  u32 prev_policy_version
 *   6   u16  header_size (120)      24  u8[32] BLAKE2b-256(payload)
 *   8   u32  device_id              56  u8[64] Ed25519 signature over bytes [0,56)
 *   12  u8   requester owner       120  rule_count x 12-byte rules
 *   13  u8   rule_count
 *   14  u16  payload_length
 * Rule: u32 start, u32 end (inclusive), u8 slot, u8 owner, u8 flags (b0 R, b1 W, b2 PRIV), u8 max_burst
 */
#ifndef POLICY_PKG_H
#define POLICY_PKG_H

#include <stddef.h>
#include <stdint.h>

#define PKG_MAGIC       0x504D5348u   /* "HSMP" read as little-endian u32 */
#define PKG_FORMAT      1u
#define PKG_HDR_SIGNED  56u
#define PKG_HDR_SIZE    120u
#define PKG_RULE_SIZE   12u
#define PKG_MAX_RULES   8u
#define PKG_MAX_SIZE    (PKG_HDR_SIZE + PKG_MAX_RULES * PKG_RULE_SIZE)

typedef struct {
    uint32_t start, end;
    uint8_t  slot, owner, flags, max_burst;
} pkg_rule_t;

typedef struct {
    uint32_t   device_id;
    uint8_t    requester;
    uint8_t    rule_count;
    uint32_t   version;
    uint32_t   prev_version;
    pkg_rule_t rules[PKG_MAX_RULES];
} policy_t;

typedef enum {
    PKG_OK = 0,
    PKG_ERR_TRUNCATED,   /* shorter than the header or than header + payload */
    PKG_ERR_MAGIC,
    PKG_ERR_FORMAT,      /* format version / header size */
    PKG_ERR_LENGTH,      /* rule count, payload length or total length inconsistent */
    PKG_ERR_OWNER,       /* requester has no trusted key */
    PKG_ERR_SIGNATURE,
    PKG_ERR_DIGEST,
    PKG_ERR_DEVICE,
    PKG_ERR_RULE         /* reserved flag bits, slot out of range, duplicate slot */
} pkg_err_t;

/* Parse and authenticate. `out` is written only when PKG_OK is returned. */
pkg_err_t   pkg_parse_verify(const uint8_t *buf, size_t len, policy_t *out);
uint32_t    pkg_rule_attr(const pkg_rule_t *r);
const char *pkg_err_str(pkg_err_t e);

#endif
