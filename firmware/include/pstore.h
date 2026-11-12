/* pstore.h - simulated persistent policy store (two package slots + two metadata copies).
 *
 * Commit protocol: the new package is programmed into the slot that is NOT committed, then
 * the older of the two metadata copies is overwritten. A power loss at any byte leaves at
 * least one valid metadata copy pointing at a complete, previously committed package.
 * Byte programming can be interrupted for fault-injection tests. */
#ifndef PSTORE_H
#define PSTORE_H

#include <stddef.h>
#include <stdint.h>

#define PS_SLOT_SIZE 256u
#define PS_META_MAGIC 0x4D455441u

typedef struct {
    uint32_t magic, seq, slot, version, len, crc;   /* crc = CRC-32 over the first five words */
} ps_meta_t;

typedef struct {
    uint8_t   slot[2][PS_SLOT_SIZE];
    ps_meta_t meta[2];
    long      fault_after_bytes;          /* test hook: -1 off; else power loss after N more bytes */
    void    (*power_loss)(void);          /* test hook: must not return (longjmp) */
    int       fail_commit;                /* test hook: metadata commit reports a write error */
    uint32_t  bytes_programmed;
} pstore_t;

void pstore_init_blank(pstore_t *ps);
int  pstore_write_slot(pstore_t *ps, uint32_t slot, const uint8_t *data, size_t len);
int  pstore_commit(pstore_t *ps, uint32_t slot, uint32_t version, uint32_t len);
/* Latest valid metadata copy; returns 0 if one exists, -1 if the store holds no committed policy. */
int  pstore_committed(const pstore_t *ps, ps_meta_t *out);
uint32_t pstore_crc32(const uint8_t *p, size_t n);

#endif
