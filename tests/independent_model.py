"""Independent reference model of the monitor and the bounded-authority validator.

Written from the specification in docs/RESEARCH_AND_DESIGN.md (sections 5 and 6 and the register
map) WITHOUT importing anything from tools/. It uses its own constants, rule representation and
decision code, so a mistake in the production Python model (tools/hsm_common.py) cannot also hide in
the expected answers. Also generates deterministic adversarial vectors for the RTL testbenches.
"""
from __future__ import annotations

import random
from pathlib import Path

SLOTS = 8
ROOT = 15
# authority envelope per owner: (low, high, read allowed, write allowed, max burst, privilege floor)
AUTHORITY = {0: (0x00000000, 0x0000FFFF, True, True, 16, False),
             1: (0x10000000, 0x1000FFFF, True, True, 64, False),
             2: (0x20000000, 0x2000FFFF, True, False, 4, True)}
# decision reasons and validation errors, as numbered in the specification tables
OK, BAD_MASTER, NO_RULE, READ_DENIED, WRITE_DENIED, PRIV, BURST, SPAN = range(8)
E_OK, E_AUTH, E_COUNT, E_MALFORMED, E_OWNER, E_RANGE, E_ESCAPE, E_PERM, E_FLOOR, E_BURST, E_FOREIGN, \
    E_OVERLAP, E_VERSION = range(13)
RESERVED_ATTR_BITS = 0x7FF0F800


def attr_word(owner, r, w, priv, burst, valid=1):
    """ATTR register: [31] valid, [19:16] owner, [10] PRIV, [9] W, [8] R, [7:0] max burst."""
    return (valid << 31) | ((owner & 15) << 16) | (priv << 10) | (w << 9) | (r << 8) | (burst & 255)


def from_attr(start, end, attr):
    return dict(valid=attr >> 31 & 1, owner=attr >> 16 & 15, start=start, end=end, priv=attr >> 10 & 1,
                w=attr >> 9 & 1, r=attr >> 8 & 1, burst=attr & 255)


# ---------------------------------------------------------------------------------- monitor
def decide(bank, master, addr, write, priv, burst):
    """bank: list of SLOTS entries (dict or None). Returns (allow, reason)."""
    if master not in AUTHORITY:
        return 0, BAD_MASTER
    match = None
    for rule in bank:                                   # slot order: lowest index wins
        if rule and rule["valid"] and rule["owner"] == master and rule["start"] <= addr <= rule["end"]:
            match = rule
            break
    if match is None:
        return 0, NO_RULE
    if not write and not match["r"]:
        return 0, READ_DENIED
    if write and not match["w"]:
        return 0, WRITE_DENIED
    if match["priv"] and not priv:
        return 0, PRIV
    if burst < 1 or burst > match["burst"]:
        return 0, BURST
    final_byte = addr + burst * 4 - 1
    if final_byte >= 1 << 32 or final_byte > match["end"]:
        return 0, SPAN
    return 1, OK


# ---------------------------------------------------------------------------------- validator
def _rule_error(c):
    lo_hi = AUTHORITY.get(c["owner"])
    if lo_hi is None:
        return E_OWNER
    lo, hi, can_r, can_w, max_burst, floor = lo_hi
    if c["burst"] == 0:
        return E_MALFORMED
    if c["start"] > c["end"]:
        return E_RANGE
    if c["start"] < lo or c["end"] > hi:
        return E_ESCAPE
    if (c["r"] and not can_r) or (c["w"] and not can_w):
        return E_PERM
    if floor and not c["priv"]:
        return E_FLOOR
    if c["burst"] > max_burst:
        return E_BURST
    return E_OK


def validate(active, writes, requester, version, count, active_version, boot_window):
    """Outcome (error, slot) of BEGIN + rule writes + VALIDATE.

    active: list of SLOTS (dict or None); writes: list of (slot, start, end, attr) applied in order.
    """
    requester &= 15
    count &= 15
    if not (requester in AUTHORITY or (requester == ROOT and boot_window)):
        return E_AUTH, 0
    if count < 1 or count > SLOTS:
        return E_COUNT, 0
    cand, malformed = [None] * SLOTS, False
    for slot, start, end, attr in writes:
        if attr & RESERVED_ATTR_BITS:
            malformed = True            # the write is refused and remembered
            continue
        cand[slot] = from_attr(start, end, attr)
    if malformed:
        return E_MALFORMED, 0
    if version <= active_version:
        return E_VERSION, 0
    for k in range(SLOTS):
        c = cand[k] if cand[k] and cand[k]["valid"] else None
        a = active[k] if active[k] and active[k]["valid"] else None
        if requester != ROOT:
            touches_other = (a is not None and a["owner"] != requester) or (c is not None and c["owner"] != requester)
            if touches_other and (a is None or c is None or a != c):
                return E_FOREIGN, k
        if c is not None:
            e = _rule_error(c)
            if e:
                return e, k
    live = [(k, cand[k]) for k in range(SLOTS) if cand[k] and cand[k]["valid"]]
    for x in range(len(live)):
        for y in range(x + 1, len(live)):
            (_, p), (q_slot, q) = live[x], live[y]
            if p["start"] <= q["end"] and q["start"] <= p["end"]:
                return E_OVERLAP, q_slot
    if len(live) != count:
        return E_COUNT, 0
    return E_OK, 0


# ---------------------------------------------------------------------------------- vectors
def _bank(rules):
    bank = [None] * SLOTS
    for slot, start, end, attr in rules:
        bank[slot] = from_attr(start, end, attr)
    return bank


def _hex32(words):
    """Hex lines for $readmemh; a value wider than 32 bits would be silently truncated by the RTL."""
    assert all(0 <= w < 1 << 32 for w in words), "vector value outside 32 bits"
    return "".join(f"{w:08X}\n" for w in words)


def _policy_hex(rules, requester=ROOT, version=1):
    words = [requester, version, len(rules)] + [x for r in rules for x in r]
    return words + [0] * (3 + 4 * SLOTS - len(words))


# A valid committed policy, written out independently of examples/ (same layout as policy_v4).
BASE = [(0, 0x00000000, 0x0000EFFF, attr_word(0, 1, 1, 0, 16)),
        (1, 0x10000000, 0x10007FFF, attr_word(1, 1, 1, 0, 16)),
        (2, 0x20000000, 0x2000FFFF, attr_word(2, 1, 0, 1, 4)),
        (3, 0x10009000, 0x1000FFFF, attr_word(1, 1, 1, 0, 16)),
        (4, 0x0000F000, 0x0000FFFF, attr_word(0, 1, 1, 1, 4))]
BASE_VERSION = 4


def monitor_policies(seed=11):
    """Adversarial policies for the unbounded (direct-write) design: overlaps, invalid owners,
    zero bursts, inverted ranges, a rule reaching 0xFFFFFFFF, rules in every slot."""
    rng = random.Random(seed)
    fixed = [
        BASE,
        [(k, 0x1000 * k, 0x1000 * k + 0xFFF, attr_word(k % 3, 1, k & 1, k & 2 > 0, 1 + 7 * k)) for k in range(8)],
        [(0, 0x0, 0xFFFFFFFF, attr_word(0, 1, 0, 0, 255)), (1, 0x100, 0x1FF, attr_word(0, 1, 1, 1, 2)),
         (7, 0x0, 0xFFFFFFFF, attr_word(1, 1, 1, 0, 8))],
        [(3, 0x2000, 0x2FFF, attr_word(5, 1, 1, 0, 4)), (4, 0x3000, 0x2FFF, attr_word(0, 1, 1, 0, 4)),
         (5, 0x4000, 0x4FFF, attr_word(0, 1, 1, 0, 0)), (6, 0x2000, 0x2FFF, attr_word(0, 0, 1, 0, 4))],
    ]
    for _ in range(8):
        rules = []
        for slot in rng.sample(range(SLOTS), rng.randint(1, SLOTS)):
            owner = rng.choice([0, 1, 2, 2, 1, 0, 3, 9])
            start = min(rng.choice([0, 0x10000000, 0x20000000, 0xFFFFF000]) + rng.randrange(0, 0x8000, 4), 0xFFFFFFFC)
            end = min(start + rng.choice([0, 3, 0xFF, 0xFFF, 0x7FFF]), 0xFFFFFFFF)
            rules.append((slot, start, end, attr_word(owner, rng.getrandbits(1), rng.getrandbits(1),
                                                     rng.getrandbits(1), rng.choice([0, 1, 4, 16, 64, 255]))))
        fixed.append(rules)
    return fixed


def monitor_transactions(rules, rng, n_random=300):
    txns = []
    for slot, start, end, attr in rules:
        for addr in {start, max(start - 4, 0), max(start - 1, 0), end, max(end - 3, 0), min(end + 1, 0xFFFFFFFF)}:
            for burst in (0, 1, 2, attr & 255, (attr & 255) + 1 & 255, 255):
                for m in (attr >> 16 & 15, rng.randrange(16)):
                    txns.append((m, addr, rng.getrandbits(1), rng.getrandbits(1), burst))
    for _ in range(n_random):
        txns.append((rng.randrange(16), rng.choice([rng.getrandbits(32), rng.randrange(0x30000000)]),
                     rng.getrandbits(1), rng.getrandbits(1), rng.choice([0, 1, 4, 16, 17, 64, 65, 255])))
    return txns


def validator_vectors(seed=7, n_random=1500):
    """(has_base, writes, requester, version, count, (err, slot)) for every corner of the check table."""
    rng = random.Random(seed)
    vecs = []

    def add(base, writes, requester, version, count=None):
        active = _bank(BASE) if base else [None] * SLOTS
        count = len(writes) if count is None else count
        expect = validate(active, writes, requester, version, count, BASE_VERSION if base else 0, not base)
        vecs.append((base, writes, requester, version, count, expect))

    env_rules = {o: (lo, hi, r, w, b, f) for o, (lo, hi, r, w, b, f) in AUTHORITY.items()}
    for owner, (lo, hi, r, w, b, f) in env_rules.items():
        for slot in range(SLOTS):
            # boot images: one rule per owner per slot, at the bounds and one address outside them
            for start, end in ((lo, hi), (lo - 1, hi), (lo, hi + 1), (lo + 4, lo), (lo, lo), (hi, hi)):
                start, end = start & 0xFFFFFFFF, end & 0xFFFFFFFF
                for burst in (0, 1, b, b + 1):
                    add(False, [(slot, start, end, attr_word(owner, r, w, f, burst))], ROOT, 1)
            add(False, [(slot, lo, hi, attr_word(owner, 1, 1, f, b))], ROOT, 1)             # write escalation
            add(False, [(slot, lo, hi, attr_word(owner, r, w, 0, b))], ROOT, 1)             # privilege floor
            add(False, [(slot, lo, hi, attr_word(owner + 3 + slot, r, w, f, b))], ROOT, 1)  # unknown owner
    for requester in (0, 1, 2, 3, 7, ROOT):
        for version in (BASE_VERSION - 1, BASE_VERSION, BASE_VERSION + 1):
            for count in (0, 4, 5, 6, 8, 9, 15):
                add(True, list(BASE), requester, version, count)
    # owner-scoped edits of the committed policy
    for requester in (0, 1, 2):
        for slot in range(SLOTS):
            for owner in (0, 1, 2, 5):
                lo, hi, r, w, b, f = AUTHORITY.get(owner, (0, 0xFF, 1, 1, 1, 0))
                edits = [x for x in BASE if x[0] != slot] + [(slot, lo, lo + 0xFF, attr_word(owner, r, w, f, min(b, 4)))]
                add(True, edits, requester, BASE_VERSION + 1)
            add(True, [x for x in BASE if x[0] != slot], requester, BASE_VERSION + 1)       # delete a rule
            dup = next(x for x in BASE if x[2] - x[1] > 0x100)
            add(True, list(BASE) + [(slot, dup[1], dup[2], dup[3])], requester, BASE_VERSION + 1)   # duplicate rule
    add(True, list(BASE) + [(5, 0x10000000, 0x1000000F, attr_word(1, 1, 1, 0, 4) | 0x1000)], 1, 5)  # reserved bit
    for _ in range(n_random):
        base = rng.random() < 0.6
        writes = list(BASE) if base and rng.random() < 0.7 else []
        for _ in range(rng.randint(0, 4)):
            owner = rng.choice([0, 1, 2, 0, 1, 2, rng.randrange(16)])
            lo, hi = AUTHORITY.get(owner, (0x30000000, 0x3000FFFF))[:2]
            start = rng.choice([lo, lo + rng.randrange(0, 0x10000, 4), lo - 4, hi]) & 0xFFFFFFFF
            end = rng.choice([hi, start + rng.choice([0, 0xF, 0xFFF]), hi + 1, start - 1]) & 0xFFFFFFFF
            slot = rng.randrange(SLOTS)
            writes = [x for x in writes if x[0] != slot] + [(slot, start, end, attr_word(
                owner, rng.getrandbits(1), rng.getrandbits(1), rng.getrandbits(1), rng.choice([0, 1, 4, 5, 16, 17, 64, 65, 255])))]
        requester = rng.choice([0, 1, 2, 0, 1, 2, rng.randrange(16), ROOT])
        version = (BASE_VERSION if base else 0) + rng.choice([-1, 0, 1, 1, 1, 1])
        count = len({w[0] for w in writes}) + rng.choice([0, 0, 0, 0, 1, -1])
        add(base, writes[:SLOTS], requester, version & 0xFFFFFFFF, max(count, 0))
    return vecs


def write_monitor_files(outdir: Path):
    """policy hex + expected-decision vectors, one pair per adversarial policy. Returns the count."""
    outdir.mkdir(parents=True, exist_ok=True)
    rng = random.Random(3)
    total = 0
    for n, rules in enumerate(monitor_policies()):
        (outdir / f"indep_pol{n}.hex").write_text(_hex32(_policy_hex(rules)))
        bank = _bank(rules)
        lines = []
        for m, addr, w, p, b in monitor_transactions(rules, rng):
            assert 0 <= addr < 1 << 32 and 0 <= b < 256 and 0 <= m < 16, "transaction field out of range"
            allow, reason = decide(bank, m, addr, w, p, b)
            lines.append(f"{m:X} {addr:08X} {w} {p} {b:02X} {allow} {reason:X}")
        (outdir / f"indep_txn{n}.vec").write_text(f"{len(lines):08X}\n" + "\n".join(lines) + "\n")
        total += len(lines)
    return len(monitor_policies()), total


def write_validator_file(path: Path):
    """One flat hex image for tb_policy_update +valvec (73 words per vector)."""
    vecs = validator_vectors()
    words = [len(vecs)]
    for base, writes, requester, version, count, (err, slot) in vecs:
        words += [int(base), BASE_VERSION, len(BASE)] + _policy_hex(BASE)[3:]
        flat = [x for wr in writes for x in wr]
        words += [requester & 15, version, count & 15, len(writes)] + flat + [0] * (4 * SLOTS - len(flat))
        words += [err, slot]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(_hex32(words))
    return vecs
