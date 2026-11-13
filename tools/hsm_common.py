"""Shared definitions and reference models for the HSM tools.

Constants mirror rtl/hsm_defs.svh and firmware/include/hsm_regs.h (tests/test_constants.py
checks this). The two reference models below (transaction decision, bounded-authority
validation) mirror the RTL. The RTL testbenches replay vectors produced by these models,
so any divergence between Python and RTL fails `make sim-rtl`.
"""
from __future__ import annotations

import hashlib
import json
import struct
from dataclasses import dataclass, field
from pathlib import Path

NRULES = 8
NUM_OWNERS = 3
DEVICE_ID = 0x48534D01
OWNERS = {"CPU": 0, "DMA": 1, "DIAG": 2, "ROOT": 0x0F}
OWNER_NAME = {v: k for k, v in OWNERS.items()}

# Immutable authority envelopes: owner -> (lo, hi, may_read, may_write, max_burst, priv_floor)
ENVELOPES = {
    0: (0x0000_0000, 0x0000_FFFF, True, True, 16, False),
    1: (0x1000_0000, 0x1000_FFFF, True, True, 64, False),
    2: (0x2000_0000, 0x2000_FFFF, True, False, 4, True),
}

V = dict(OK=0, BAD_MASTER=1, NO_RULE=2, READ_DENIED=3, WRITE_DENIED=4, PRIV=5, BURST=6, SPAN=7)
E = dict(NONE=0, AUTH=1, COUNT=2, MALFORMED=3, OWNER_ID=4, RANGE=5, ADDR_ESCAPE=6, PERM_ESC=7,
         PRIV_FLOOR=8, BURST_ESC=9, FOREIGN=10, OVERLAP=11, VERSION=12)
V_NAME = {v: k for k, v in V.items()}
E_NAME = {v: k for k, v in E.items()}

# Package format (little-endian), see docs/RESEARCH_AND_DESIGN.md section 6
MAGIC = b"HSMP"
FORMAT_VERSION = 1
HDR_SIGNED = 56          # bytes covered by the signature (includes the payload digest)
HDR_SIZE = 120           # signed header + 64-byte Ed25519 signature
RULE_SIZE = 12
HDR_FMT = "<4sHHIBBHII"  # magic, format, header_size, device, requester, count, payload_len, ver, prev


@dataclass(frozen=True)
class Rule:
    slot: int
    owner: int
    start: int
    end: int
    read: bool
    write: bool
    priv: bool
    max_burst: int

    def attr(self) -> int:
        """Hardware ATTR register word (valid bit set)."""
        return (1 << 31) | (self.owner << 16) | (self.priv << 10) | (self.write << 9) | (self.read << 8) | self.max_burst

    def key(self):
        """Everything the hardware stores for a slot (used for the ownership comparison)."""
        return (self.owner, self.start, self.end, self.read, self.write, self.priv, self.max_burst)

    def describe(self) -> str:
        perm = ("R" if self.read else "-") + ("W" if self.write else "-")
        p = " priv" if self.priv else ""
        return (f"slot {self.slot} {OWNER_NAME.get(self.owner, self.owner)} "
                f"0x{self.start:08X}-0x{self.end:08X} {perm}{p} burst<={self.max_burst}")


@dataclass
class Policy:
    requester: int
    version: int
    prev_version: int
    rules: list[Rule]
    device_id: int = DEVICE_ID
    description: str = ""
    name: str = ""
    meta: dict = field(default_factory=dict)


def _int(x) -> int:
    return int(x, 0) if isinstance(x, str) else int(x)


def _owner(x) -> int:
    return OWNERS[x] if isinstance(x, str) else int(x)


def load_policy(path) -> Policy:
    """Load and type-check a policy JSON. Authority is NOT checked here (that is the validator's job)."""
    d = json.loads(Path(path).read_text())

    def need(cond, what):
        if not cond:
            raise ValueError(f"{path}: {what}")

    def u(v, bits, what):
        v = _int(v) if isinstance(v, str) else v
        need(isinstance(v, int) and not isinstance(v, bool) and 0 <= v < (1 << bits), f"{what} must be a {bits}-bit unsigned integer")
        return v

    def owner(v, what):
        need(v in OWNERS if isinstance(v, str) else (isinstance(v, int) and not isinstance(v, bool)), f"unknown {what} {v!r}")
        return u(_owner(v), 4, what)

    need(isinstance(d.get("rules"), list) and 1 <= len(d["rules"]) <= NRULES, f"rules must be a list of 1..{NRULES}")
    rules = []
    for r in d["rules"]:
        for flag in ("read", "write", "priv"):
            need(isinstance(r.get(flag), bool), f"rule {flag} must be true/false, got {r.get(flag)!r}")
        rules.append(Rule(u(r["slot"], 3, "slot"), owner(r["owner"], "owner"), u(r["start"], 32, "start"),
                          u(r["end"], 32, "end"), r["read"], r["write"], r["priv"], u(r["max_burst"], 8, "max_burst")))
    need(len({r.slot for r in rules}) == len(rules), "duplicate slot")
    return Policy(owner(d["requester"], "requester"), u(d["policy_version"], 32, "policy_version"),
                  u(d["prev_version"], 32, "prev_version"), sorted(rules, key=lambda r: r.slot),
                  u(d.get("device_id", DEVICE_ID), 32, "device_id"), d.get("description", ""), Path(path).stem,
                  d.get("meta", {}))


def policy_to_json(p: Policy) -> dict:
    return {
        "description": p.description,
        "device_id": f"0x{p.device_id:08X}",
        "requester": OWNER_NAME.get(p.requester, p.requester),
        "policy_version": p.version,
        "prev_version": p.prev_version,
        "rules": [{"slot": r.slot, "owner": OWNER_NAME.get(r.owner, r.owner),
                   "start": f"0x{r.start:08X}", "end": f"0x{r.end:08X}", "read": r.read,
                   "write": r.write, "priv": r.priv, "max_burst": r.max_burst} for r in p.rules],
        **({"meta": p.meta} if p.meta else {}),
    }


# ---------------------------------------------------------------------------------------
# Binary package
# ---------------------------------------------------------------------------------------
def encode_rules(rules) -> bytes:
    return b"".join(struct.pack("<IIBBBB", r.start, r.end, r.slot, r.owner,
                                r.read | (r.write << 1) | (r.priv << 2), r.max_burst) for r in rules)


def signed_header(p: Policy, payload: bytes, count: int | None = None) -> bytes:
    count = len(p.rules) if count is None else count
    hdr = struct.pack(HDR_FMT, MAGIC, FORMAT_VERSION, HDR_SIZE, p.device_id, p.requester, count,
                      len(payload), p.version, p.prev_version)
    return hdr + hashlib.blake2b(payload, digest_size=32).digest()


def parse_package(blob: bytes) -> dict:
    """Unauthenticated structural parse (for inspection; the firmware is the real verifier)."""
    if len(blob) < HDR_SIZE:
        raise ValueError("truncated header")
    magic, fmt, hsz, dev, req, count, plen, ver, prev = struct.unpack_from(HDR_FMT, blob)
    if magic != MAGIC or fmt != FORMAT_VERSION or hsz != HDR_SIZE:
        raise ValueError("bad magic/format")
    if len(blob) != HDR_SIZE + plen or plen != count * RULE_SIZE:
        raise ValueError("bad length")
    payload = blob[HDR_SIZE:]
    rules = []
    for i in range(count):
        start, end, slot, owner, flags, burst = struct.unpack_from("<IIBBBB", payload, i * RULE_SIZE)
        rules.append(Rule(slot, owner, start, end, bool(flags & 1), bool(flags & 2), bool(flags & 4), burst))
    return dict(device_id=dev, requester=req, count=count, version=ver, prev_version=prev,
                digest=blob[24:56], signature=blob[56:120], signed=blob[:HDR_SIGNED],
                payload=payload, rules=rules)


# ---------------------------------------------------------------------------------------
# Reference model 1: transaction decision (mirrors rtl/bus_security_monitor.sv)
# ---------------------------------------------------------------------------------------
def check_txn(rules, master, addr, write, priv, burst):
    """Return (allow, reason_code, matched_rule_or_None)."""
    if master >= NUM_OWNERS:
        return False, V["BAD_MASTER"], None
    hit = next((r for r in sorted(rules, key=lambda r: r.slot)
                if r.owner == master and r.start <= addr <= r.end), None)
    if hit is None:
        return False, V["NO_RULE"], None
    if not write and not hit.read:
        return False, V["READ_DENIED"], hit
    if write and not hit.write:
        return False, V["WRITE_DENIED"], hit
    if hit.priv and not priv:
        return False, V["PRIV"], hit
    if burst == 0 or burst > hit.max_burst:
        return False, V["BURST"], hit
    last = addr + 4 * burst - 1
    if last > 0xFFFF_FFFF or last > hit.end:
        return False, V["SPAN"], hit
    return True, V["OK"], hit


# ---------------------------------------------------------------------------------------
# Reference model 2: bounded-authority validation (mirrors policy_update_controller BEGIN
# checks + rtl/policy_validator.sv, same check order, same error slot)
# ---------------------------------------------------------------------------------------
def validate_update(cand: Policy, active_rules, active_version: int, boot_window: bool = False):
    """Return (error_code, slot) the hardware would report for installing `cand`."""
    req, count = cand.requester, len(cand.rules)
    root = req == OWNERS["ROOT"]
    if not (req < NUM_OWNERS or (root and boot_window)):
        return E["AUTH"], 0
    if count == 0 or count > NRULES:
        return E["COUNT"], 0
    if cand.version <= active_version:
        return E["VERSION"], 0
    cs = {r.slot: r for r in cand.rules}
    acts = {r.slot: r for r in active_rules}
    for i in range(NRULES):
        c, a = cs.get(i), acts.get(i)
        foreign = not root and ((a is not None and a.owner != req) or (c is not None and c.owner != req))
        same = a is not None and c is not None and a.key() == c.key()
        if foreign and not same:
            return E["FOREIGN"], i
        if c is None:
            continue
        if c.owner >= NUM_OWNERS:
            return E["OWNER_ID"], i
        lo, hi, mr, mw, mb, pf = ENVELOPES[c.owner]
        if c.max_burst == 0:
            return E["MALFORMED"], i
        if c.start > c.end:
            return E["RANGE"], i
        if c.start < lo or c.end > hi:
            return E["ADDR_ESCAPE"], i
        if (c.read and not mr) or (c.write and not mw):
            return E["PERM_ESC"], i
        if pf and not c.priv:
            return E["PRIV_FLOOR"], i
        if c.max_burst > mb:
            return E["BURST_ESC"], i
    for i in range(NRULES):
        for j in range(i + 1, NRULES):
            a, b = cs.get(i), cs.get(j)
            if a and b and a.start <= b.end and b.start <= a.end:
                return E["OVERLAP"], j
    return E["NONE"], 0


def policy_hex_words(p: Policy) -> list[int]:
    """RTL image: requester, version, count, then (slot, start, end, attr) per rule, zero-padded
    to the testbench buffer size (3 + 4 * NRULES words)."""
    words = [p.requester, p.version, len(p.rules)]
    for r in p.rules:
        words += [r.slot, r.start, r.end, r.attr()]
    return words + [0] * max(0, 3 + 4 * NRULES - len(words))


def write_hex(path, words):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    Path(path).write_text("".join(f"{w & 0xFFFFFFFF:08X}\n" for w in words))
