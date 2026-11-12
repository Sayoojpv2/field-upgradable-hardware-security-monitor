#!/usr/bin/env python3
"""Create security policies.

  examples [--out examples]           regenerate the scenario policies (v1..v4, attacks, candidates)
  scaled   --rules N --out FILE.json  synthetic N-rule policy for the scaling experiments
  hex      --policy P.json --out F.hex  RTL load image (used by the testbenches)

The example policies form one update chain on the synthetic SoC:
  v1 factory (ROOT) -> v2 DMA (scenario 1) -> v3 CPU (scenario 2) -> v4 DMA (scenario 3)
Attack policies are signed by a legitimate owner key but try to exceed that owner's authority.
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import replace
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hsm_common import ENVELOPES, OWNERS, Policy, Rule, policy_hex_words, policy_to_json, load_policy, write_hex  # noqa: E402

CPU, DMA, DIAG, ROOT = (OWNERS[k] for k in ("CPU", "DMA", "DIAG", "ROOT"))


def R(slot, owner, start, end, perm, max_burst, priv=False):
    return Rule(slot, owner, start, end, "R" in perm, "W" in perm, priv, max_burst)


def with_rules(base: Policy, requester, version, desc, changes=(), remove=()):
    rules = {r.slot: r for r in base.rules}
    for s in remove:
        rules.pop(s)
    for r in changes:
        rules[r.slot] = r
    return Policy(requester, version, base.version, sorted(rules.values(), key=lambda r: r.slot),
                  description=desc)


def example_policies() -> dict[str, Policy]:
    v1 = Policy(ROOT, 1, 0, [
        R(0, CPU, 0x0000_0000, 0x0000_FFFF, "RW", 16),
        R(1, DMA, 0x1000_0000, 0x1000_FFFF, "RW", 64),
        R(2, DIAG, 0x2000_0000, 0x2000_FFFF, "R", 4, priv=True),
    ], description="Factory policy (provisioning authority). Contains the three synthetic weaknesses.")
    v2 = with_rules(v1, DMA, 2, "Scenario 1: DMA owner removes 0x10008000-0x10008FFF from its own window.", [
        R(1, DMA, 0x1000_0000, 0x1000_7FFF, "RW", 64),
        R(3, DMA, 0x1000_9000, 0x1000_FFFF, "RW", 64)])
    v3 = with_rules(v2, CPU, 3, "Scenario 2: CPU owner makes the peripheral page 0xF000-0xFFFF privileged-only.", [
        R(0, CPU, 0x0000_0000, 0x0000_EFFF, "RW", 16),
        R(4, CPU, 0x0000_F000, 0x0000_FFFF, "RW", 4, priv=True)])
    v4 = with_rules(v3, DMA, 4, "Scenario 3: DMA owner lowers its maximum burst from 64 to 16 beats.", [
        replace(v3.rules[1], max_burst=16), replace(next(r for r in v3.rules if r.slot == 3), max_burst=16)])

    s = {r.slot: r for r in v4.rules}
    atk = {
        "atk_dma_expand": with_rules(v4, DMA, 5, "DMA widens slot 3 past its envelope (0x1000FFFF).",
                                     [replace(s[3], end=0x1001_FFFF)]),
        "atk_dma_burst": with_rules(v4, DMA, 5, "DMA raises its burst above the envelope maximum (64).",
                                    [replace(s[1], max_burst=128)]),
        "atk_diag_write": with_rules(v4, DIAG, 5, "Diagnostics grants itself write permission.",
                                     [replace(s[2], write=True)]),
        "atk_diag_unpriv": with_rules(v4, DIAG, 5, "Diagnostics drops its mandatory privilege requirement.",
                                      [replace(s[2], priv=False)]),
        "atk_dma_foreign_modify": with_rules(v4, DMA, 5, "DMA re-opens the CPU peripheral page by editing a CPU rule.",
                                             [replace(s[0], end=0x0000_FFFF)], remove=[4]),
        "atk_dma_foreign_delete": with_rules(v4, DMA, 5, "DMA deletes the CPU's privileged-peripheral rule.",
                                             remove=[4]),
        "atk_dma_claim_slot": with_rules(v4, DMA, 5, "DMA creates a rule on behalf of the diagnostics owner.",
                                         [R(5, DIAG, 0x2000_0000, 0x2000_00FF, "R", 4, priv=True)]),
        "atk_dma_overlap": with_rules(v4, DMA, 5, "DMA adds a shadow rule overlapping its own slot 1.",
                                      [R(5, DMA, 0x1000_7000, 0x1000_9FFF, "RW", 16)]),
    }
    cand = {
        # Over-restrictive fix for scenario 1: hardware accepts it, trace validation must flag it.
        "cand_v2_overbroad": with_rules(v1, DMA, 2, "Scenario 1 fix that also blocks the legitimate 0x10009000-0x1000BFFF buffer.", [
            R(1, DMA, 0x1000_0000, 0x1000_7FFF, "RW", 64),
            R(3, DMA, 0x1000_C000, 0x1000_FFFF, "RW", 64)]),
        # Within DMA's authority, so hardware accepts it, but it re-opens scenario 1.
        "cand_v5_dma_reopen": with_rules(v4, DMA, 5, "DMA merges its windows back together (re-opens 0x10008000).", [
            R(1, DMA, 0x1000_0000, 0x1000_FFFF, "RW", 16)], remove=[3]),
    }
    return {"policy_v1": v1, "policy_v2": v2, "policy_v3": v3, "policy_v4": v4,
            **{f"attacks/{k}": v for k, v in atk.items()}, **{f"candidates/{k}": v for k, v in cand.items()}}


def scaled_policy(n: int) -> Policy:
    """n non-overlapping in-envelope rules spread over the three owners (ROOT restore image)."""
    rules = []
    for slot in range(n):
        owner = slot % 3
        lo, hi, mr, mw, mb, pf = ENVELOPES[owner]
        k = slot // 3
        rules.append(Rule(slot, owner, lo + k * 0x1000, lo + k * 0x1000 + 0xFFF, mr, mw, pf, mb))
    return Policy(ROOT, 1, 0, rules, description=f"Synthetic {n}-rule policy for scaling experiments")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    e = sub.add_parser("examples"); e.add_argument("--out", default="examples")
    s = sub.add_parser("scaled"); s.add_argument("--rules", type=int, required=True); s.add_argument("--out", required=True)
    h = sub.add_parser("hex"); h.add_argument("--policy", required=True); h.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    if a.cmd == "examples":
        for name, pol in example_policies().items():
            path = Path(a.out) / f"{name}.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(policy_to_json(pol), indent=2) + "\n")
        print(f"wrote {len(example_policies())} policies to {a.out}/")
    elif a.cmd == "scaled":
        Path(a.out).parent.mkdir(parents=True, exist_ok=True)
        Path(a.out).write_text(json.dumps(policy_to_json(scaled_policy(a.rules)), indent=2) + "\n")
    else:
        write_hex(a.out, policy_hex_words(load_policy(a.policy)))


if __name__ == "__main__":
    main()
