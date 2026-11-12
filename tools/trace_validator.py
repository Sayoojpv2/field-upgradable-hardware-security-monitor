#!/usr/bin/env python3
"""Offline trace validation of candidate policies (release gate, runs before signing).

  gen        --out build/traces/corpus.csv            deterministic benign/malicious/boundary corpus
  replay     --policy P.json --trace T.csv [--explain] confusion matrix for one policy
  compare    --baseline A.json --candidate B.json --trace T.csv [--report R.md] [--json R.json]
             exit 0 = recommended for signing, 1 = not recommended
  export-rtl --policy P.json --trace T.csv --out V.hex expected decisions for the RTL testbench

Labels are the security intent once all three synthetic weaknesses are known: `benign`
transactions must be accepted, `malicious` ones must be blocked. Decisions come from the
same reference model the RTL is checked against. Nothing here installs a policy.
"""
from __future__ import annotations

import argparse
import csv
import json
import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from hsm_common import (OWNER_NAME, V_NAME, E_NAME, check_txn, load_policy, validate_update)  # noqa: E402

FIELDS = ["ts", "master", "addr", "op", "priv", "burst", "label", "scenario", "note"]
CPU, DMA, DIAG = 0, 1, 2


# ---------------------------------------------------------------------------------------
# Trace generation
# ---------------------------------------------------------------------------------------
def gen_traces(seed: int = 2026) -> list[dict]:
    rng = random.Random(seed)
    out = []

    def add(m, addr, op, priv, burst, label, scen, note=""):
        out.append(dict(ts=len(out) * 10, master=m, addr=addr, op=op, priv=int(priv), burst=burst,
                        label=label, scenario=scen, note=note))

    def inside(lo, hi, maxb):
        """Random word-aligned burst fully inside [lo, hi]."""
        b = rng.randint(1, maxb)
        return rng.randrange(lo, hi - 4 * b + 2, 4), b

    rw = lambda: rng.choice("RW")
    # --- benign traffic (must be accepted by the intended final policy)
    for _ in range(120):
        a, b = inside(0x0000_0000, 0x0000_EFFF, 16); add(CPU, a, rw(), rng.random() < .5, b, "benign", "base", "CPU memory")
    for _ in range(30):
        a, b = inside(0x0000_F000, 0x0000_FFFF, 4); add(CPU, a, rw(), 1, b, "benign", "s2", "privileged peripheral access")
    for _ in range(120):
        lo, hi = rng.choice([(0x1000_0000, 0x1000_7FFF), (0x1000_9000, 0x1000_FFFF)])
        a, b = inside(lo, hi, 16); add(DMA, a, rw(), 0, b, "benign", "base", "DMA buffer")
    for _ in range(40):
        a, b = inside(0x2000_0000, 0x2000_FFFF, 4); add(DIAG, a, "R", 1, b, "benign", "base", "diagnostic read")
    # --- scenario 1: DMA into the newly-protected 0x10008000-0x10008FFF window
    for _ in range(30):
        a, b = inside(0x1000_8000, 0x1000_8FFF, 16); add(DMA, a, rw(), 0, b, "malicious", "s1", "DMA into protected window")
    for _ in range(10):
        b = rng.randint(2, 16); add(DMA, 0x1000_8000 - 4 * rng.randint(1, b - 1), "W", 0, b, "malicious", "s1",
                                    "burst crossing into protected window")
    # --- scenario 2: unprivileged CPU access to the peripheral page
    for _ in range(30):
        a, b = inside(0x0000_F000, 0x0000_FFFF, 4); add(CPU, a, rw(), 0, b, "malicious", "s2", "unprivileged peripheral access")
    # --- scenario 3: oversized DMA bursts (17..64 beats) inside legitimate buffers
    for _ in range(30):
        lo, hi = rng.choice([(0x1000_0000, 0x1000_7FFF), (0x1000_9000, 0x1000_FFFF)])
        b = rng.randint(17, 64); a = rng.randrange(lo, hi - 4 * b + 2, 4)
        add(DMA, a, rw(), 0, b, "malicious", "s3", "oversized DMA burst")
    # --- always-blocked attacks (outside every owner's authority)
    for _ in range(10):
        add(DIAG, rng.randrange(0x2000_0000, 0x2000_FFF0, 4), "W", 1, 1, "malicious", "auth", "diagnostics write")
    for _ in range(10):
        add(DIAG, rng.randrange(0x2000_0000, 0x2000_FFF0, 4), "R", 0, 1, "malicious", "auth", "unprivileged diagnostics read")
    for _ in range(10):
        add(DMA, rng.randrange(0x0000_0000, 0x0000_FFF0, 4), rw(), 0, 1, "malicious", "auth", "DMA into CPU memory")
    for _ in range(10):
        add(CPU, rng.randrange(0x1000_0000, 0x1000_FFF0, 4), rw(), 1, 1, "malicious", "auth", "CPU into DMA memory")
    for m in range(3, 16, 2):
        add(m, 0x0000_1000, "R", 1, 1, "malicious", "auth", "unknown bus master")
    for m in (CPU, DMA):
        add(m, 0x3000_0000, "R", 1, 1, "malicious", "auth", "unassigned address space")
        add(m, [0x1000, 0x1000_1000][m], "R", 1, 0, "malicious", "auth", "zero-length burst")
    add(DMA, 0x1000_1000, "W", 0, 255, "malicious", "auth", "burst above envelope")
    # --- boundary conditions
    for m, a, op, p, b, lab, note in [
        (CPU, 0x0000_0000, "R", 0, 1, "benign", "first word of CPU region"),
        (CPU, 0x0000_EFFC, "W", 0, 1, "benign", "last unprivileged CPU word"),
        (CPU, 0x0000_EFF8, "W", 0, 3, "malicious", "unprivileged burst crossing into peripheral"),
        (CPU, 0x0000_FFFC, "R", 1, 1, "benign", "last CPU word, privileged"),
        (CPU, 0x0000_FFFC, "R", 1, 2, "malicious", "burst leaving CPU region"),
        (DMA, 0x1000_7FFC, "W", 0, 1, "benign", "last word below protected window"),
        (DMA, 0x1000_7FFC, "W", 0, 2, "malicious", "burst touching protected window"),
        (DMA, 0x1000_8FFC, "R", 0, 1, "malicious", "last protected word"),
        (DMA, 0x1000_9000, "R", 0, 1, "benign", "first word above protected window"),
        (DMA, 0x1000_FFC0, "W", 0, 16, "benign", "max legitimate burst ending at region end"),
        (DMA, 0x1000_FFC4, "W", 0, 16, "malicious", "burst leaving DMA region"),
        (DMA, 0x1000_0000, "R", 0, 16, "benign", "max legitimate burst at region start"),
        (DMA, 0x1000_0000, "R", 0, 17, "malicious", "one beat over the patched burst limit"),
        (DIAG, 0x2000_FFF0, "R", 1, 4, "benign", "max diagnostics burst at region end"),
        (DIAG, 0x2000_FFF4, "R", 1, 4, "malicious", "diagnostics burst leaving region"),
    ]:
        add(m, a, op, p, b, lab, "boundary", note)
    return out


def write_trace(path, rows):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", newline="") as f:
        w = csv.DictWriter(f, FIELDS)
        w.writeheader()
        for r in rows:
            w.writerow({**r, "addr": f"0x{r['addr']:08X}"})


def read_trace(path) -> list[dict]:
    with open(path, newline="") as f:
        return [dict(r, ts=int(r["ts"]), master=int(r["master"]), addr=int(r["addr"], 0), priv=int(r["priv"]),
                     burst=int(r["burst"])) for r in csv.DictReader(f)]


# ---------------------------------------------------------------------------------------
# Replay and comparison
# ---------------------------------------------------------------------------------------
def decide(policy, t):
    return check_txn(policy.rules, t["master"], t["addr"], t["op"] == "W", t["priv"], t["burst"])


def explain(t, allow, reason, rule) -> str:
    who = OWNER_NAME.get(t["master"], f"M{t['master']}")
    txn = f"{who} {t['op']} 0x{t['addr']:08X} x{t['burst']} priv={t['priv']}"
    if allow:
        return f"{txn}: ACCEPTED by {rule.describe()}"
    why = {"BAD_MASTER": "unknown bus master", "NO_RULE": "no rule of this master covers the address (default deny)",
           "READ_DENIED": "rule forbids reads", "WRITE_DENIED": "rule forbids writes",
           "PRIV": "rule requires privileged access", "BURST": "burst length is zero or above the rule maximum",
           "SPAN": "burst runs past the end of the matching rule"}[V_NAME[reason]]
    return f"{txn}: REJECTED ({V_NAME[reason]}) - {why}" + (f" [{rule.describe()}]" if rule else "")


def replay(policy, trace):
    s = dict(benign_accepted=0, benign_rejected=0, malicious_accepted=0, malicious_rejected=0)
    decisions = []
    for t in trace:
        allow, reason, rule = decide(policy, t)
        decisions.append((allow, reason, rule))
        s[f"{t['label']}_{'accepted' if allow else 'rejected'}"] += 1
    nb = s["benign_accepted"] + s["benign_rejected"]
    nm = s["malicious_accepted"] + s["malicious_rejected"]
    s["false_positive_rate"] = round(s["benign_rejected"] / nb, 4) if nb else 0.0
    s["false_negative_rate"] = round(s["malicious_accepted"] / nm, 4) if nm else 0.0
    return s, decisions


def compare(base, cand, trace):
    sb, db = replay(base, trace)
    sc, dc = replay(cand, trace)
    diff = dict(fixed=[], regressions_benign=[], regressions_malicious=[], newly_allowed_benign=[])
    for i, (t, b, c) in enumerate(zip(trace, db, dc)):
        if b[0] == c[0]:
            continue
        key = ("fixed" if t["label"] == "malicious" else "regressions_benign") if not c[0] else \
              ("regressions_malicious" if t["label"] == "malicious" else "newly_allowed_benign")
        diff[key].append((i, explain(t, *c)))
    remaining = [(i, t["scenario"], explain(t, *c)) for i, (t, c) in enumerate(zip(trace, dc))
                 if t["label"] == "malicious" and c[0]]
    hw_err, hw_slot = validate_update(cand, base.rules, base.version, boot_window=False)
    reasons = []
    if hw_err:
        reasons.append(f"hardware authority check would reject it: {E_NAME[hw_err]} at slot {hw_slot}")
    if diff["regressions_benign"]:
        reasons.append(f"{len(diff['regressions_benign'])} legitimate transaction(s) newly rejected")
    if diff["regressions_malicious"]:
        reasons.append(f"{len(diff['regressions_malicious'])} malicious transaction(s) newly accepted")
    return dict(baseline=dict(name=base.name, version=base.version, **sb),
                candidate=dict(name=cand.name, version=cand.version, requester=OWNER_NAME[cand.requester], **sc),
                hardware_check=E_NAME[hw_err] if hw_err else "PASS", hardware_err_slot=hw_slot if hw_err else None,
                diff=diff, remaining_undetected=remaining,
                recommended=not reasons, reasons=reasons)


def report_md(r) -> str:
    b, c = r["baseline"], r["candidate"]
    rows = ["benign_accepted", "benign_rejected", "malicious_accepted", "malicious_rejected",
            "false_positive_rate", "false_negative_rate"]
    lines = [f"# Trace validation: {c['name']} (v{c['version']}, requester {c['requester']}) vs {b['name']} (v{b['version']})", "",
             f"**Verdict: {'RECOMMENDED for signing' if r['recommended'] else 'NOT RECOMMENDED'}**", ""]
    lines += [f"- {x}" for x in r["reasons"]] or ["- no legitimate-traffic or security regression found"]
    lines += ["", f"Hardware authority pre-check (reference model of policy_validator): **{r['hardware_check']}**", "",
              "| metric | baseline | candidate |", "|---|---:|---:|"]
    lines += [f"| {k} | {b[k]} | {c[k]} |" for k in rows]
    titles = dict(fixed="Malicious transactions newly blocked", regressions_benign="REGRESSION: legitimate transactions newly rejected",
                  regressions_malicious="REGRESSION: malicious transactions newly accepted",
                  newly_allowed_benign="Legitimate transactions newly accepted")
    for k, title in titles.items():
        items = r["diff"][k]
        lines += ["", f"## {title} ({len(items)})"]
        lines += [f"- #{i}: {e}" for i, e in items[:15]] + ([f"- ... {len(items) - 15} more"] if len(items) > 15 else [])
    rem = r["remaining_undetected"]
    by_scen = {}
    for _, s, _ in rem:
        by_scen[s] = by_scen.get(s, 0) + 1
    lines += ["", f"## Remaining undetected attacks ({len(rem)})",
              ", ".join(f"{k}: {v}" for k, v in sorted(by_scen.items())) or "none"]
    lines += [f"- #{i}: {e}" for i, _, e in rem[:10]]
    return "\n".join(lines) + "\n"


def export_rtl(policy, trace, out):
    words = []
    for t in trace:
        allow, reason, _ = decide(policy, t)
        words.append(f"{t['master']:X} {t['addr']:08X} {int(t['op'] == 'W')} {t['priv']} {t['burst']:02X} {int(allow)} {reason:X}")
    Path(out).parent.mkdir(parents=True, exist_ok=True)
    Path(out).write_text(f"{len(words):08X}\n" + "\n".join(words) + "\n")


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    g = sub.add_parser("gen"); g.add_argument("--out", required=True); g.add_argument("--seed", type=int, default=2026)
    r = sub.add_parser("replay"); r.add_argument("--policy", required=True); r.add_argument("--trace", required=True)
    r.add_argument("--explain", action="store_true")
    c = sub.add_parser("compare"); c.add_argument("--baseline", required=True); c.add_argument("--candidate", required=True)
    c.add_argument("--trace", required=True); c.add_argument("--report"); c.add_argument("--json")
    x = sub.add_parser("export-rtl"); x.add_argument("--policy", required=True); x.add_argument("--trace", required=True)
    x.add_argument("--out", required=True)
    a = ap.parse_args(argv)

    if a.cmd == "gen":
        rows = gen_traces(a.seed)
        write_trace(a.out, rows)
        print(f"{a.out}: {len(rows)} transactions "
              f"({sum(t['label'] == 'benign' for t in rows)} benign, {sum(t['label'] == 'malicious' for t in rows)} malicious)")
    elif a.cmd == "replay":
        pol, trace = load_policy(a.policy), read_trace(a.trace)
        s, dec = replay(pol, trace)
        print(json.dumps(s, indent=2))
        if a.explain:
            for t, d in zip(trace, dec):
                print(f"[{t['label']:9}] " + explain(t, *d))
    elif a.cmd == "compare":
        res = compare(load_policy(a.baseline), load_policy(a.candidate), read_trace(a.trace))
        md = report_md(res)
        if a.report:
            Path(a.report).parent.mkdir(parents=True, exist_ok=True); Path(a.report).write_text(md)
        if a.json:
            Path(a.json).parent.mkdir(parents=True, exist_ok=True); Path(a.json).write_text(json.dumps(res, indent=2))
        print(md.split("\n## ")[0])
        return 0 if res["recommended"] else 1
    else:
        export_rtl(load_policy(a.policy), read_trace(a.trace), a.out)
    return 0


if __name__ == "__main__":
    sys.exit(main())
