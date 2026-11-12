#!/usr/bin/env python3
"""Generate RTL test inputs from the Python tools, then run every self-checking testbench.

usage: run_rtl.py [--replay LOG ...]     (exit 1 if any testbench fails)
Tool paths come from $IVERILOG / $VVP (default: iverilog / vvp on PATH).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import trace_validator as tv  # noqa: E402
from hsm_common import load_policy, policy_hex_words, validate_update, write_hex  # noqa: E402
from policy_generator import scaled_policy  # noqa: E402

IVERILOG = os.environ.get("IVERILOG", "iverilog")
VVP = os.environ.get("VVP", "vvp")
BUILD = ROOT / "build"
VDIR = BUILD / "vectors"
RTL = [f"rtl/{p.name}" for p in sorted((ROOT / "rtl").glob("*.sv"))]


def prepare_vectors():
    """Policy images, attack expectations and per-policy trace vectors (reference decisions)."""
    trace = tv.gen_traces()
    tv.write_trace(BUILD / "traces" / "corpus.csv", trace)
    v4 = load_policy(ROOT / "examples" / "policy_v4.json")
    attacks = []
    for f in sorted((ROOT / "examples").rglob("*.json")):
        rel = f.relative_to(ROOT / "examples").with_suffix("").as_posix()
        pol = load_policy(f)
        write_hex(VDIR / f"{rel}.hex", policy_hex_words(pol))
        if rel.startswith("attacks/"):
            err, slot = validate_update(pol, v4.rules, v4.version)
            attacks.append(f"{rel} {err} {slot}\n")
    (VDIR / "attacks.txt").write_text("".join(attacks))
    for n in (2, 4, 6, 8):
        write_hex(VDIR / f"scaled_{n}.hex", policy_hex_words(scaled_policy(n)))
    for v in range(1, 5):
        tv.export_rtl(load_policy(ROOT / "examples" / f"policy_v{v}.json"), trace, VDIR / f"trace_v{v}.vec")
    return trace


def compile_tb(tb: str, params: dict | None = None) -> Path:
    params = params or {}
    tag = "_".join(f"{k}{v}" for k, v in params.items())
    out = BUILD / "sim" / f"{tb}{'_' + tag if tag else ''}.vvp"
    out.parent.mkdir(parents=True, exist_ok=True)
    cmd = [IVERILOG, "-g2012", "-Irtl", "-Itb", "-s", tb, "-o", str(out.relative_to(ROOT))]
    cmd += [f"-P{tb}.{k}={v}" for k, v in params.items()] + RTL + [f"tb/{tb}.sv"]
    r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"iverilog failed for {tb} {params}:\n{r.stdout}{r.stderr}")
    return out


def run_vvp(vvp: Path, plusargs=()) -> str:
    r = subprocess.run([VVP, "-n", str(vvp.relative_to(ROOT)), *plusargs], cwd=ROOT, capture_output=True, text=True)
    return r.stdout + r.stderr


def result(out: str):
    m = re.search(r"TB_RESULT tb=(\S+) checks=(\d+) errors=(\d+) (PASS|FAIL)", out)
    return (m.group(1), int(m.group(2)), int(m.group(3)), m.group(4)) if m else None


def regression_runs():
    sm = {m: compile_tb("tb_security_monitor", {"MODE": m}) for m in (0, 1, 2)}
    runs = [(sm[2], [], "datapath, bounded design"), (sm[1], [], "datapath, unbounded baseline"),
            (sm[0], [], "datapath, static monitor")]
    for v in range(1, 5):
        runs.append((sm[2], [f"+policy=build/vectors/policy_v{v}.hex", f"+vectors=build/vectors/trace_v{v}.vec", "+check"],
                     f"trace replay v{v} == Python model (bounded)"))
    runs.append((sm[1], ["+policy=build/vectors/policy_v4.hex", "+vectors=build/vectors/trace_v4.vec", "+check"],
                 "trace replay v4 == Python model (baseline)"))
    runs.append((sm[0], ["+vectors=build/vectors/trace_v1.vec", "+check"], "trace replay v1 == Python model (static)"))
    runs.append((compile_tb("tb_policy_update"), ["+vdir=build/vectors"], "update flow, authority, rollback, reset"))
    return runs


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--replay", nargs="*", default=[], help="firmware MMIO logs to replay into the RTL")
    ap.add_argument("--only-replay", action="store_true", help="skip the regular testbenches")
    a = ap.parse_args(argv)
    prepare_vectors()

    runs = [] if a.only_replay else regression_runs()
    if a.replay:
        rp = compile_tb("tb_mmio_replay")
        for log in a.replay:
            if not (ROOT / log).exists():
                sys.exit(f"missing {log}: run the C tests first (make test-c)")
            runs.append((rp, [f"+log={log}"], f"firmware MMIO replay {Path(log).name}"))

    summary, failed = [], 0
    for vvp, args, what in runs:
        out = run_vvp(vvp, args)
        res = result(out)
        ok = res is not None and res[3] == "PASS"
        failed += not ok
        extra = " ".join(l for l in out.splitlines() if l.startswith(("REPLAY", "METRIC")))
        print(f"{'PASS' if ok else 'FAIL'}  {what:48} checks={res[1] if res else '?':<6} {extra}")
        if not ok:
            print("\n".join(l for l in out.splitlines() if "ERROR" in l or "mismatch" in l)[:3000] or out[-3000:])
        summary.append(dict(test=what, tb=res[0] if res else None, checks=res[1] if res else 0,
                            errors=res[2] if res else None, passed=ok))
    if not a.only_replay:
        (BUILD / "results").mkdir(parents=True, exist_ok=True)
        (BUILD / "results" / "rtl_tests.json").write_text(json.dumps(summary, indent=2))
    total = sum(s["checks"] for s in summary)
    print(f"RTL: {len(runs) - failed}/{len(runs)} testbench runs passed, {total} checks")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
