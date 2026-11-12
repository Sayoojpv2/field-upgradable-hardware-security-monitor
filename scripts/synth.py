#!/usr/bin/env python3
"""Generic Yosys synthesis of the three designs for 2/4/6/8-rule configurations.

Writes results/synth.csv, results/synth_modules.csv and build/synth/*.log.
Numbers are technology-independent Yosys cell counts (generic gates + flip-flops) and a
generic 6-input-LUT mapping (`synth -lut 6`). They are NOT FPGA or ASIC implementation results.
"""
from __future__ import annotations

import csv
import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from policy_generator import scaled_policy  # noqa: E402

YOSYS = os.environ.get("YOSYS", "yowasp-yosys")
RTL = " ".join(f"rtl/{p.name}" for p in sorted((ROOT / "rtl").glob("*.sv")))
OUT = ROOT / "build" / "synth"
MODES = {0: "static", 1: "configurable (unbounded)", 2: "bounded dual-bank"}


def static_vector(n: int) -> str:
    """Pack an n-rule policy into the 640-bit STATIC_POLICY parameter (slot k at [k*80 +: 80])."""
    v = 0
    for r in scaled_policy(n).rules:
        attr = (r.priv << 10) | (r.write << 9) | (r.read << 8) | r.max_burst
        v |= ((1 << 79) | (r.owner << 75) | (r.start << 43) | (r.end << 11) | attr) << (80 * r.slot)
    return f"640'h{v:0160X}"


def run_yosys(tag: str, mode: int, n: int, flatten=True, lut=None) -> dict:
    OUT.mkdir(parents=True, exist_ok=True)
    stat_json = OUT / f"{tag}.json"
    params = f"-set MODE {mode} -set NRULES {n}" + (f" -set STATIC_POLICY {static_vector(n)}" if mode == 0 else "")
    synth = "synth -top security_monitor_top" + (" -flatten" if flatten else "") + (f" -lut {lut}" if lut else "")
    script = (f"read_verilog -sv -Irtl {RTL}; chparam {params} security_monitor_top; {synth}; "
              f"check -assert; tee -q -o {stat_json.relative_to(ROOT).as_posix()} stat -json")
    r = subprocess.run([YOSYS, "-q", "-l", (OUT / f"{tag}.log").relative_to(ROOT).as_posix(), "-p", script],
                       cwd=ROOT, capture_output=True, text=True)
    if r.returncode != 0:
        sys.exit(f"yosys failed ({tag}):\n{r.stdout[-2000:]}{r.stderr[-2000:]}")
    return json.loads(stat_json.read_text())


def summarize(mods: dict) -> dict:
    cells, by = 0, {}
    for m in mods.values():
        cells += m["num_cells"]
        for k, v in m.get("num_cells_by_type", {}).items():
            by[k] = by.get(k, 0) + v
    ff = sum(v for k, v in by.items() if "DFF" in k)
    latches = sum(v for k, v in by.items() if "DLATCH" in k)
    if latches:
        sys.exit(f"inferred {latches} latches - RTL bug")
    luts = by.get("$lut", 0)
    return dict(cells=cells, flip_flops=ff, comb_cells=cells - ff, luts=luts)


def main():
    rows = []
    for mode, name in MODES.items():
        for n in (2, 4, 6, 8):
            s = summarize(run_yosys(f"m{mode}_n{n}", mode, n)["modules"])
            l = summarize(run_yosys(f"m{mode}_n{n}_lut6", mode, n, lut=6)["modules"])
            rows.append(dict(design=name, mode=mode, nrules=n, gate_cells=s["cells"], flip_flops=s["flip_flops"],
                             comb_gate_cells=s["comb_cells"], lut6=l["luts"], lut6_flow_ffs=l["flip_flops"]))
            print(f"MODE {mode} ({name:22}) N={n}: {s['cells']:6} gate cells, {s['flip_flops']:5} FFs, {l['luts']:5} LUT6")
    res = ROOT / "results"
    res.mkdir(exist_ok=True)
    with open(res / "synth.csv", "w", newline="") as f:
        w = csv.DictWriter(f, list(rows[0])); w.writeheader(); w.writerows(rows)

    # Per-module breakdown of the bounded design (hierarchy kept)
    mods = run_yosys("m2_n8_hier", 2, 8, flatten=False)["modules"]
    mrows = []
    for mname, m in sorted(mods.items()):
        s = summarize({mname: m})
        short = mname.lstrip("\\").split("$")[-1] if "$paramod" in mname else mname.lstrip("\\")
        for base in ("bus_security_monitor", "policy_bank", "policy_validator", "policy_update_controller", "security_monitor_top"):
            if base in mname:
                short = base
        mrows.append(dict(module=short, gate_cells=s["cells"], flip_flops=s["flip_flops"]))
        print(f"  {short:26} {s['cells']:6} cells {s['flip_flops']:5} FFs")
    with open(res / "synth_modules.csv", "w", newline="") as f:
        w = csv.DictWriter(f, list(mrows[0])); w.writeheader(); w.writerows(mrows)
    print("wrote results/synth.csv, results/synth_modules.csv")


if __name__ == "__main__":
    main()
