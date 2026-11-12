#!/usr/bin/env python3
"""Comparative experiments on the RTL (identical traces for all designs) + plots.

Runs after `make test-c` and `make synth`. Every number written here is measured from an
RTL simulation, a Yosys run, the firmware test binary, or the generated packages.
Outputs: results/*.csv, results/*.json, results/summary.md, results/plots/*.png
"""
from __future__ import annotations

import csv
import json
import re
import shutil
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
sys.path.insert(0, str(ROOT / "scripts"))
import run_rtl  # noqa: E402
import trace_validator as tv  # noqa: E402
from hsm_common import HDR_SIZE, RULE_SIZE, check_txn, load_policy  # noqa: E402

RES = ROOT / "results"
PLOTS = RES / "plots"
VD = "build/vectors"
DESIGNS = {0: "static", 1: "configurable (unbounded)", 2: "bounded dual-bank"}
ATTACKS = sorted(p.stem for p in (ROOT / "examples" / "attacks").glob("*.json"))


def write_csv(name, rows):
    with open(RES / name, "w", newline="") as f:
        w = csv.DictWriter(f, list(rows[0]))
        w.writeheader()
        w.writerows(rows)


def sim(vvp, args):
    out = run_rtl.run_vvp(vvp, args)
    res = run_rtl.result(out)
    if not res or res[3] != "PASS":
        sys.exit(f"simulation failed: {vvp.name} {args}\n{out[-2000:]}")
    return out


def confusion(trace, decisions):
    c = Counter()
    for t, allow in zip(trace, decisions):
        c[f"{t['label']}_{'accepted' if allow else 'rejected'}"] += 1
    return {k: c[k] for k in ("benign_accepted", "benign_rejected", "malicious_accepted", "malicious_rejected")}


def rtl_decisions(path):
    return [int(l.split()[1]) for l in Path(path).read_text().split("\n") if l.strip()]


# ---------------------------------------------------------------------------------------------
def e_latency():
    rows = []
    for n in (2, 4, 6, 8):
        vvp = run_rtl.compile_tb("tb_policy_update", {"NRULES": n})
        out = sim(vvp, ["+measure", f"+policy={VD}/scaled_{n}.hex"])
        m = dict(re.findall(r"(\w+)=(\d+)", re.search(r"METRIC (.*)", out).group(1)))
        rows.append(dict(nrules=n, policy_rules=int(m["rules"]), validate_cycles=int(m["validate_cycles"]),
                         update_cycles=int(m["update_cycles"]), mmio_writes=int(m["mmio_writes"]),
                         switch_hold_cycles=int(m["switch_hold_cycles"]), decision_latency_cycles=1,
                         package_bytes=HDR_SIZE + RULE_SIZE * n))
    write_csv("latency.csv", rows)
    return rows


def e_designs(trace):
    sm = {m: run_rtl.compile_tb("tb_security_monitor", {"MODE": m}) for m in DESIGNS}
    rows = []
    for mode, pol in ((0, None), (1, "policy_v1"), (1, "policy_v4"), (2, "policy_v1"), (2, "policy_v4")):
        out = RES / "raw" / f"dec_m{mode}_{pol or 'static_v1'}.txt"
        args = [f"+vectors={VD}/trace_v1.vec", f"+out={out.relative_to(ROOT).as_posix()}"]
        if pol:
            args.insert(0, f"+policy={VD}/{pol}.hex")
        sim(sm[mode], args)
        c = confusion(trace, rtl_decisions(out))
        rows.append(dict(design=DESIGNS[mode], policy=pol or "policy_v1 (fixed at synthesis)", **c))
    write_csv("design_comparison.csv", rows)

    # Malicious-but-authenticated updates on top of v4 (the static design cannot be updated at all)
    mal = []
    for mode in (1, 2):
        for atk in ATTACKS:
            out = RES / "raw" / f"dec_m{mode}_{atk}.txt"
            o = sim(sm[mode], [f"+policy={VD}/policy_v4.hex", f"+attack={VD}/attacks/{atk}.hex",
                               f"+vectors={VD}/trace_v1.vec", f"+out={out.relative_to(ROOT).as_posix()}"])
            acc, err = re.search(r"ATTACK accepted=(\d) err=(\d+)", o).groups()
            c = confusion(trace, rtl_decisions(out))
            mal.append(dict(design=DESIGNS[mode], attack=atk, update_took_effect=int(acc), hw_error=int(err), **c))
    write_csv("malicious_updates.csv", mal)
    return rows, mal


def e_transient(trace, runs=20):
    """Update while a transaction is issued every cycle; classify each decision against the old and new policy."""
    sm = {m: run_rtl.compile_tb("tb_security_monitor", {"MODE": m}) for m in (1, 2)}
    rows = []
    for mode in (1, 2):
        for a, b in ((1, 2), (2, 3), (3, 4)):
            old, new = load_policy(ROOT / f"examples/policy_v{a}.json"), load_policy(ROOT / f"examples/policy_v{b}.json")
            exp_old = [check_txn(old.rules, t["master"], t["addr"], t["op"] == "W", t["priv"], t["burst"])[0] for t in trace]
            exp_new = [check_txn(new.rules, t["master"], t["addr"], t["op"] == "W", t["priv"], t["burst"])[0] for t in trace]
            out = RES / "raw" / f"transient_m{mode}_v{a}v{b}.txt"
            sim(sm[mode], [f"+policy={VD}/policy_v{a}.hex", f"+transient={VD}/policy_v{b}.hex", f"+vectors={VD}/trace_v1.vec",
                           f"+out={out.relative_to(ROOT).as_posix()}", f"+runs={runs}"])
            c, seen_new, stalls, windows = Counter(), {}, [], []
            for line in out.read_text().split("\n"):
                f = line.split()
                if not f:
                    continue
                if f[0] == "U":
                    windows.append(int(f[3]) - int(f[2])); stalls.append(int(f[4])); continue
                run, idx, allow = int(f[1]), int(f[3]), int(f[4])
                c["decisions"] += 1
                if exp_old[idx] == exp_new[idx]:
                    c["unaffected"] += 1
                    c["wrong_unaffected"] += allow != exp_old[idx]
                elif allow == exp_new[idx]:
                    c["new_policy"] += 1; seen_new[run] = True
                elif seen_new.get(run):
                    c["old_after_new"] += 1                     # mixing: old behaviour after the cut-over
                else:
                    c["old_policy"] += 1
            # "neither" cannot happen for a boolean decision; non-atomicity shows up as reversals
            # and as unaffected transactions decided wrongly mid-update.
            rows.append(dict(design=DESIGNS[mode], transition=f"v{a}->v{b}", runs=runs, decisions=c["decisions"],
                             affected_decisions=c["old_policy"] + c["new_policy"] + c["old_after_new"],
                             old_after_new=c["old_after_new"], wrong_unaffected=c["wrong_unaffected"],
                             inconsistent=c["old_after_new"] + c["wrong_unaffected"],
                             update_window_cycles=round(sum(windows) / len(windows), 1),
                             hold_cycles_per_update=round(sum(stalls) / len(stalls), 1)))
    write_csv("transient.csv", rows)
    return rows


def e_gate():
    pols = ["policy_v1", "policy_v2", "policy_v3", "policy_v4", "candidates/cand_v2_overbroad", "candidates/cand_v5_dma_reopen"]
    base = {"policy_v2": "policy_v1", "policy_v3": "policy_v2", "policy_v4": "policy_v3",
            "candidates/cand_v2_overbroad": "policy_v1", "candidates/cand_v5_dma_reopen": "policy_v4"}
    trace = tv.gen_traces()
    rows = []
    for p in pols:
        s, _ = tv.replay(load_policy(ROOT / f"examples/{p}.json"), trace)
        r = tv.compare(load_policy(ROOT / f"examples/{base[p]}.json"), load_policy(ROOT / f"examples/{p}.json"), trace) if p in base else None
        rows.append(dict(policy=Path(p).name, **{k: s[k] for k in ("benign_rejected", "malicious_accepted",
                         "false_positive_rate", "false_negative_rate")},
                         hardware_check=r["hardware_check"] if r else "-", gate=("recommended" if r["recommended"] else "NOT recommended") if r else "-"))
    write_csv("trace_validation.csv", rows)
    return rows


# ---------------------------------------------------------------------------------------------
def plots(lat, synth, gate, trans, modules):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    SURF, INK, INK2, GRID = "#fcfcfb", "#0b0b0b", "#52514e", "#e4e3df"
    COL = {"static": "#2a78d6", "configurable (unbounded)": "#eb6834", "bounded dual-bank": "#1baf7a"}
    MARK = {"static": "o", "configurable (unbounded)": "s", "bounded dual-bank": "D"}
    plt.rcParams.update({"figure.facecolor": SURF, "axes.facecolor": SURF, "axes.edgecolor": GRID, "axes.labelcolor": INK2,
                         "xtick.color": INK2, "ytick.color": INK2, "text.color": INK, "font.size": 10,
                         "axes.spines.top": False, "axes.spines.right": False, "axes.grid": True, "grid.color": GRID,
                         "grid.linewidth": 0.8, "axes.axisbelow": True})
    PLOTS.mkdir(parents=True, exist_ok=True)
    from matplotlib.ticker import FuncFormatter
    thousands = FuncFormatter(lambda v, _: f"{v:,.0f}")

    # 1. resource scaling (small multiples, one unit per panel)
    fig, axs = plt.subplots(1, 2, figsize=(10, 3.8))
    for ax, key, title in ((axs[0], "gate_cells", "Generic gate cells"), (axs[1], "flip_flops", "Flip-flops")):
        for d in COL:
            pts = [(int(r["nrules"]), int(r[key])) for r in synth if DESIGNS[int(r["mode"])] == d]
            ax.plot(*zip(*pts), color=COL[d], marker=MARK[d], ms=6, lw=2, solid_capstyle="round")
            ax.annotate(f"{d}  {pts[-1][1]:,}", pts[-1], xytext=(6, 0), textcoords="offset points", va="center", fontsize=9, color=INK2)
        ax.set_title(title, loc="left", fontsize=11, color=INK); ax.yaxis.set_major_formatter(thousands)
        ax.set_xlabel("rule slots (NRULES)"); ax.set_xticks([2, 4, 6, 8]); ax.set_xlim(1.5, 13)
    fig.suptitle("Yosys generic synthesis vs rule count (not an FPGA/ASIC result)", x=0.01, ha="left", fontsize=10, color=INK2)
    fig.tight_layout(); fig.savefig(PLOTS / "resource_scaling.png", dpi=150); plt.close(fig)

    # 2. update latency (one unit: cycles)
    fig, ax = plt.subplots(figsize=(6.4, 3.8))
    n = [r["nrules"] for r in lat]
    for key, col, mk, label in (("validate_cycles", "#2a78d6", "o", "hardware validation"),
                                ("update_cycles", "#eb6834", "s", "full update (writes + validate + switch)")):
        ys = [r[key] for r in lat]
        ax.plot(n, ys, color=col, marker=mk, ms=6, lw=2)
        ax.annotate(f"{label}  {ys[-1]}", (n[-1], ys[-1]), xytext=(6, 0), textcoords="offset points", va="center", fontsize=9, color=INK2)
    ax.set_xlabel("rule slots (NRULES), all slots filled"); ax.set_ylabel("clock cycles"); ax.set_xticks(n); ax.set_xlim(1.5, 14)
    ax.set_title("Update latency (RTL simulation); decision latency stays 1 cycle", loc="left", fontsize=11)
    fig.tight_layout(); fig.savefig(PLOTS / "update_latency.png", dpi=150); plt.close(fig)

    # 3. trace validation per policy (one unit: transactions)
    fig, ax = plt.subplots(figsize=(8, 3.8))
    names = [r["policy"].replace("cand_", "cand\n") for r in gate]
    xs = range(len(gate))
    w = 0.36
    for off, key, col, label in ((-w / 2, "malicious_accepted", "#eb6834", "attacks accepted (false negatives)"),
                                 (w / 2, "benign_rejected", "#2a78d6", "legitimate rejected (false positives)")):
        vals = [int(r[key]) for r in gate]
        bars = ax.bar([x + off for x in xs], vals, width=w - 0.04, color=col, label=label)
        for b, v in zip(bars, vals):
            ax.annotate(str(v), (b.get_x() + b.get_width() / 2, v), xytext=(0, 2), textcoords="offset points", ha="center", fontsize=8, color=INK2)
    ax.set_xticks(list(xs)); ax.set_xticklabels(names, fontsize=9); ax.set_ylabel("transactions (of 477)")
    ax.legend(frameon=False, fontsize=9, loc="upper right")
    ax.set_title("Offline trace validation of each policy", loc="left", fontsize=11)
    fig.tight_layout(); fig.savefig(PLOTS / "trace_validation.png", dpi=150); plt.close(fig)

    # 4. per-module area of the bounded design
    fig, ax = plt.subplots(figsize=(6.4, 2.8))
    mods = [m for m in modules if int(m["gate_cells"]) > 0]
    ax.barh([m["module"] for m in mods], [int(m["gate_cells"]) for m in mods], height=0.5, color="#1baf7a")
    for i, m in enumerate(mods):
        ax.annotate(f"{int(m['gate_cells']):,} cells / {int(m['flip_flops']):,} FFs", (int(m["gate_cells"]), i), xytext=(4, 0),
                    textcoords="offset points", va="center", fontsize=9, color=INK2)
    ax.set_xlim(0, max(int(m["gate_cells"]) for m in mods) * 1.55); ax.invert_yaxis(); ax.xaxis.set_major_formatter(thousands)
    ax.set_title("Bounded design (NRULES=8): generic cells per module", loc="left", fontsize=11)
    fig.tight_layout(); fig.savefig(PLOTS / "module_breakdown.png", dpi=150); plt.close(fig)


def md_table(rows, cols=None):
    cols = cols or list(rows[0])
    return "\n".join(["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)] +
                     ["| " + " | ".join(str(r[c]) for c in cols) + " |" for r in rows])


def main():
    (RES / "raw").mkdir(parents=True, exist_ok=True)
    trace = run_rtl.prepare_vectors()
    print("latency ..."); lat = e_latency()
    print("designs ..."); des, mal = e_designs(trace)
    print("transient ..."); trans = e_transient(trace)
    gate = e_gate()
    synth = list(csv.DictReader(open(RES / "synth.csv")))
    modules = list(csv.DictReader(open(RES / "synth_modules.csv")))
    fi = json.loads((ROOT / "build/results/fault_injection.json").read_text())
    shutil.copy(ROOT / "build/results/fault_injection.json", RES / "fault_injection.json")
    rtl = json.loads((ROOT / "build/results/rtl_tests.json").read_text()) if (ROOT / "build/results/rtl_tests.json").exists() else []
    plots(lat, synth, gate, trans, modules)

    agg = {}
    for r in mal:
        a = agg.setdefault(r["design"], dict(design=r["design"], attacks=0, updates_took_effect=0, malicious_accepted_total=0, benign_rejected_total=0))
        a["attacks"] += 1; a["updates_took_effect"] += r["update_took_effect"]
        a["malicious_accepted_total"] += r["malicious_accepted"]; a["benign_rejected_total"] += r["benign_rejected"]
    s8 = {DESIGNS[int(r["mode"])]: r for r in synth if r["nrules"] == "8"}
    md = ["# Measured results (generated by scripts/run_experiments.py)", "",
          "## Update latency vs rule slots (RTL, all slots filled)", md_table(lat), "",
          "## Synthesis (Yosys generic `synth`, and `synth -lut 6`)", md_table(synth), "",
          "## Bounded design per module (NRULES=8, hierarchy kept)", md_table(modules), "",
          "## Same 477-transaction trace on each design", md_table(des), "",
          "## Authenticated but malicious updates applied on top of v4 (8 attack images)",
          md_table(list(agg.values())), "", md_table(mal, ["design", "attack", "update_took_effect", "hw_error", "malicious_accepted", "benign_rejected"]), "",
          "## Updating while a transaction is issued every cycle", md_table(trans), "",
          "## Offline trace validation", md_table(gate), "",
          "## Fault injection (firmware + host model)", md_table(fi["fault_points"]), "",
          f"Torn-write sweep: {fi['torn_write_recovered']}/{fi['torn_write_runs']} interrupted installs restored the committed policy.", "",
          f"RTL regression: {sum(r['passed'] for r in rtl)}/{len(rtl)} testbench runs, {sum(r['checks'] for r in rtl)} checks."]
    (RES / "summary.md").write_text("\n".join(md) + "\n")
    json.dump(dict(latency=lat, designs=des, malicious_summary=list(agg.values()), transient=trans, gate=gate,
                   synth_n8={k: {c: v[c] for c in ("gate_cells", "flip_flops", "lut6")} for k, v in s8.items()},
                   fault_injection=fi), open(RES / "summary.json", "w"), indent=2)
    print((RES / "summary.md").read_text())


if __name__ == "__main__":
    main()
