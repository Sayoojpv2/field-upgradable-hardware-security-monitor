#!/usr/bin/env python3
"""Formal verification of the RTL with Yosys' built-in SAT engine (MiniSAT).

usage: run_formal.py [--quick]      (--quick: proofs only, no covers / BMC / mutants)

Engines (all inside yowasp-yosys, no external solver):
  comb   one time step, free state and inputs        -> PROVED (combinational property)
  prove  `sat -tempinduct`: k-induction from reset   -> PROVED (k) | UNKNOWN | FAILED
  bmc    `sat -seq N`: bounded model check from reset -> BOUNDED PASS (depth N) | FAILED
  cover  `sat -seq N` forcing a witness flag high     -> REACHED (with trace) | UNREACHED within N
Every outcome other than the expected one (including TIMEOUT and ERROR) fails the run.
Writes results/formal.json, results/formal.csv and logs/VCDs under build/formal/.
"""
from __future__ import annotations

import csv
import json
import os
import re
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from mutation_check import MUTANTS  # noqa: E402  (same planted bugs as the simulation mutation check)

YOSYS = os.environ.get("YOSYS", "yowasp-yosys")
OUT = ROOT / "build" / "formal"
RTL = ["bus_security_monitor.sv", "policy_bank.sv", "policy_validator.sv", "policy_update_controller.sv",
       "security_monitor_top.sv"]
TIMEOUT = 3000   # seconds per SAT call

# name, property, harness top, extra file, defines, mode, steps
JOBS = [
    ("A_monitor_protocol",   "A", "fv_monitor",   "fv_monitor.sv",    [],                                 "prove", 3),
    ("A_monitor_sound",      "A", "bus_security_monitor", None,       ["FV_MONITOR", "FV_A_SOUND"],       "comb", 1),
    ("A_monitor_deny",       "A", "bus_security_monitor", None,       ["FV_MONITOR", "FV_A_DENY"],        "comb", 1),
    ("A_monitor_priority",   "A", "bus_security_monitor", None,       ["FV_MONITOR", "FV_A_PRIORITY"],    "comb", 1),
    ("A_monitor_grant",      "A", "bus_security_monitor", None,       ["FV_MONITOR", "FV_A_GRANT"],       "comb", 1),
    ("A_spec_lemmas",        "A", "fv_spec",      "fv_spec.sv",       [],                                 "comb", 1),
    ("B_validator",          "B,F", "fv_validator", "fv_validator.sv", ["FV_VALIDATOR", "FV_DIAG"],       "prove", 3),
    ("C_bank",               "C", "fv_bank",      "fv_bank.sv",       [],                                 "prove", 3),
    ("CDEF_controller",      "C,D,E,F", "fv_controller", "fv_controller.sv", ["FV_CONTROLLER", "FV_CONTROLLER_UNIT"], "prove", 6),
    ("D_top_registered_bus", "D", "fv_top",       "fv_top.sv",        ["FV_TOP"],                         "prove", 4),
    ("E2E_top_n2",           "B,C,E", "fv_top",   "fv_top.sv",        ["FV_TOP", "FV_E2E", "FV_NR=2"],    "bmc", 40),
]
# name, harness top, extra file, defines, witness flag, depth. Witness flags are sticky registers, so
# they rise one cycle after the event; depths follow the cycle counts (reset = step 1).
COVERS = [
    ("legitimate transaction granted",        "fv_monitor",    "fv_monitor.sv",    [], "fv_cov_grant", 5),
    ("transaction denied (known master)",     "fv_monitor",    "fv_monitor.sv",    [], "fv_cov_deny_known_master", 5),
    ("8-slot candidate accepted",             "fv_validator",  "fv_validator.sv",  ["FV_VALIDATOR"], "fv_cov_accept", 44),
    ("foreign-rule candidate rejected",       "fv_validator",  "fv_validator.sv",  ["FV_VALIDATOR"], "fv_cov_reject_foreign", 12),
    ("envelope escape rejected",              "fv_validator",  "fv_validator.sv",  ["FV_VALIDATOR"], "fv_cov_reject_escape", 12),
    ("overlap found in the last slot pair",   "fv_validator",  "fv_validator.sv",  ["FV_VALIDATOR"], "fv_cov_last_slot", 44),
    ("controller activates a candidate",      "fv_controller", "fv_controller.sv", ["FV_CONTROLLER", "FV_CONTROLLER_UNIT"], "dut.fv_cov_activate", 12),
    ("switch waits for a busy bus",           "fv_controller", "fv_controller.sv", ["FV_CONTROLLER", "FV_CONTROLLER_UNIT"], "dut.fv_cov_wait", 14),
    ("candidate rejected (FOREIGN)",          "fv_controller", "fv_controller.sv", ["FV_CONTROLLER", "FV_CONTROLLER_UNIT"], "dut.fv_cov_reject", 10),
    ("revert completes",                      "fv_controller", "fv_controller.sv", ["FV_CONTROLLER", "FV_CONTROLLER_UNIT"], "dut.fv_cov_revert", 16),
    ("system: bank switch after validation",  "fv_top",        "fv_top.sv",        ["FV_TOP", "FV_NR=2"], "dut.genblk1.g_bounded.fv_cov_switch", 22),
    ("system: switch waits for a granted burst", "fv_top",     "fv_top.sv",        ["FV_TOP", "FV_NR=2"], "dut.genblk1.g_bounded.fv_cov_wait_then_switch", 42),
    ("system: failed update keeps the policy", "fv_top",       "fv_top.sv",        ["FV_TOP", "FV_NR=2"], "dut.genblk1.g_bounded.fv_cov_fail_after_switch", 34),
]
# planted bug (description in MUTANTS) -> proof job that must produce a concrete counterexample (FAILED).
# Bugs that only show after a full update sequence run as BMC on a 2-slot configuration (short scan).
FORMAL_MUTANTS = [
    ("monitor ignores privilege requirement", "A_monitor_sound", None),
    ("highest slot wins instead of lowest", "A_monitor_priority", None),
    ("monitor ignores burst span (address wrap / region overrun)", "A_monitor_sound", None),
    ("validator skips burst containment", "B_validator", ("bmc", 12, ["FV_NR=2"])),
    ("validator skips ownership check", "B_validator", ("bmc", 12, ["FV_NR=2"])),
    ("validator skips last overlap pair", "B_validator", ("bmc", 12, ["FV_NR=2"])),
    ("bank writes reach the ACTIVE bank", "C_bank", None),
    ("switch does not wait for bus idle", "CDEF_controller", ("bmc", 12, [])),
    ("controller activates a rejected candidate", "CDEF_controller", None),
    ("switch trusts bus_idle in the grant cycle", "D_top_registered_bus", ("bmc", 24, ["FV_NR=2"])),  # d426302 bug
]


def yosys(name, top, extra, defines, sat_cmd, rtl_dir: Path):
    OUT.mkdir(parents=True, exist_ok=True)
    srcs = " ".join([(rtl_dir / f).relative_to(ROOT).as_posix() for f in RTL] + ([f"formal/{extra}"] if extra else []))
    defs = " ".join(f"-D{d}" for d in defines)
    script = (f"read_verilog -formal -sv {defs} -I{rtl_dir.relative_to(ROOT).as_posix()} -Iformal {srcs}; "
              f"prep -flatten -top {top}; async2sync; opt -full; dffunmap; {sat_cmd}")
    log = OUT / f"{name}.log"
    t0 = time.time()
    r = subprocess.run([YOSYS, "-q", "-l", log.relative_to(ROOT).as_posix(), "-p", script], cwd=ROOT,
                       capture_output=True, text=True)
    text = log.read_text(errors="replace") if log.exists() else ""
    if r.returncode != 0:  # no -verify, so a failed proof exits 0: a non-zero status is a tool failure
        text += f"\nERROR: yosys exited with status {r.returncode}\n{r.stderr[-4000:]}"
        log.write_text(text)
    return text, round(time.time() - t0, 1)


def classify(mode, text):
    if re.search(r"TIMEOUT", text):
        return "TIMEOUT", None
    if re.search(r"^ERROR:", text, re.M):
        return "ERROR", None
    if mode == "cover":
        if "model found:" in text and "no model found" not in text:
            return "REACHED", None
        return ("UNREACHED", None) if "no model found" in text else ("ERROR", None)
    if mode == "prove":
        k = re.findall(r"Trying induction with length (\d+)", text)
        if "Induction step proven: SUCCESS!" in text:
            return "PROVED", int(k[-1]) if k else None
        if "FAIL!" in text or re.search(r"Base case for induction length \d+ failed", text):
            return "FAILED", None
        if "Reached maximum number of time steps" in text:
            return "UNKNOWN", int(k[-1]) if k else None
        return "ERROR", None
    if "SUCCESS!" in text:
        return ("PROVED" if mode == "comb" else "BOUNDED PASS"), None
    if "FAIL!" in text:
        return "FAILED", None
    return "ERROR", None


def sat_command(mode, steps, vcd, flag=None):
    common = f"-set-assumes -timeout {TIMEOUT}"
    if mode == "comb":
        return f"sat -seq 1 -prove-asserts {common}"
    trace = f"-show-public -dump_vcd {vcd}"          # traces carry every named signal
    if mode == "prove":
        return f"sat -tempinduct -prove-asserts {common} -set-at 1 rst_n 0 -maxsteps {steps} {trace}"
    if mode == "bmc":
        return f"sat -seq {steps} -prove-asserts {common} -set-at 1 rst_n 0 {trace}"
    return f"sat -seq {steps} {common} -set-at 1 rst_n 0 -set-at {steps} {flag} 1 {trace}"


def run_job(job, rtl_dir=ROOT / "rtl", tag=""):
    name, prop, top, extra, defines, mode, steps = job
    vcd = (OUT / f"{name}{tag}.vcd").relative_to(ROOT).as_posix()
    text, secs = yosys(name + tag, top, extra, defines, sat_command(mode, steps, vcd), rtl_dir)
    status, k = classify(mode, text)
    sizes = re.findall(r"Solving problem with (\d+) variables", text)
    return dict(job=name, property=prop, mode=mode, status=status,
                depth=(steps if mode == "bmc" else k), seconds=secs,
                max_sat_variables=max(map(int, sizes)) if sizes else None,
                assertions=len(set(re.findall(r"Import proof for assert: (\S+)", text))))


def run_cover(cov):
    desc, top, extra, defines, flag, depth = cov
    safe = re.sub(r"\W+", "_", desc)
    vcd = (OUT / f"cover_{safe}.vcd").relative_to(ROOT).as_posix()
    text, secs = yosys(f"cover_{safe}", top, extra, defines, sat_command("cover", depth, vcd, flag), ROOT / "rtl")
    status, _ = classify("cover", text)
    return dict(cover=desc, status=status, depth=depth, seconds=secs)


def run_mutant(desc, job_name, override):
    m = next(m for m in MUTANTS if m[0] == desc)
    safe = re.sub(r"\W+", "_", desc)
    mdir = OUT / "mut" / safe / "rtl"
    shutil.rmtree(mdir, ignore_errors=True)
    shutil.copytree(ROOT / "rtl", mdir)
    src = (mdir / m[1]).read_text()
    assert src.count(m[2]) == 1, f"anchor not found: {desc}"
    (mdir / m[1]).write_text(src.replace(m[2], m[3]))
    job = next(j for j in JOBS if j[0] == job_name)
    if override:
        mode, steps, extra_defs = override
        job = (job[0], job[1], job[2], job[3], job[4] + extra_defs, mode, steps)
    r = run_job(job, mdir, tag="__" + safe)
    return dict(mutant=desc, job=job_name, method=f"{job[5]} {job[6]}" + (f" {' '.join(override[2])}" if override else ""),
                status=r["status"], caught=r["status"] == "FAILED")


def main():
    quick = "--quick" in sys.argv
    jobs = [j for j in JOBS if not (quick and j[5] == "bmc")]
    # yowasp-runtime writes its compiled-module cache without locking or an atomic rename, so parallel
    # first runs can load a half-written module and crash. Compile it once before going parallel.
    subprocess.run([YOSYS, "-V"], cwd=ROOT, capture_output=True, check=True)
    with ThreadPoolExecutor(max_workers=4) as ex:
        results = list(ex.map(run_job, jobs))
        covers = [] if quick else list(ex.map(run_cover, COVERS))
        mutants = [] if quick else list(ex.map(lambda m: run_mutant(*m), FORMAL_MUTANTS))

    bad = 0
    print(f"{'job':24} {'prop':8} {'mode':6} {'status':13} {'k/depth':>7} {'vars':>8} {'sec':>7}")
    for r in results:
        ok = r["status"] == ("BOUNDED PASS" if r["mode"] == "bmc" else "PROVED")
        bad += not ok
        print(f"{r['job']:24} {r['property']:8} {r['mode']:6} {r['status']:13} {str(r['depth'] or '-'):>7} "
              f"{str(r['max_sat_variables'] or '-'):>8} {r['seconds']:>7}{'' if ok else '   <-- not proved'}")
    for c in covers:
        bad += c["status"] != "REACHED"
        print(f"cover  {c['status']:10} depth<={c['depth']:<3} {c['cover']}")
    for m in mutants:
        bad += not m["caught"]
        print(f"mutant {'CAUGHT ' if m['caught'] else 'MISSED '} {m['job']:22} {m['mutant']}")
    # keep the counterexample for the d426302 bug as a regression artifact (VCD + readable table)
    hist = OUT / "D_top_registered_bus__switch_trusts_bus_idle_in_the_grant_cycle.vcd"
    if hist.exists():
        (ROOT / "formal" / "cex").mkdir(exist_ok=True)
        shutil.copy(hist, ROOT / "formal" / "cex" / "d426302_switch_race.vcd")
        (ROOT / "formal" / "cex" / "d426302_switch_race.txt").write_text(trace_table(hist, CEX_SIGNALS))

    res = ROOT / "results"
    res.mkdir(exist_ok=True)
    (res / "formal.json").write_text(json.dumps(dict(jobs=results, covers=covers, mutants=mutants), indent=2))
    with open(res / "formal.csv", "w", newline="") as f:
        w = csv.DictWriter(f, list(results[0])); w.writeheader(); w.writerows(results)
    write_md(dict(jobs=results, covers=covers, mutants=mutants))
    print(f"FORMAL_RESULT jobs={len(results)} covers={len(covers)} mutants={len(mutants)} problems={bad} "
          f"{'PASS' if bad == 0 else 'FAIL'}")
    return 1 if bad else 0


CEX_SIGNALS = ["rst_n", "reg_we", "reg_addr", "reg_wdata", "txn_valid", "txn_ready", "txn_burst", "dec_valid",
               "dec_allow", "bus_idle", "dut.genblk1.g_bounded.fv_beats", "dut.genblk1.g_bounded.swap",
               "dut.genblk1.g_bounded.sel"]


def trace_table(vcd: Path, names) -> str:
    """Per-step values of selected signals from a Yosys `sat -dump_vcd` trace."""
    ids, cur, steps = {}, {}, []
    for line in vcd.read_text().splitlines():
        m = re.match(r"\$var \w+ \d+ (\S+) \\?(\S+)( \[\S+\])? \$end", line)
        if m and not m.group(3):
            ids[m.group(1)] = m.group(2)
        elif line.startswith("#"):
            if cur:
                steps.append(dict(cur))
        elif line[:1] == "b" and " " in line:
            v, i = line[1:].split()
            cur[ids.get(i, i)] = int(v, 2) if set(v) <= {"0", "1"} else v
        elif line[:1] in "01" and len(line) > 1:
            cur[ids.get(line[1:], line[1:])] = int(line[0])
    # Yosys writes "#t" after each step's values (#0 opens, the last "#n" closes): one entry per step.
    short = [n.split(".")[-1] for n in names]
    rows = ["step " + " ".join(f"{s:>9}" for s in short)]
    for t, st in enumerate(steps, 1):
        rows.append(f"{t:>4} " + " ".join(f"{str(st.get(n, '-')):>9}" for n in names))
    header = ("Counterexample found by scripts/run_formal.py on the RTL with the d426302 fix removed\n"
              "(bus_idle no longer ignored in the grant cycle). Registered interconnect model, NRULES=2.\n"
              "Read it as: a burst is granted (dec_valid && dec_allow) in the cycle a switch is requested; the\n"
              "interconnect only sees it a cycle later, so bus_idle still reads 1 and 'swap' fires while\n"
              "'fv_beats' > 0 - the bank select flips while that burst is still transferring.\n"
              "CMD writes go to reg_addr 0; reg_wdata[3:0] is the command (3 ACTIVATE, 5 REVERT).\n\n")
    return header + "\n".join(rows) + "\n"


def write_md(data):
    """results/formal.md, generated from the same data as results/formal.json."""
    L = ["# Formal verification results (generated by scripts/run_formal.py)", "",
         "Engine: Yosys built-in SAT (MiniSAT) via yowasp-yosys. k = induction length; depth = BMC steps from reset.", "",
         "| Job | Property | Method | Result | k / depth | max SAT variables | seconds |", "|---|---|---|---|---:|---:|---:|"]
    method = dict(comb="one-step SAT, all state free", prove="k-induction", bmc="bounded model check")
    for r in data["jobs"]:
        L.append(f"| {r['job']} | {r['property']} | {method[r['mode']]} | {r['status']} | {r['depth'] or '-'} | "
                 f"{r['max_sat_variables'] or '-'} | {r['seconds']} |")
    if data["covers"]:
        L += ["", "| Reachability (cover) | Result | within depth | seconds |", "|---|---|---:|---:|"]
        L += [f"| {c['cover']} | {c['status']} | {c['depth']} | {c['seconds']} |" for c in data["covers"]]
    if data["mutants"]:
        L += ["", "| Planted bug | Proof expected to fail | Result |", "|---|---|---|"]
        L += [f"| {m['mutant']} | {m['job']} | {'caught (FAILED)' if m['caught'] else 'MISSED: ' + m['status']} |"
              for m in data["mutants"]]
    (ROOT / "results" / "formal.md").write_text("\n".join(L) + "\n")


if __name__ == "__main__":
    sys.exit(main())
