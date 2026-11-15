#!/usr/bin/env python3
"""Test the testbenches: plant known security bugs in a copy of the RTL and require that the
regression catches every one. A mutant that survives means a verification gap.

usage: mutation_check.py   (needs build/vectors and build/fw/mmio_tests.log: run `make sim-rtl` first)
"""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
IVERILOG = os.environ.get("IVERILOG", "iverilog")
VVP = os.environ.get("VVP", "vvp")
WORK = ROOT / "build" / "mutants"

# (description, file, original text, mutated text)
MUTANTS = [
    ("monitor ignores burst span (address wrap / region overrun)", "bus_security_monitor.sv",
     "else if (last[32] || last[31:0] > r_end(sel))", "else if (1'b0)"),
    ("monitor ignores privilege requirement", "bus_security_monitor.sv",
     "else if (r_priv(sel) && !txn_priv)", "else if (1'b0)"),
    ("monitor ignores unknown masters", "bus_security_monitor.sv",
     "if (txn_master >= NUM_OWNERS)", "if (1'b0)"),
    ("highest slot wins instead of lowest", "bus_security_monitor.sv",
     "for (int k = NRULES - 1; k >= 0; k--)", "for (int k = 0; k < NRULES; k++)"),
    ("bank writes reach the ACTIVE bank", "policy_bank.sv",
     "wire                      wbank = (DUAL != 0) ? ~sel : 1'b0;", "wire                      wbank = 1'b0;"),
    ("BEGIN does not clear the candidate bank", "policy_update_controller.sv",
     "assign bank_clear  = begin_ok;", "assign bank_clear  = 1'b0;"),
    ("validator skips address-envelope containment", "policy_validator.sv",
     "else if (r_start(ci) < env_lo(o) || r_end(ci) > env_hi(o))", "else if (1'b0)"),
    ("validator skips permission containment", "policy_validator.sv",
     "else if ((r_rd(ci) && !env_r(o)) || (r_wr(ci) && !env_w(o)))", "else if (1'b0)"),
    ("validator skips privilege floor", "policy_validator.sv",
     "else if (env_pf(o) && !r_priv(ci))", "else if (1'b0)"),
    ("validator skips burst containment", "policy_validator.sv",
     "else if (r_burst(ci) > env_burst(o))", "else if (1'b0)"),
    ("validator skips ownership check", "policy_validator.sv",
     "if (foreign && !same)", "if (1'b0)"),
    ("validator skips overlap check", "policy_validator.sv",
     "wire overlap = r_valid(ci)", "wire overlap = 1'b0 && r_valid(ci)"),
    ("validator accepts replayed versions", "policy_validator.sv",
     "else if (cand_version <= active_version)", "else if (cand_version < active_version)"),
    ("validator skips last overlap pair", "policy_validator.sv",
     "if (i == NRULES - 2) st <= VS_FINAL;", "if (i == NRULES - 3) st <= VS_FINAL;"),
    ("controller activates a rejected candidate", "policy_update_controller.sv",
     "if (val_ok) state <= S_READY;", "if (1'b1) state <= S_READY;"),
    ("switch does not wait for bus idle", "policy_update_controller.sv",
     "else if (bus_idle)                          state <= S_SWITCH;", "else                                        state <= S_SWITCH;"),
    ("no transaction hold during switch", "policy_update_controller.sv",
     "assign hold        = (state == S_WAIT_IDLE) || (state == S_SWITCH);", "assign hold        = 1'b0;"),
    ("config registers writable during an update (TOCTOU)", "policy_update_controller.sv",
     "wire cfg_open = (state == S_IDLE) || (state == S_ERROR);", "wire cfg_open = 1'b1;"),
    ("boot window never closes", "policy_update_controller.sv",
     "boot_window    <= 1'b0;          // first activation", "boot_window    <= boot_window;   // first activation"),
    ("revert does not restore the version", "policy_update_controller.sv",
     "active_version <= prev_version;", "active_version <= active_version;"),
    ("reserved ATTR bits accepted", "policy_update_controller.sv",
     "(rfield == 2'd2 && (reg_wdata & ATTR_RSVD_MASK) != 32'd0)", "1'b0"),
    ("switch trusts bus_idle in the grant cycle", "security_monitor_top.sv",
     ".bus_idle(bus_idle && !(dec_valid && dec_allow))", ".bus_idle(bus_idle)"),
]


class CompileError(Exception):
    pass

RUNS = [
    ("tb_policy_update", {}, ["+vdir=build/vectors"]),
    ("tb_security_monitor", {"MODE": 2}, []),
    ("tb_security_monitor", {"MODE": 1}, []),
    ("tb_security_monitor", {"MODE": 2}, ["+policy=build/vectors/policy_v4.hex", "+vectors=build/vectors/trace_v4.vec", "+check"]),
    ("tb_mmio_replay", {}, ["+log=build/fw/mmio_tests.log"]),
]


def regression_fails(rtl_dir: Path) -> str | None:
    """Return the first failing testbench run, or None if everything passed."""
    srcs = [str(p.relative_to(ROOT)) for p in sorted(rtl_dir.glob("*.sv"))]
    for tb, params, args in RUNS:
        out = WORK / f"{tb}.vvp"
        cmd = [IVERILOG, "-g2012", f"-I{rtl_dir.relative_to(ROOT).as_posix()}", "-Itb", "-s", tb, "-o", str(out.relative_to(ROOT))]
        cmd += [f"-P{tb}.{k}={v}" for k, v in params.items()] + srcs + [f"tb/{tb}.sv"]
        r = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        if r.returncode:   # a mutant that does not compile proves nothing about the tests
            raise CompileError(f"{tb}: {(r.stdout + r.stderr)[-500:]}")
        r = subprocess.run([VVP, "-n", str(out.relative_to(ROOT)), *args], cwd=ROOT, capture_output=True, text=True)
        if not re.search(r"TB_RESULT .* PASS", r.stdout):
            return f"{tb} {params} {' '.join(args)[:40]}"
    return None


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    mdir = WORK / "rtl"
    if regression_fails(ROOT / "rtl"):   # baseline must pass, or every mutant would look "killed"
        sys.exit("unmodified RTL fails the regression; fix that first")
    killed = 0
    for desc, fname, old, new in MUTANTS:
        shutil.rmtree(mdir, ignore_errors=True)
        shutil.copytree(ROOT / "rtl", mdir)
        src = (mdir / fname).read_text()
        if src.count(old) != 1:
            sys.exit(f"mutation anchor not found exactly once: {fname}: {old}")
        (mdir / fname).write_text(src.replace(old, new))
        try:
            caught = regression_fails(mdir)
        except CompileError as e:
            sys.exit(f"INVALID mutant (does not compile): {desc}\n{e}")
        killed += caught is not None
        print(f"{'KILLED ' if caught else 'SURVIVED'} {desc:56} {caught or ''}")
    print(f"MUTATION_RESULT killed={killed}/{len(MUTANTS)}")
    return 0 if killed == len(MUTANTS) else 1


if __name__ == "__main__":
    sys.exit(main())
