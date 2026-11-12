"""RTL, firmware and Python must agree on every shared constant and on the authority table."""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
from hsm_common import E, ENVELOPES, V, load_policy  # noqa: E402

SVH = (ROOT / "rtl" / "hsm_defs.svh").read_text()
REGS = (ROOT / "firmware" / "include" / "hsm_regs.h").read_text()
HOST = (ROOT / "firmware" / "src" / "hal_host.c").read_text()


def svh_params(prefix):
    found = re.findall(rf"\b({prefix}_[A-Z_]+)\s*=\s*\d+'([hd])([0-9A-Fa-f_]+)", SVH)
    return {name: int(val.replace("_", ""), 16 if base == "h" else 10) for name, base, val in found}


def test_error_and_violation_codes():
    assert {k[2:]: v for k, v in svh_params("E").items()} == E
    assert {k[2:]: v for k, v in svh_params("V").items()} == V
    c_err = {k: int(v) for k, v in re.findall(r"HSM_E_([A-Z_]+)\s*=\s*(\d+)", REGS)}
    assert c_err == E


def test_states_commands_registers():
    for sv, c in (("S", "HSM_S"), ("C", "HSM_C")):
        rtl = {k[2:]: v for k, v in svh_params(sv).items()}
        fw = {k: int(v) for k, v in re.findall(rf"{c}_([A-Z_]+)\s*=\s*(\d+)", REGS)}
        assert rtl == fw and len(rtl) >= 7, sv
    rtl_regs = {k[2:]: v for k, v in svh_params("A").items()}
    fw_regs = {k: int(v, 16) for k, v in re.findall(r"#define HSM_REG_([A-Z_]+)\s+0x([0-9A-F]+)u", REGS)}
    assert rtl_regs == fw_regs and len(rtl_regs) == 9
    assert "32'h7FF0_F800" in SVH and "0x7FF0F800u" in REGS


def test_authority_table_matches_everywhere():
    lo = dict(re.findall(r"4'd(\d): env_lo = 32'h([0-9A-F_]+);", SVH))
    hi = dict(re.findall(r"4'd(\d): env_hi = 32'h([0-9A-F_]+);", SVH))
    burst = dict(re.findall(r"4'd(\d): env_burst = 8'd(\d+);", SVH))
    c_rows = re.findall(r"\{0x([0-9A-F]+)u, 0x([0-9A-F]+)u, (\d), (\d), (\d+), (\d)\}", HOST)
    assert len(c_rows) == len(ENVELOPES) == 3
    for o, (elo, ehi, r, w, b, pf) in ENVELOPES.items():
        assert int(lo[str(o)].replace("_", ""), 16) == elo
        assert int(hi[str(o)].replace("_", ""), 16) == ehi
        assert int(burst[str(o)]) == b
        assert tuple(int(x, 16) for x in c_rows[o][:2]) == (elo, ehi)
        assert tuple(int(x) for x in c_rows[o][2:]) == (r, w, b, pf)
    # read/write/privilege-floor functions in the RTL
    assert "env_r = (o <= 4'd2)" in SVH and "env_w = (o == 4'd0 || o == 4'd1)" in SVH and "env_pf = (o == 4'd2)" in SVH


def test_static_policy_default_is_v1():
    top = (ROOT / "rtl" / "security_monitor_top.sv").read_text()
    words = re.findall(r"80'h([0-9A-F]{20})", top)
    packed = {}
    for r in load_policy(ROOT / "examples" / "policy_v1.json").rules:
        attr = (r.priv << 10) | (r.write << 9) | (r.read << 8) | r.max_burst
        packed[r.slot] = (1 << 79) | (r.owner << 75) | (r.start << 43) | (r.end << 11) | attr
    assert [int(w, 16) for w in reversed(words)] == [packed[s] for s in sorted(packed)]
