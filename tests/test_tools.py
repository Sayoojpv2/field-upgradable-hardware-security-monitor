"""Python tools: example policies, packages, reference models, trace validation gate."""
import json
import struct
import sys
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import policy_generator as pg  # noqa: E402
import policy_signer as ps  # noqa: E402
import trace_validator as tv  # noqa: E402
from hsm_common import (E, HDR_SIGNED, HDR_SIZE, OWNERS, V, Rule, check_txn, load_policy,  # noqa: E402
                        parse_package, policy_to_json, validate_update)

EX = ROOT / "examples"
pol = lambda name: load_policy(EX / f"{name}.json")


def test_examples_are_generated_and_current():
    for name, p in pg.example_policies().items():
        assert json.loads((EX / f"{name}.json").read_text()) == policy_to_json(p), name


def test_update_chain_is_within_authority():
    active = pol("policy_v1")
    for v in (2, 3, 4):
        cand = pol(f"policy_v{v}")
        assert validate_update(cand, active.rules, active.version) == (E["NONE"], 0)
        active = cand


@pytest.mark.parametrize("name,err,slot", [
    ("atk_dma_expand", "ADDR_ESCAPE", 3), ("atk_dma_burst", "BURST_ESC", 1),
    ("atk_diag_write", "PERM_ESC", 2), ("atk_diag_unpriv", "PRIV_FLOOR", 2),
    ("atk_dma_foreign_modify", "FOREIGN", 0), ("atk_dma_foreign_delete", "FOREIGN", 4),
    ("atk_dma_claim_slot", "FOREIGN", 5), ("atk_dma_overlap", "OVERLAP", 5),
])
def test_attacks_rejected_by_authority_model(name, err, slot):
    v4 = pol("policy_v4")
    assert validate_update(pol(f"attacks/{name}"), v4.rules, v4.version) == (E[err], slot)


def test_authority_model_edge_cases():
    v1, v4 = pol("policy_v1"), pol("policy_v4")
    assert validate_update(v4, v1.rules, 4)[0] == E["VERSION"]                       # replay / old
    assert validate_update(v1, [], 0, boot_window=False)[0] == E["AUTH"]             # ROOT after boot
    assert validate_update(v1, [], 0, boot_window=True) == (E["NONE"], 0)            # boot restore
    bad = pg.Policy(OWNERS["DMA"], 5, 4, [Rule(0, 1, 0x1000_0010, 0x1000_0000, True, True, False, 4)])
    assert validate_update(bad, [], 4)[0] == E["RANGE"]
    for n in (2, 4, 6, 8):
        assert validate_update(pg.scaled_policy(n), [], 0, boot_window=True) == (E["NONE"], 0)


def test_monitor_model():
    rules = [Rule(0, 0, 0x1000, 0x1FFF, True, False, False, 4), Rule(1, 0, 0x0, 0xFFFF_FFFF, True, True, False, 8)]
    assert check_txn(rules, 0, 0x1000, True, 0, 1)[:2] == (False, V["WRITE_DENIED"])   # lowest slot wins
    assert check_txn(rules, 0, 0x1FFC, False, 0, 2)[:2] == (False, V["SPAN"])
    assert check_txn(rules, 0, 0xFFFF_FFFC, False, 0, 2)[:2] == (False, V["SPAN"])     # wrap-around
    assert check_txn(rules, 0, 0xFFFF_FFF8, False, 0, 2)[:2] == (True, V["OK"])
    assert check_txn(rules, 3, 0x1000, False, 1, 1)[:2] == (False, V["BAD_MASTER"])
    assert check_txn(rules, 0, 0x2000, False, 0, 0)[:2] == (False, V["BURST"])


def test_package_sign_verify_and_tamper(tmp_path):
    keys = tmp_path / "keys"
    ps.keygen(keys, tmp_path / "device_config.c")
    assert "hsm_trusted_keys" in (tmp_path / "device_config.c").read_text()
    v2 = pol("policy_v2")
    blob = ps.build_package(v2, ps.load_key(keys, "DMA"))
    assert len(blob) == HDR_SIZE + 12 * len(v2.rules)
    d = ps.verify(blob, keys)
    assert (d["requester"], d["version"], d["prev_version"]) == (1, 2, 1)
    assert d["rules"] == v2.rules
    tampered = bytearray(blob); tampered[16] ^= 1
    with pytest.raises(InvalidSignature):
        ps.verify(bytes(tampered), keys)
    other = ps.build_package(v2, ps.load_key(keys, "CPU"))   # wrong owner key
    with pytest.raises(InvalidSignature):
        ps.verify(other, keys)
    assert struct.unpack_from("<4s", blob)[0] == b"HSMP" and len(blob[:HDR_SIGNED]) == 56
    with pytest.raises(ValueError):
        parse_package(blob[:-1])


def test_keygen_keeps_existing_keys(tmp_path):
    ps.keygen(tmp_path, tmp_path / "c.c")
    first = (tmp_path / "dma.key").read_text()
    ps.keygen(tmp_path, tmp_path / "c.c")
    assert (tmp_path / "dma.key").read_text() == first
    Ed25519PrivateKey.from_private_bytes(bytes.fromhex(first.strip()))


def test_trace_corpus_and_policies():
    trace = tv.gen_traces()
    assert trace == tv.gen_traces()                                   # deterministic
    s4, _ = tv.replay(pol("policy_v4"), trace)
    assert s4["benign_rejected"] == 0 and s4["malicious_accepted"] == 0
    s1, _ = tv.replay(pol("policy_v1"), trace)
    assert s1["benign_rejected"] == 0 and s1["malicious_accepted"] > 0
    # every scenario's attacks are open in v1 and closed by its own update
    open_v1 = {t["scenario"] for t, d in zip(trace, tv.replay(pol("policy_v1"), trace)[1]) if t["label"] == "malicious" and d[0]}
    assert {"s1", "s2", "s3"} <= open_v1


@pytest.mark.parametrize("base,cand,ok", [
    ("policy_v1", "policy_v2", True), ("policy_v2", "policy_v3", True), ("policy_v3", "policy_v4", True),
    ("policy_v1", "candidates/cand_v2_overbroad", False), ("policy_v4", "candidates/cand_v5_dma_reopen", False),
    ("policy_v4", "attacks/atk_dma_expand", False),
])
def test_release_gate(base, cand, ok):
    r = tv.compare(pol(base), pol(cand), tv.gen_traces())
    assert r["recommended"] is ok, r["reasons"]


def test_gate_explains_regressions():
    r = tv.compare(pol("policy_v1"), pol("candidates/cand_v2_overbroad"), tv.gen_traces())
    assert r["hardware_check"] == "PASS"            # within DMA authority ...
    assert r["diff"]["regressions_benign"]          # ... but breaks legitimate DMA traffic
    assert "NO_RULE" in r["diff"]["regressions_benign"][0][1]
    r = tv.compare(pol("policy_v4"), pol("candidates/cand_v5_dma_reopen"), tv.gen_traces())
    assert r["hardware_check"] == "PASS" and r["diff"]["regressions_malicious"]
    assert {s for _, s, _ in r["remaining_undetected"]} == {"s1", "boundary"}
