"""The independent model (tests/independent_model.py) against the production model, plus coverage
of its adversarial vectors. The RTL is compared with the same vectors in scripts/run_rtl.py."""
import random
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests"))
sys.path.insert(0, str(ROOT / "tools"))
import independent_model as ind  # noqa: E402
from hsm_common import Policy, Rule, check_txn, validate_update  # noqa: E402


def _prod_rules(bank):
    return [Rule(k, r["owner"], r["start"], r["end"], bool(r["r"]), bool(r["w"]), bool(r["priv"]), r["burst"])
            for k, r in enumerate(bank) if r and r["valid"]]


def test_independent_model_does_not_import_production_code():
    src = (ROOT / "tests" / "independent_model.py").read_text()
    imports = [l for l in src.splitlines() if l.strip().startswith(("import ", "from "))]
    assert imports and not any(m in l for l in imports
                               for m in ("hsm_common", "tools", "policy_generator", "policy_signer", "trace_validator"))


def test_decisions_agree_with_production_model():
    rng, n = random.Random(5), 0
    for rules in ind.monitor_policies():
        bank = ind._bank(rules)
        prod = _prod_rules(bank)
        for m, a, w, p, b in ind.monitor_transactions(rules, rng):
            assert ind.decide(bank, m, a, w, p, b) == check_txn(prod, m, a, w, p, b)[:2], (rules, m, hex(a), w, p, b)
            n += 1
    assert n > 5000


def test_validation_agrees_with_production_model():
    compared = 0
    for base, writes, req, ver, count, expect in ind.validator_vectors():
        slots = {s: (start, end, attr) for s, start, end, attr in writes}
        if any(a & ind.RESERVED_ATTR_BITS for _, _, _, a in writes):
            continue                                    # malformed writes: modelled only by RTL + independent model
        rules = [Rule(s, a >> 16 & 15, st, en, bool(a >> 8 & 1), bool(a >> 9 & 1), bool(a >> 10 & 1), a & 255)
                 for s, (st, en, a) in slots.items() if a >> 31]
        if count != len(rules):
            continue                                    # declared-count mismatches: likewise
        active = _prod_rules(ind._bank(ind.BASE)) if base else []
        got = validate_update(Policy(req, ver, 0, rules), active, ind.BASE_VERSION if base else 0, boot_window=not base)
        assert got == expect, (base, writes, req, ver, count)
        compared += 1
    assert compared > 1000


def test_vectors_cover_every_check_and_every_slot():
    vecs = ind.validator_vectors()
    assert set(Counter(v[5][0] for v in vecs)) == set(range(13))                     # every error code + accept
    assert {v[5][1] for v in vecs if 4 <= v[5][0] <= 11} == set(range(8))           # every slot reported
    assert {w[0] for v in vecs if v[5] == (0, 0) for w in v[1] if w[3] >> 31} == set(range(8))  # accepted, all slots
    rng = random.Random(3)
    reasons, slots_granted = Counter(), set()
    for rules in ind.monitor_policies():
        bank = ind._bank(rules)
        for txn in ind.monitor_transactions(rules, rng):
            allow, reason = ind.decide(bank, *txn)
            reasons[reason] += 1
            if allow:
                slots_granted |= {k for k, r in enumerate(bank) if r and r["valid"] and r["owner"] == txn[0]
                                  and r["start"] <= txn[1] <= r["end"]}
    assert set(reasons) == set(range(8)) and slots_granted == set(range(8))


def test_model_spot_checks():
    bank = ind._bank(ind.BASE)
    assert ind.decide(bank, 1, 0x10008000, 1, 0, 1) == (0, ind.NO_RULE)        # protected DMA window
    assert ind.decide(bank, 0, 0x0000F000, 0, 0, 1) == (0, ind.PRIV)           # privileged peripheral
    assert ind.decide(bank, 1, 0x1000FFC0, 1, 0, 16) == (1, ind.OK)            # burst ends on the last byte
    assert ind.decide(bank, 1, 0x1000FFC4, 1, 0, 16) == (0, ind.SPAN)
    edit = [x for x in ind.BASE if x[0] != 3] + [(3, 0x10009000, 0x1001FFFF, ind.attr_word(1, 1, 1, 0, 16))]
    assert ind.validate(bank, edit, 1, 5, 5, 4, False) == (ind.E_ESCAPE, 3)
    assert ind.validate(bank, list(ind.BASE), 1, 4, 5, 4, False) == (ind.E_VERSION, 0)
