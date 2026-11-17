# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)

import pytest

from npcore import policy as P
from npcore.deception import DecoyRegistry, Decoy, FILE, CREDENTIAL
from npcore.engine import Engine, preset
from npcore.evidence import Evidence
from npcore.ledger import Ledger
from npcore.privacy import Pseudonymizer, ReidentificationDenied
from npcore.trust import TrustConfig, TrustModel


def test_trust_starts_at_zero_and_goes_negative():
    tm = TrustModel()
    assert tm.trust("a", 0) == 0.0
    tm.add(Evidence(1, "a", "email_personal", 0.9, "x"))
    assert tm.trust("a", 1) == pytest.approx(-0.9)


def test_asymmetry_positive_history_cannot_hide_strong_negative():
    asym, sym = TrustModel(TrustConfig()), TrustModel(TrustConfig.symmetric())
    for m in (asym, sym):
        for d in range(60):                     # 60 clean days
            m.add(Evidence(d * 24, "a", "clean_day", -0.15, "clean"))
        m.add(Evidence(60 * 24, "a", "exfil_chain", 1.5, "chain"))
    t = 60 * 24 + 1
    assert asym.trust("a", t) < -0.9            # capped earned trust: chain still shows
    assert sym.trust("a", t) > asym.trust("a", t)


def test_weak_evidence_fades_strong_persists():
    tm = TrustModel()
    tm.add(Evidence(0, "a", "off_hours_login", 0.35, "weak"))
    tm.add(Evidence(0, "b", "exfil_chain", 1.5, "strong"))
    t = 14 * 24
    assert -tm.trust("a", t) < 0.35 * 0.1       # weak: half-life 4 days
    assert -tm.trust("b", t) > 1.5 * 0.7        # strong: half-life 30 days


def test_levels_and_decisions():
    cfg = P.PolicyConfig()
    assert P.level_for(0.0, cfg) == P.Level.L0_OBSERVE
    assert P.level_for(-1.0, cfg) == P.Level.L1_VERIFY
    assert P.level_for(-2.0, cfg) == P.Level.L2_DUAL_CONTROL
    assert P.level_for(-3.0, cfg) == P.Level.L3_READ_ONLY
    assert P.level_for(-5.0, cfg) == P.Level.L4_ISOLATE
    assert P.decide(P.Level.L0_OBSERVE, P.EGRESS) == P.ALLOW
    assert P.decide(P.Level.L2_DUAL_CONTROL, P.EGRESS) == P.DUAL_CONTROL
    assert P.decide(P.Level.L3_READ_ONLY, P.EGRESS) == P.DENY
    assert P.decide(P.Level.L3_READ_ONLY, P.READ) == P.ALLOW
    assert P.decide(P.Level.L4_ISOLATE, P.READ) == P.DENY


def test_ledger_detects_tampering():
    lg = Ledger()
    for i in range(5):
        lg.append("evidence", {"i": i}, float(i))
    assert lg.verify() == (True, None)
    lg.entries[2]["payload"]["i"] = 99
    ok, bad = lg.verify()
    assert not ok and bad == 2


def test_ledger_detects_deletion(tmp_path):
    lg = Ledger()
    for i in range(4):
        lg.append("evidence", {"i": i})
    del lg.entries[1]
    assert lg.verify()[0] is False
    lg2 = Ledger(); lg2.append("x", {"a": 1}); p = tmp_path / "l.jsonl"; lg2.dump_jsonl(p)
    assert Ledger.load_jsonl(p).verify()[0]


def test_pseudonymisation_and_four_eyes():
    pz = Pseudonymizer(key=b"k" * 32)
    p = pz.pseudonym("alice")
    assert p.startswith("P-") and "alice" not in p and pz.pseudonym("alice") == p
    lg = Ledger()
    with pytest.raises(ReidentificationDenied):
        pz.reidentify(p, {"dpo"}, "case 1", {"dpo", "ciso"}, lg)
    with pytest.raises(ReidentificationDenied):
        pz.reidentify(p, {"dpo", "ciso"}, "  ", {"dpo", "ciso"}, lg)
    assert pz.reidentify(p, {"dpo", "ciso"}, "case 1", {"dpo", "ciso"}, lg) == "alice"
    assert [e["payload"]["granted"] for e in lg.filter("reidentification")] == [False, False, True]


def test_decoy_strength_depends_on_context():
    reg = DecoyRegistry()
    reg.add(Decoy("d1", FILE, "Payroll_2026.xlsx", "//fs/Finance/restricted", "Finance"))
    reg.add(Decoy("d2", CREDENTIAL, "AKIA-svc", "wiki", "Engineering"))
    own = reg.check(0, "u1", "d1", "view", subject_dept="Finance")
    other = reg.check(0, "u2", "d1", "view", subject_dept="Sales")
    cred = reg.check(0, "u3", "d2", "use", subject_dept="Engineering")
    assert own.weight < other.weight < cred.weight
    assert own.source == "deception_weak" and cred.source == "deception"


class _E:
    def __init__(self, t, account, kind, **kw):
        self.t, self.account, self.kind = t, account, kind
        self.resource = kw.get("resource"); self.rdept = kw.get("rdept"); self.sensitive = kw.get("sensitive", False)
        self.nbytes = kw.get("nbytes", 0); self.attrs = kw.get("attrs", {})


def _engine(name="nt"):
    owners = {"v": "v", "m": "m"}
    reg = DecoyRegistry(); reg.add(Decoy("c1", CREDENTIAL, "AKIA-svc", "wiki", "Engineering"))
    return Engine(preset(name), owners, {"v": "Finance", "m": "Engineering"}, reg)


def test_vishing_contains_account_not_victim():
    eng = _engine()
    for d in range(16):     # learn the victim's normal context
        eng.observe(_E(d * 24 + 9, "v", "login", attrs={"device": "dv", "ip": "10.0.0.1", "ip_type": "corporate"}))
    t = 16 * 24 + 10
    eng.observe(_E(t, "ext", "call", attrs={"target": "v"}))
    eng.observe(_E(t + 0.3, "v", "login", attrs={"device": "evil", "ip": "185.1.1.1", "ip_type": "foreign"}))
    eng.observe(_E(t + 0.5, "v", "login", attrs={"device": "evil", "ip": "185.1.1.1", "ip_type": "foreign", "decoy_id": "c1", "credential": True}))
    assert eng.trust.trust("acct:v", t + 1) < -4
    assert eng.trust.trust("v", t + 1) > -0.5           # the person is not blamed
    attacker = _E(t + 2, "v", "egress_cloud", nbytes=10**8, attrs={"device": "evil", "ip": "185.1.1.1", "dest": "mega"})
    owner = _E(t + 2, "v", "read", resource="f", rdept="Finance")
    assert eng.decide(attacker) == P.DENY
    assert eng.decide(owner) == P.ALLOW


def test_perimeter_preset_never_blocks():
    eng = _engine("perimeter")
    e = _E(100, "m", "egress_usb", nbytes=10**9)
    assert eng.decide(e) == P.ALLOW
    assert eng.observe(e) == []


def test_review_dismissal_lifts_containment():
    eng = _engine()
    for i in range(4):
        eng.observe(_E(400 + i, "m", "egress_usb", nbytes=10**8))
    eng.observe(_E(404, "m", "email", sensitive=True, attrs={"to": "x@gmail.com", "external": True, "attachment": True}))
    assert eng.subject_level("m") >= P.Level.L3_READ_ONLY
    if "m" in eng.cases:
        eng.review("m", confirmed=False, t=410)
        assert eng.subject_level("m") < P.Level.L3_READ_ONLY
    assert eng.ledger.verify()[0]
