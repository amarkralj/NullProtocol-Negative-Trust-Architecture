# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""v0.2 mechanisms: adaptive scenarios, device-owner attribution, habitual egress, lookalike domains."""
from npcore.engine import Engine, preset
from npcore.evaluate import run_one
from npcore.signals import SignalExtractor, _edit_distance
from npcore.sim import Event, generate, ADAPTIVE_SCENARIOS


def test_adaptive_set_generates_all_scenarios():
    org, ev = generate(7, n_people=80, days=50, scenario_set="adaptive")
    assert [s["type"] for s in org.scenarios] == ADAPTIVE_SCENARIOS
    assert any(p.it_support for p in org.people.values()) and any(p.usb_user for p in org.people.values())
    assert {e.scenario for e in ev if e.scenario} == set(ADAPTIVE_SCENARIOS)


def test_instances_label_scenarios():
    org, _ = generate(3, n_people=200, days=60, scenario_set="standard", instances=2)
    names = [s["name"] for s in org.scenarios]
    assert "compromised#1" in names and "compromised#2" in names and len(names) == 12


def test_habitual_egress_is_weak_and_sensitive_stays_strong():
    sx = SignalExtractor({"a": "Sales"}, warmup_days=1, v02=True)
    kinds = []
    for d in range(2, 8):
        kinds += [x.kind for x in sx.observe(Event(d * 24 + 10, "a", "egress_usb", "f", "Sales", False, 50_000_000))]
    assert kinds[:3] == ["egress_removable"] * 3 and set(kinds[3:]) == {"egress_habitual"}
    strong = [x.kind for x in sx.observe(Event(9 * 24 + 10, "a", "egress_usb", "f", "Sales", True, 50_000_000))]
    assert strong == ["egress_removable"]


def test_lookalike_domain_and_repeat():
    assert _edit_distance("clien.example", "client.example") == 1
    sx = SignalExtractor({"a": "Legal"}, warmup_days=0, partner_domains=("client.example",), v02=True)
    def mail(t, to):
        return [x.kind for x in sx.observe(Event(t, "a", "email", "f", "Legal", True, 1_000_000,
                                                 attrs={"to": to, "external": True, "attachment": True}))]
    assert "lookalike_domain" in mail(30, "ap@client-example.co")
    assert "lookalike_repeat" in mail(60, "ap@client-example.co")
    assert "lookalike_domain" not in mail(90, "x@client.example")


def test_device_owner_attribution_blames_the_device_owner():
    owners = {"att": "att", "vic": "vic"}
    eng = Engine(preset("nt", v02=True), owners, {"att": "Engineering", "vic": "Finance"})
    login = lambda t, acct, dev: Event(t, acct, "login", attrs={"device": dev, "ip": "10.0.0.1", "ip_type": "corporate"})
    for d in range(0, 20):
        for who in ("att", "vic"):
            e = login(d * 24 + 9, who, f"dev-{who}")
            eng.decide(e); eng.observe(e, True)
    e = login(20 * 24 + 19, "vic", "dev-att")
    ev = eng.observe(e, True)
    assert any(x.kind == "cross_account_login" and x.subject == "att" for x in ev)
    mail = Event(20 * 24 + 19.5, "vic", "email", "f", "Finance", True, 3_000_000,
                 attrs={"device": "dev-att", "ip": "10.0.0.1", "to": "x.drop@protonmail.com", "external": True, "attachment": True})
    ev = eng.observe(mail, True)
    assert any(x.subject == "att" and x.kind == "email_personal" for x in ev)
    assert not any(x.subject == "vic" for x in ev)


def test_v02_reduces_victim_blaming_in_impersonation():
    data = generate(11, scenario_set="adaptive")
    v1 = run_one(11, None, cfg=preset("nt"), scenario_set="adaptive", data=data)
    v2 = run_one(11, None, cfg=preset("nt", v02=True), scenario_set="adaptive", data=data)
    assert v2["scenarios"]["impersonation"]["victim_person_contained"] is False
    assert v2["ledger_ok"] and v1["ledger_ok"]
