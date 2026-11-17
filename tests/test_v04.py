# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""v0.4: detections modelled on documented incidents."""
from npcore.engine import Engine, version_preset
from npcore.evaluate import run_one
from npcore.sim import Event, generate
from npcore.sim_cases import CASE_SCENARIOS


def _eng(people, workloads=()):
    return Engine(version_preset("v0.4"), {p: p for p in people}, {p: "Finance" for p in people}, workloads=workloads)


def _warm(eng, acct, days=20, dev="d1", ip="10.0.0.1"):
    for d in range(days):
        e = Event(d * 24 + 9, acct, "login", attrs={"device": dev, "ip": ip, "ip_type": "corporate"})
        eng.decide(e); eng.observe(e, True)


def test_helpdesk_reset_then_new_device_is_account_takeover():
    eng = _eng(["v"]); _warm(eng, "v")
    eng.observe(Event(20 * 24 + 14, "v", "mfa_reset", attrs={"via": "helpdesk", "verified": False}), True)
    ev = eng.observe(Event(20 * 24 + 14.5, "v", "login", attrs={"device": "evil", "ip": "91.1.1.1", "ip_type": "residential"}), True)
    assert any(x.kind == "account_takeover_reset" and x.subject == "acct:v" for x in ev)
    assert eng.trust.trust("v", 20 * 24 + 15) > -0.5


def test_verified_reset_is_weak():
    eng = _eng(["v"]); _warm(eng, "v")
    eng.observe(Event(20 * 24 + 14, "v", "mfa_reset", attrs={"via": "helpdesk", "verified": True}), True)
    ev = eng.observe(Event(20 * 24 + 14.5, "v", "login", attrs={"device": "new-laptop", "ip": "10.0.0.2", "ip_type": "corporate"}), True)
    assert [x.weight for x in ev if x.kind == "account_takeover_reset"] == [0.8]


def test_push_bombing_goes_to_the_account():
    eng = _eng(["v"]); _warm(eng, "v")
    ev = []
    for k in range(6):
        ev += eng.observe(Event(20 * 24 + 22 + k * .05, "v", "mfa_push", attrs={"result": "deny"}), True)
    assert any(x.kind == "mfa_fatigue" and x.subject == "acct:v" for x in ev)


def test_activity_after_termination_is_strong():
    eng = _eng(["a"]); _warm(eng, "a")
    eng.observe(Event(20 * 24 + 17, "a", "lifecycle", attrs={"status": "terminated"}), True)
    ev = eng.observe(Event(23 * 24 + 20, "a", "login", attrs={"device": "d1", "ip": "10.0.0.1", "ip_type": "corporate"}), True)
    assert any(x.kind == "post_termination_activity" and x.weight == 4.0 for x in ev)


def test_session_presented_by_another_client_is_replay():
    eng = _eng(["v"]); _warm(eng, "v")
    eng.observe(Event(20 * 24 + 9, "v", "login", attrs={"device": "d1", "ip": "10.0.0.1", "ip_type": "corporate",
                                                         "sid": "S", "sip": "10.0.0.1", "ua": "Edge"}), True)
    ev = eng.observe(Event(20 * 24 + 21, "v", "config_change", sensitive=True,
                           attrs={"device": "d1", "ip": "91.2.2.2", "sid": "S", "sip": "91.2.2.2", "ua": "python-requests",
                                  "what": "add_admin_api_token"}), True)
    assert any(x.kind == "session_replay" and x.subject == "acct:v" for x in ev)
    assert all(x.subject != "v" for x in ev)


def test_workload_secret_search_hits_the_integration_account():
    eng = _eng(["svc"], workloads=["svc"])
    for d in range(20):
        for k in range(5):
            eng.observe(Event(d * 24 + k, "svc", "api_export", attrs={"ip": "10.9.0.5", "objects": 30, "query": "SELECT Id"}), True)
    ev = eng.observe(Event(21 * 24, "svc", "api_export", attrs={"ip": "185.1.1.1", "objects": 900,
                                                                "query": "SELECT * FROM Case WHERE Description LIKE '%AKIA%'"}), True)
    kinds = {x.kind for x in ev}
    assert {"secret_search", "workload_new_network", "workload_volume_spike"} <= kinds
    assert all(x.subject == "acct:svc" for x in ev)


def test_cases_set_runs_and_contains_all_cases():
    data = generate(5, scenario_set="cases")
    r = run_one(5, None, cfg=version_preset("v0.4"), scenario_set="cases", data=data)
    assert set(r["scenarios"]) == set(CASE_SCENARIOS)
    assert sum(v["contained"] for v in r["scenarios"].values()) >= 7
    assert r["ledger_ok"]


def test_v08_notice_period_turns_routine_egress_into_evidence():
    from npcore.signals import SignalExtractor
    from npcore.sim import Event
    sx = SignalExtractor({"u": "IT"}, warmup_days=1, v02=True, v04=True, v08=True)
    kinds = []
    for d in range(2, 12):                                   # routine USB use builds a habit
        kinds += [x.kind for x in sx.observe(Event(d * 24 + 10, "u", "egress_usb", nbytes=1_000_000))]
    assert kinds[-1] == "egress_habitual"
    sx.observe(Event(12 * 24, "u", "lifecycle", attrs={"status": "notice"}))
    after = [x.kind for x in sx.observe(Event(13 * 24 + 10, "u", "egress_usb", nbytes=1_000_000))]
    assert "leaver_egress" in after and "egress_habitual" not in after
