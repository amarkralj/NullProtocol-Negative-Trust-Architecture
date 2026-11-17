# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""v0.3: session-replay detection (token theft), proportionality, embedding API and HTTP service."""
import json
import threading
import urllib.request

from npcore.api import NegativeTrust
from npcore.engine import Engine, version_preset
from npcore.evaluate import run_one
from npcore.integrations import to_ocsf
from npcore.sim import Event, generate, DEPTS, PARTNER_DOMAINS


def _ev(t, acct, kind, **attrs):
    return Event(t, acct, kind, attrs=attrs)


def test_session_replay_contains_account_not_owner():
    eng = Engine(version_preset("v0.3"), {"v": "v"}, {"v": "Finance"})
    for d in range(15):
        e = _ev(d * 24 + 9, "v", "login", device="dv", ip="10.0.0.5", ip_type="corporate", sid=f"s{d}", sip="10.0.0.5")
        eng.decide(e); eng.observe(e, True)
    t = 15 * 24
    owner = _ev(t + 9, "v", "login", device="dv", ip="10.0.0.5", ip_type="corporate", sid="s15", sip="10.0.0.5")
    eng.observe(owner, True)
    thief = _ev(t + 10, "v", "read", device="dv", ip="91.1.1.1", sid="s15", sip="91.1.1.1")
    eng.observe(thief, True)
    back = _ev(t + 10.2, "v", "read", sid="s15", sip="10.0.0.5")
    ev = eng.observe(back, True)
    assert any(x.kind == "session_replay" and x.subject == "acct:v" for x in ev)
    assert eng.trust.trust("v", t + 10.3) > -0.5          # owner not blamed


def test_network_handover_is_not_replay():
    eng = Engine(version_preset("v0.3"), {"v": "v"}, {"v": "Sales"})
    e = _ev(9, "v", "login", device="dv", ip="91.0.0.1", ip_type="residential", sid="s", sip="91.0.0.1")
    eng.observe(e, True)
    for k in range(3):
        eng.observe(_ev(9.5 + k * 0.1, "v", "read", sid="s", sip="91.0.0.1"), True)
    ev = []
    for k in range(5):
        ev += eng.observe(_ev(10 + k * 0.1, "v", "read", sid="s", sip="92.0.0.2"), True)
    assert not any(x.kind == "session_replay" for x in ev)


def test_v03_contains_token_theft_without_blaming_victim():
    data = generate(102, scenario_set="adaptive")
    r = run_one(102, None, cfg=version_preset("v0.3"), scenario_set="adaptive", data=data)
    assert r["scenarios"]["token_theft"]["contained"]
    assert r["scenarios"]["token_theft"]["victim_person_contained"] is False


def test_proportionality_caps_careless_employee():
    eng = Engine(version_preset("v0.3"), {"n": "n"}, {"n": "Legal"}, partner_domains=PARTNER_DOMAINS)
    for k, to in enumerate(["a@clien.example", "b@suplier.example", "c@bank-partnr.example", "d@clien2.example"]):
        e = Event(20 * 24 + k, "n", "email", "f", "Legal", True, 2_000_000, attrs={"to": to, "external": True, "attachment": True})
        eng.observe(e, True)
    assert int(eng.level["n"]) <= 2


def _directory_and_records():
    org, events = generate(3, 40, 40)
    epoch = 1_767_225_600_000
    d = {"departments": {p: org.people[p].dept for p in org.people}, "path_departments": {f"//fs/{x}/": x for x in DEPTS},
         "partner_domains": list(PARTNER_DOMAINS), "epoch_ms": epoch}
    return org, d, [r for r in (to_ocsf(e, epoch) for e in events) if r]


def test_embedding_api_and_status():
    org, d, recs = _directory_and_records()
    nt = NegativeTrust(d, decoys=org.decoys)
    outs = list(nt.process_many(recs))
    assert any(o["type"] == "level" for o in outs)
    s = nt.status(next(o["subject"] for o in outs if o["type"] == "level"))
    assert {"level", "trust", "evidence"} <= set(s)
    assert nt.verify_ledger()["ok"]


def test_http_service_roundtrip():
    from http.server import ThreadingHTTPServer
    from npcore.serve import make_handler
    org, d, recs = _directory_and_records()
    nt = NegativeTrust(d)
    srv = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(nt))
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    body = "\n".join(json.dumps(r) for r in recs[:3000]).encode()
    res = json.loads(urllib.request.urlopen(urllib.request.Request(base + "/v1/events", data=body, method="POST")).read())
    assert res["accepted"] == 3000
    assert json.loads(urllib.request.urlopen(base + "/v1/health").read())["ok"]
    assert json.loads(urllib.request.urlopen(base + "/v1/ledger/verify").read())["ok"]
    srv.shutdown()
