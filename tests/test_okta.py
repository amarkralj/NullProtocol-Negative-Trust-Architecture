# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Okta System Log adapter and v0.5 identity-provider rules (synthetic Okta-format events)."""
from npcore import okta
from npcore.engine import Engine, version_preset


def ev(et, user, ts, res="SUCCESS", ip="10.0.0.1", lat=52.5, lon=13.4, ua="Mozilla", sid="S1", targets=None):
    return {"eventType": et, "published": ts, "outcome": {"result": res}, "actor": {"alternateId": user},
            "client": {"ipAddress": ip, "userAgent": {"rawUserAgent": ua}, "geographicalContext": {"country": "DE",
                       "geolocation": {"lat": lat, "lon": lon}}},
            "authenticationContext": {"externalSessionId": sid}, "debugContext": {"debugData": {}}, "target": targets or []}


def run(raw):
    t0 = okta._t(raw[0]["published"]) - 24 * 20
    evs = [x for x in (okta.to_event(e, t0) for e in raw) if x]
    users = sorted({e.account for e in evs})
    eng = Engine(version_preset("v0.5"), {u: u for u in users}, {u: "IT" for u in users})
    out = []
    for e in evs:
        out += eng.observe(e, True)
    return out


def test_mapping_of_core_event_types():
    t0 = okta._t("2026-01-01T10:00:00Z")
    assert okta.to_event(ev("user.session.start", "a", "2026-01-01T10:00:00Z"), t0).kind == "login"
    assert okta.to_event(ev("user.authentication.auth_via_mfa", "a", "2026-01-01T10:00:00Z", "FAILURE"), t0).attrs["result"] == "deny"
    assert okta.to_event(ev("system.idp.lifecycle.create", "a", "2026-01-01T10:00:00Z"), t0).attrs["what"] == "add_identity_provider"
    one_fa = ev("policy.evaluate_sign_on", "a", "2026-01-01T10:00:00Z", "ALLOW",
                targets=[{"type": "Rule", "detailEntry": {"policyRuleFactorMode": "1FA"}}])
    assert okta.to_event(one_fa, t0).attrs["mfa"] is False


def test_password_spray_is_evidence_against_the_accounts():
    raw = [ev("user.session.start", f"u{i}", f"2026-01-01T10:0{i}:00Z", "FAILURE", ip="185.1.1.1") for i in range(6)]
    out = run(raw)
    assert {x.subject for x in out if x.kind == "password_spray"} >= {f"acct:u{i}" for i in range(5)}


def test_impossible_travel_and_push_answers_are_not_replay():
    raw = [ev("user.session.start", "a", "2026-01-01T10:00:00Z", lat=37.8, lon=-122.2),
           ev("user.authentication.auth_via_mfa", "a", "2026-01-01T10:00:30Z", "FAILURE", ip="100.1.1.1", ua="OktaVerify"),
           ev("policy.evaluate_sign_on", "a", "2026-01-01T10:01:00Z", "ALLOW", ip="18.1.1.1", lat=50.1, lon=8.7, ua="python")]
    out = run(raw)
    assert any(x.kind == "impossible_travel" and x.subject == "acct:a" for x in out)
    assert not any(x.kind == "session_replay" and x.t < okta._t("2026-01-01T10:00:45Z") - okta._t("2026-01-01T10:00:00Z") + 24 * 20
                   for x in out)
