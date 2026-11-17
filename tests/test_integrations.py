# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""End-to-end: simulator events -> OCSF records -> engine gives the same decisions as running the
engine directly on the same events (for the event kinds OCSF carries)."""
from npcore import policy as P
from npcore.engine import Engine
from npcore.integrations import Directory, from_ocsf, to_ocsf, stream, caep_set, CAEP
from npcore.sim import generate, DEPTS, PARTNER_DOMAINS

KINDS = {"login", "read", "egress_usb", "email", "egress_cloud", "mfa_push", "mfa_reset", "lifecycle", "config_change",
         "detection", "record_read", "api_export"}


def _direct(org, events, cfg):
    eng = Engine(cfg, {p: p for p in org.people}, {p: org.people[p].dept for p in org.people}, org.decoys,
                 partner_domains=PARTNER_DOMAINS, workloads=[p for p in org.people if org.people[p].workload])
    out, day = [], 1
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        d = eng.decide(e)
        if d == P.STEP_UP:
            eng.confirm_stepup(e.account, e.t)
        eng.observe(e, d in (P.ALLOW, P.STEP_UP))
        out.append(d)
    return out, eng


import pytest


@pytest.mark.parametrize("version,sset", [("v0.2", "standard"), ("v0.3", "standard"), ("v0.4", "cases")])
def test_ocsf_roundtrip_matches_direct_engine(version, sset):
    org, events = generate(4, 60, 45, scenario_set=sset)
    events = [e for e in events if e.kind in KINDS and not e.attrs.get("credential")
              and not (e.kind == "email" and not e.attrs.get("attachment") and not e.attrs.get("external"))]
    epoch = 1_767_225_600_000
    d = Directory({p: org.people[p].dept for p in org.people}, {f"//fs/{x}/": x for x in DEPTS},
                  partner_domains=PARTNER_DOMAINS, epoch_ms=epoch,
                  workloads=tuple(p for p in org.people if org.people[p].workload))
    recs = [to_ocsf(e, epoch) for e in events]
    mapped = [from_ocsf(r, d) for r in recs]
    assert all(m is not None for m in mapped)
    from npcore.engine import version_preset
    a, eng_a = _direct(org, events, version_preset(version))
    b, eng_b = _direct(org, mapped, version_preset(version))
    assert a == b
    assert [x[1:] for x in eng_a.level_log] == [x[1:] for x in eng_b.level_log]
    assert all(abs(x[0] - y[0]) < 1 / 3600 for x, y in zip(eng_a.level_log, eng_b.level_log, strict=True))   # OCSF time is whole ms


def test_stream_emits_caep_for_containment():
    org, events = generate(1, 60, 50)
    epoch = 1_767_225_600_000
    d = Directory({p: org.people[p].dept for p in org.people}, {f"//fs/{x}/": x for x in DEPTS},
                  partner_domains=PARTNER_DOMAINS, epoch_ms=epoch)
    recs = [r for r in (to_ocsf(e, epoch) for e in events) if r]
    out = list(stream(recs, d, decoys=org.decoys))
    sets = [o["set"] for o in out if o["type"] == "caep"]
    assert any(CAEP + "risk-level-change" in s["events"] for s in sets)
    assert any(CAEP + "session-revoked" in s["events"] for s in sets)
    s = sets[0]
    assert {"iss", "jti", "iat", "aud", "sub_id", "events"} <= set(s)


def test_caep_payload_shape():
    sets = caep_set("acct:u001", 2, 4, 1_767_225_600, "https://nt.example/", "https://idp.example/caep", "account_compromise")
    rl = sets[0]["events"][CAEP + "risk-level-change"]
    assert rl["principal"] == "SESSION" and rl["current_level"] == "HIGH" and rl["previous_level"] == "MEDIUM"
    assert CAEP + "session-revoked" in sets[1]["events"]
