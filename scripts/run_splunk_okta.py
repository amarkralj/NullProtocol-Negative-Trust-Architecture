# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Replay the recorded Okta attack logs from splunk/attack_data through the engine (v0.4 and v0.5).

The expected detection for each dataset is fixed here, before running, from the dataset's own description
(MITRE technique and title). Writes results/splunk_okta.json.
"""
import json, pathlib
from collections import defaultdict
from npcore import okta
from npcore.engine import Engine, version_preset
from npcore.anon import pseudonymize

EXPECTED = {   # dataset -> evidence kinds any of which counts as a detection (None: nothing should fire)
    "okta_single_factor_auth": {"no_mfa_login"},
    "okta_threatinsight_threat_detected": {"idp_risk"},
    "okta_suspicious_activity_reported_by_user": {"idp_risk"},
    "okta_unauth_access": {"app_denied"},
    "okta_new_api_token_created": {"identity_config_change"},
    "okta_new_device_enrolled": None,
    "okta_multiple_users_from_ip": {"password_spray"},
    "okta_multiple_accounts_lockout": {"password_spray"},
    "okta_web_session_multiple_ip": {"session_replay", "impossible_travel"},
    "okta_mfa_method_disabled": {"identity_config_change"},
    "okta_idp": {"identity_config_change"},
    "okta_multiple_city": {"session_replay", "impossible_travel"},
    "okta_mfa_login_failed": None,
    "okta_multiple_failed_mfa_pushes": {"mfa_fatigue"},
    "okta_multiple_failed_mfa_requests": {"mfa_fatigue"},
}


def replay(events, version):
    users = sorted({e.account for e in events})
    eng = Engine(version_preset(version), {u: u for u in users}, {u: "Unknown" for u in users})
    kinds = defaultdict(set)
    day = int(events[0].t // 24) + 1
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        for x in eng.observe(e, True):
            if x.weight > 0:
                kinds[x.kind].add(x.subject)
    levels = {s: int(l) for s, l in eng.level.items() if int(l) > 0}
    return kinds, levels, eng.ledger.verify()[0]


rows = {}
for d in sorted(pathlib.Path("data/splunk_attack_data").rglob("*.yml")):
    name = d.parent.name
    logs = list(d.parent.glob("*.log"))
    if name not in EXPECTED or not logs:
        continue
    events = okta.load(logs)
    row = {"technique": d.parent.parent.name, "events_mapped": len(events), "expected": sorted(EXPECTED[name] or [])}
    for v in ("v0.4", "v0.5"):
        kinds, levels, ok = replay(events, v) if events else ({}, {}, True)
        exp = EXPECTED[name]
        hit = (not any(k in kinds for k in ("mfa_fatigue", "password_spray", "idp_risk", "impossible_travel", "session_replay",
                                              "identity_config_change", "no_mfa_login", "app_denied"))) if exp is None else bool(exp & set(kinds))
        row[v] = {"detections": {k: sorted(v_) for k, v_ in kinds.items()}, "levels": levels, "as_expected": hit,
                  "account_level": sorted(s for s in levels if s.startswith("acct:")), "ledger_ok": ok}
    rows[name] = row
    print(f"{name:42s} events {len(events):3d}  v0.4 {'OK ' if row['v0.4']['as_expected'] else 'MISS'}  v0.5 {'OK ' if row['v0.5']['as_expected'] else 'MISS'}  "
          f"{sorted(k for k in row['v0.5']['detections'] if k not in ('new_device',))}")
n = len(rows)
print(f"\nas expected: v0.4 {sum(r['v0.4']['as_expected'] for r in rows.values())}/{n}, v0.5 {sum(r['v0.5']['as_expected'] for r in rows.values())}/{n}")
pathlib.Path("results/splunk_okta.json").write_text(json.dumps(pseudonymize(rows), indent=1))  # no lab identities in results
