# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Replay the OTRF Security-Datasets Windows host datasets through the engine with the Windows endpoint adapter.
Writes results/otrf_windows.json.

Expected detection per dataset follows from its OTRF tactic (fixed before the first run):
    credential_access          -> edr_high (credential theft is the endpoint signal this adapter is for)
    defense_evasion            -> audit_tamper, edr_high or edr_low
    every other tactic         -> any endpoint evidence (edr_high, edr_low, remote_access_tool, audit_tamper,
                                  identity_config_change, new_principal)
These datasets record external-attacker tradecraft on lab machines; most of it is the job of an EDR product.
OTRF clears the event logs right before each recording; those log-cleared events (first two minutes of a recording)
are lab setup, not the attack, and are removed (the first run counted them: results/otrf_windows_first_run.json).
"""
import json, pathlib
from collections import defaultdict
from npcore import windows
from npcore.engine import Engine, version_preset
from npcore.anon import pseudonymize

ANY = {"edr_high", "edr_low", "remote_access_tool", "audit_tamper", "identity_config_change", "new_principal"}
EXPECTED = {"credential_access": {"edr_high"}, "defense_evasion": {"audit_tamper", "edr_high", "edr_low"}}


def replay(events, version):
    users = sorted({e.account for e in events})
    eng = Engine(version_preset(version), {u: u for u in users}, {u: "Unknown" for u in users})
    kinds = defaultdict(set)
    day = int(events[0].t // 24) + 1
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        for x in eng.observe(e, True):
            if x.weight > 0 and x.kind in ANY:
                kinds[x.kind].add(x.subject)
    return kinds, {s: int(l) for s, l in eng.level.items() if int(l) > 0}


rows = {}
for f in sorted(pathlib.Path("data/otrf/windows").rglob("*.json")):
    tactic = f.parent.name
    exp = EXPECTED.get(tactic, ANY)
    events = windows.load([f])
    if events:
        start = events[0].t
        events = [e for e in events if not (e.kind == "audit_change" and e.attrs.get("what") == "event log cleared"
                                            and e.t - start < 2 / 60)]
    row = {"tactic": tactic, "events_mapped": len(events), "expected": sorted(exp)}
    for v in ("v0.6", "v0.7"):
        kinds, levels = replay(events, v) if events else ({}, {})
        row[v] = {"detections": {k: sorted(s) for k, s in kinds.items()}, "as_expected": bool(exp & set(kinds)),
                  "accounts_with_evidence": len({s for ss in kinds.values() for s in ss}), "levels": levels}
    rows[f.stem] = row
    print(f"{tactic[:17]:17s} {f.stem[:58]:58s} ev {len(events):4d}  {'Y' if row['v0.7']['as_expected'] else '-'}  "
          f"{sorted(row['v0.7']['detections'])}")
by = defaultdict(lambda: [0, 0])
for r in rows.values():
    by[r["tactic"]][0] += 1; by[r["tactic"]][1] += r["v0.7"]["as_expected"]
print({k: f"{v[1]}/{v[0]}" for k, v in sorted(by.items())}, "total", sum(v[1] for v in by.values()), "/", len(rows))
pathlib.Path("results/otrf_windows.json").write_text(json.dumps(pseudonymize(rows), indent=1))  # no lab identities in results
