# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""OTRF Golden SAML (compound/GoldenSAMLADFSMailAccess): forged federation token, then mailbox access.

Download the two JSON files from https://github.com/OTRF/Security-Datasets (datasets/compound/GoldenSAMLADFSMailAccess)
into data/otrf/golden_saml/, then run this script. Writes results/otrf_golden_saml.json (identities pseudonymised).
Expected detections were fixed before the first run: identity_config_change and bulk_data_access.
"""
import collections
import json
import pathlib

from npcore import cloudlogs
from npcore.anon import pseudonymize
from npcore.engine import Engine, version_preset

FILES = ["data/otrf/golden_saml/AADAuditEvents.json", "data/otrf/golden_saml/OfficeActivityEvents.json"]
EXPECTED = ["identity_config_change", "bulk_data_access"]

evs = cloudlogs.load(FILES)
users = sorted({e.account for e in evs})
res = {}
for v in ("v0.5", "v0.6"):
    eng = Engine(version_preset(v), {u: u for u in users}, {u: "Unknown" for u in users})
    found = collections.defaultdict(set)
    for e in evs:
        for x in eng.observe(e, True):
            if x.weight > 0:
                found[x.kind].add(x.subject)
    res[v] = {"detections": {k: sorted(s) for k, s in found.items()},
              "levels": {s: int(lv) for s, lv in eng.level.items() if int(lv) > 0}}
    print(v, "detected:", ", ".join(res[v]["detections"]) or "nothing")
out = {"dataset": "OTRF Security-Datasets compound/GoldenSAMLADFSMailAccess", "expected": EXPECTED,
       "events_mapped": len(evs), **res}
pathlib.Path("results/otrf_golden_saml.json").write_text(json.dumps(pseudonymize(out), indent=1))
