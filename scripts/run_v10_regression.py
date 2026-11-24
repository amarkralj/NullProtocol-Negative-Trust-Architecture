# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Regression check for v1.0 on every recorded dataset of earlier releases (Splunk cloud and Okta, OTRF Windows).

v0.9 runs exactly as released (its own adapters); v1.0 runs with npcore.sources (a superset). For each dataset:
was the pre-registered detection kept, and which evidence kinds does v1.0 raise that v0.9 did not (each one is a
possible new false alarm and is listed). Writes results/v10_regression.json.
"""
import json, pathlib, sys
NEW = sys.argv[1] if len(sys.argv) > 1 else "v1.0"
from collections import defaultdict
from npcore import cloudlogs, okta, sources, windows
from npcore.engine import Engine, version_preset

ROOT = pathlib.Path("data")


def replay(events, version):
    users = sorted({e.account for e in events})
    eng = Engine(version_preset(version), {u: u for u in users}, {u: "Unknown" for u in users})
    found = defaultdict(set)
    day = int(events[0].t // 24) + 1
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        for x in eng.observe(e, True):
            if x.weight > 0:
                found[x.kind].add(x.subject)
    return found


def files(d):
    return sorted(f for f in d.iterdir() if f.is_file() and f.suffix in (".log", ".json", ".ndjson"))


def dirs_named(base, name):
    return [d for d in base.rglob(name) if d.is_dir()]


suites = {
    "splunk_cloud": (json.loads(pathlib.Path("results/splunk_cloud.json").read_text()), ROOT / "splunk_attack_data/attack_techniques",
                     cloudlogs.load, sources.load),
    "splunk_okta": (json.loads(pathlib.Path("results/splunk_okta.json").read_text()), ROOT / "splunk_attack_data",
                    okta.load, okta.load),
    "otrf_windows": (json.loads(pathlib.Path("results/otrf_windows.json").read_text()), ROOT / "otrf",
                     windows.load, windows.load),
}
out, total = {}, {}
for suite, (prev, base, load_old, load_new) in suites.items():
    t = defaultdict(int)
    for name, row in prev.items():
        exp = row.get("expected")
        if not exp:
            continue
        ds = dirs_named(base, name)
        fs = [f for d in ds for f in files(d)]
        if not fs:
            t["not on disk"] += 1
            continue
        ev_old, ev_new = load_old(fs), load_new(fs)
        if not ev_old and not ev_new:
            t["not readable"] += 1
            continue
        k9 = replay(ev_old, "v0.9") if ev_old else {}
        k10 = replay(ev_new, NEW) if ev_new else {}
        hit9, hit10 = bool(set(exp) & set(k9)), bool(set(exp) & set(k10))
        new_kinds = sorted(set(k10) - set(k9))
        t["scored"] += 1
        t["v0.9 detected"] += hit9
        t[NEW + " detected"] += hit10
        t["lost"] += hit9 and not hit10
        t["gained"] += hit10 and not hit9
        t["datasets with new kinds"] += bool(new_kinds)
        out[f"{suite}/{name}"] = {"expected": exp, "v0.9": hit9, NEW: hit10, "new_kinds_" + NEW: new_kinds,
                                  "new_kinds_expected": sorted(set(new_kinds) & set(exp))}
        if new_kinds or hit9 != hit10:
            print(f"{suite:13s} {name[:50]:50s} v0.9 {'Y' if hit9 else '-'} {NEW} {'Y' if hit10 else '-'} new {new_kinds}")
    total[suite] = dict(t)
print(json.dumps(total, indent=1))
pathlib.Path("results/v10_regression.json" if NEW == "v1.0" else f"results/{NEW.replace('.', '')}_regression.json").write_text(json.dumps({"summary": total, "datasets": out}, indent=1))
