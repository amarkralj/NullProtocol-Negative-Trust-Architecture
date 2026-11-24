# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Score v1.0 against a pre-registration (results/v10_expected.json, or the hold-out with --holdout).

Every dataset is replayed through the recommended configuration of v0.9 (before) and v1.0 (after). A dataset counts as
detected if at least one pre-registered evidence kind is raised. The first run of each pre-registration is written once
(results/v10_first_run.json, results/v10_holdout_run.json) and never overwritten; later runs go to results/v10.json.

    python scripts/run_v10.py            # the 55 development datasets
    python scripts/run_v10.py --holdout  # the hold-out (run once, after the rules are frozen)
"""
import hashlib, json, pathlib, sys
from collections import defaultdict
from npcore import sources
from npcore.engine import Engine, version_preset
from npcore.anon import pseudonymize

HOLD = "--holdout" in sys.argv
ROOT = pathlib.Path("data/splunk_attack_data")
PRE = pathlib.Path("results/v10_holdout_expected.json" if HOLD else "results/v10_expected.json")
FIRST = pathlib.Path("results/v10_holdout_run.json" if HOLD else "results/v10_first_run.json")
LATEST = pathlib.Path("results/v10_holdout_latest.json" if HOLD else "results/v10.json")
RULE_FILES = ["src/npcore/engine.py", "src/npcore/sources.py", "src/npcore/aiguard.py", "src/npcore/signals.py",
              "src/npcore/cloudlogs.py", "src/npcore/okta.py", "src/npcore/trust.py", "src/npcore/policy.py"]


def files_for(key):
    for base in (ROOT / "attack_techniques" / key, ROOT / key):
        if base.is_dir():
            return sorted(f for f in base.rglob("*") if f.is_file() and f.suffix != ".yml")
    d, stem = (ROOT / key).parent, (ROOT / key).name           # AI datasets: one file per dataset name
    if not d.is_dir():
        return []
    own = sorted(f for f in d.glob(stem + ".*") if f.suffix != ".yml")
    return own or sorted(f for f in d.iterdir() if f.is_file() and f.suffix != ".yml")   # folder-level datasets (MCP, Ollama)


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
    eng.end_of_day(day)
    return found, {s: int(l) for s, l in eng.level.items() if int(l) > 0}


def main():
    pre = json.loads(PRE.read_text())
    groups = pre["datasets"] if "datasets" in pre else {g: v for g, v in pre.items() if not g.startswith("_")}
    if "datasets" in pre:
        groups = {"holdout": groups}
    rows, tally = {}, defaultdict(lambda: defaultdict(int))
    for group, items in groups.items():
        for key, exp in items.items():
            if key.startswith("_"):
                continue
            fs = files_for(key)
            events = sources.load(fs) if fs else []
            row = {"group": group, "files": [str(f.relative_to(ROOT)) for f in fs], "events_mapped": len(events),
                   "expected": exp}
            if exp is None:
                row["status"] = "not scored"
            elif exp == "format test":
                row["status"] = "format test: read" if events else "format test: not readable"
                if events:
                    k, lv = replay(events, "v1.0")
                    row["v1.0"] = {"detections": {a: sorted(b) for a, b in k.items()}, "levels": lv}
            elif not fs:
                row["status"] = "not downloaded"
            elif not events:
                row["status"] = "not readable"
            else:
                for v in ("v0.9", "v1.0"):
                    k, lv = replay(events, v)
                    row[v] = {"detections": {a: sorted(b) for a, b in k.items()}, "as_expected": bool(set(exp) & set(k)),
                              "levels": lv}
                row["status"] = "detected" if row["v1.0"]["as_expected"] else "missed"
            tally[group][row["status"]] += 1
            if "v0.9" in row:
                tally[group]["v0.9 detected"] += row["v0.9"]["as_expected"]
            rows[key] = row
            print(f"{key[-58:]:58s} ev {len(events):5d} {row['status']:22s} "
                  + (f"v0.9 {'Y' if row['v0.9']['as_expected'] else '-'}  {sorted(row['v1.0']['detections'])}" if "v0.9" in row else ""))
    scored = [r for r in rows.values() if r["status"] in ("detected", "missed", "not readable", "not downloaded")]
    summary = {"pre_registration": str(PRE), "pre_registration_sha256": hashlib.sha256(PRE.read_bytes()).hexdigest(),
               "rule_files_sha256": {f: hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest() for f in RULE_FILES},
               "scored": len(scored), "detected_v1.0": sum(r["status"] == "detected" for r in scored),
               "detected_v0.9": sum(r.get("v0.9", {}).get("as_expected", False) for r in scored),
               "not_readable": sum(r["status"] in ("not readable", "not downloaded") for r in scored),
               "by_group": {g: dict(t) for g, t in tally.items()}}
    print(json.dumps({k: v for k, v in summary.items() if k != "rule_files_sha256"}, indent=1))
    out = json.dumps({"summary": summary, "datasets": pseudonymize(rows)}, indent=1)
    if not FIRST.exists():
        FIRST.write_text(out)
        print("first run written to", FIRST)
    LATEST.write_text(out)


if __name__ == "__main__":
    main()
