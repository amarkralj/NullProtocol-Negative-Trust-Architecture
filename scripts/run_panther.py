# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.1 blind test, step 2: score v1.0 and v1.1 on the unit-test logs of panther-labs/panther-analysis, pinned to the
commit named in results/v11_panther_expected.json (pre-registered from rule names only).

    pip install pyyaml        # only this benchmark needs it
    python scripts/run_panther.py

Downloads every in-scope rule file (text, from the pinned commit) to data/panther/, reads its Tests, replays each test
log ALONE through the engine and applies the pre-registered metrics:
    positive test (ExpectedResult: true) of a scored rule -> detected if one of the rule's expected kinds is raised
    negative test (ExpectedResult: false) of any rule      -> false alarm if any evidence of weight >= 1.0 is raised
The first run is written once to results/v11_panther_run.json and never overwritten; later runs go to
results/v11_panther_latest.json.
"""
import hashlib, json, pathlib, urllib.request
from collections import defaultdict
import yaml
from npcore import sources
from npcore.engine import Engine, version_preset

PRE = pathlib.Path("results/v11_panther_expected.json")
OUT = pathlib.Path("data/panther")
FIRST, LATEST = pathlib.Path("results/v11_panther_run.json"), pathlib.Path("results/v11_panther_latest.json")
VERSIONS = tuple(__import__("os").environ.get("NP_VERSIONS", "v1.0,v1.1").split(","))
RULE_FILES = ["src/npcore/engine.py", "src/npcore/sources.py", "src/npcore/aiguard.py", "src/npcore/opclass.py",
              "src/npcore/signals.py", "src/npcore/cloudlogs.py", "src/npcore/okta.py"]


def fetch(sha, path):
    dest = OUT / path
    if not dest.exists():
        dest.parent.mkdir(parents=True, exist_ok=True)
        import time
        for k in range(5):                                     # network retries only; nothing is scored before all files exist
            try:
                with urllib.request.urlopen(f"https://raw.githubusercontent.com/panther-labs/panther-analysis/{sha}/{path}",
                                            timeout=60) as r:
                    data = r.read(2_000_000)
                break
            except OSError:
                if k == 4:
                    raise
                time.sleep(5 * (k + 1))
        data.decode("utf-8")                                   # text only
        dest.write_bytes(data)
    return dest


def events_of(log):
    if isinstance(log, str):
        log = json.loads(log)
    evs = [e for e in sources.convert(log) if e.account]
    if not evs:
        return []
    t0 = min(e.t for e in evs) - 24 * 20                       # past any learning period, like the recorded replays
    for e in evs:
        e.t -= t0
    return sorted(evs, key=lambda e: e.t)


def replay(evs, version):
    users = sorted({e.account for e in evs})
    eng = Engine(version_preset(version), {u: u for u in users}, {u: "Unknown" for u in users})
    out = []
    for e in evs:
        out += [x for x in eng.observe(e, True) if x.weight > 0]
    return out


def main():
    pre = json.loads(PRE.read_text())
    sha = pre["_commit"]
    rows, tests = {}, {v: defaultdict(int) for v in VERSIONS}
    for path, exp in pre["rules"].items():
        doc = yaml.safe_load(fetch(sha, path).read_text()) or {}
        scored = isinstance(exp, list)
        row = {"expected": exp, "tests": []}
        for t in doc.get("Tests") or []:
            pos = bool(t.get("ExpectedResult"))
            try:
                evs = events_of(t.get("Log") or {})
            except (ValueError, KeyError, TypeError, AttributeError):
                evs = []
            rec = {"name": t.get("Name"), "positive": pos, "readable": bool(evs)}
            for v in VERSIONS:
                ev = replay(evs, v) if evs else []
                kinds = sorted({x.kind for x in ev})
                strong = sorted({x.kind for x in ev if x.weight >= 1.0})
                rec[v] = {"kinds": kinds}
                if pos and scored:
                    hit = bool(set(exp) & set(kinds))
                    rec[v]["detected"] = hit
                    tests[v]["positives"] += 1
                    tests[v]["positives detected"] += hit
                    tests[v]["positives readable"] += bool(evs)
                elif not pos:
                    fa = bool(strong)
                    rec[v]["false_alarm"] = strong if fa else False
                    tests[v]["negatives"] += 1
                    tests[v]["negatives false alarm"] += fa
                    tests[v]["negatives readable"] += bool(evs)
            row["tests"].append(rec)
        if scored:
            for v in VERSIONS:
                ps = [r[v].get("detected") for r in row["tests"] if r["positive"]]
                if ps:
                    tests[v]["rules with positives"] += 1
                    tests[v]["rules all positives detected"] += all(ps)
                    tests[v]["rules some positive detected"] += any(ps)
        rows[path] = row
    summary = {"panther_commit": sha, "pre_registration_sha256": hashlib.sha256(PRE.read_bytes()).hexdigest(),
               "rule_files_sha256": {f: hashlib.sha256(pathlib.Path(f).read_bytes()).hexdigest() for f in RULE_FILES},
               "by_version": {v: dict(t) for v, t in tests.items()}}
    for v, t in tests.items():
        print(f"{v}: positives detected {t['positives detected']} / {t['positives']} (readable {t['positives readable']}), "
              f"rules fully detected {t['rules all positives detected']} / {t['rules with positives']}, "
              f"false alarms {t['negatives false alarm']} / {t['negatives']} negatives (readable {t['negatives readable']})")
    out = json.dumps({"summary": summary, "rules": rows}, indent=1)
    if not FIRST.exists():
        FIRST.write_text(out)
        print("first run written to", FIRST)
    LATEST.write_text(out)


if __name__ == "__main__":
    main()
