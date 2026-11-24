# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Score a lab run (lab/scenarios/*.sh inside the isolated VM): real Kubernetes API audit logs + step labels.

    python scripts/score_lab.py <run dir with audit.log and labels.jsonl> [versions, default v1.0.1,v1.0.2]

Metrics, fixed before the first lab run:
  * an ATTACK step is detected if the engine raises any evidence (weight > 0) on audit events inside the step's time
    window [t0, t1 + 1 s];
  * an ORDINARY step is a false alarm if evidence of weight >= 1.0 is raised inside its window;
  * the final containment level of every principal is reported (insider, stolen identity, ordinary staff).
Writes <run dir>/score.json; nothing is sent anywhere.
"""
import datetime as dt
import json
import pathlib
import sys
from collections import defaultdict

from npcore import sources
from npcore.engine import Engine, version_preset


def iso(s):
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() / 3600


def score(run: pathlib.Path, version: str):
    labels = [json.loads(x) for x in (run / "labels.jsonl").read_text().splitlines() if x.strip()]
    evs = sources.load([run / "audit.log"], shift=False)
    t_abs = [e.t for e in evs]
    t0 = t_abs[0] - 24 * 20
    for e in evs:
        e.t -= t0
    users = sorted({e.account for e in evs})
    eng = Engine(version_preset(version), {u: u for u in users}, {u: "Unknown" for u in users})
    found = []                                         # (absolute hour, weight, kind, subject, desc)
    day = int(evs[0].t // 24) + 1
    for e, ta in zip(evs, t_abs, strict=True):
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        for x in eng.observe(e, True):
            if x.weight > 0:
                found.append((ta, x.weight, x.kind, x.subject, x.desc))
    steps, per_tech = [], defaultdict(lambda: [0, 0])
    for lb in labels:
        a, b = iso(lb["t0"]), iso(lb["t1"]) + 1 / 3600
        hits = [f for f in found if a <= f[0] <= b]
        strong = [f for f in hits if f[1] >= 1.0]
        row = dict(lb, evidence=sorted({f"{k}:{w}" for _, w, k, _, _ in hits}))
        if lb["label"] == "attack":
            row["detected"] = bool(hits)
            per_tech[lb["technique"]][0] += 1
            per_tech[lb["technique"]][1] += bool(hits)
        else:
            row["false_alarm"] = bool(strong)
        steps.append(row)
    att = [s for s in steps if s["label"] == "attack"]
    ordi = [s for s in steps if s["label"] == "ordinary"]
    levels = {s: int(l) for s, l in eng.level.items() if int(l) > 0}
    return {"version": version, "events_read": len(evs), "attack_steps": len(att),
            "attacks_detected": sum(s["detected"] for s in att), "ordinary_steps": len(ordi),
            "false_alarms": sum(s["false_alarm"] for s in ordi),
            "per_technique": {k: {"steps": v[0], "detected": v[1]} for k, v in sorted(per_tech.items())},
            "final_levels": levels, "steps": steps}


def main():
    run = pathlib.Path(sys.argv[1])
    versions = (sys.argv[2] if len(sys.argv) > 2 else "v1.0.1,v1.0.2").split(",")
    res = {v: score(run, v) for v in versions}
    (run / "score.json").write_text(json.dumps(res, indent=1))
    for v, r in res.items():
        print(f"{v}: attacks detected {r['attacks_detected']} / {r['attack_steps']}, false alarms {r['false_alarms']} / "
              f"{r['ordinary_steps']} ordinary steps, events read {r['events_read']}, levels {r['final_levels']}")


if __name__ == "__main__":
    main()
