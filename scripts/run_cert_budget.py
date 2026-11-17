# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""CERT replay under the v0.9 calibration protocol: every architecture is calibrated (days 60-150, no labels) to at most
5 cases per week and at most 1 user restricted (L3+) per week, both per 1,000 users. Releases r4.2, r6.2 and r6.1
(r6.1 was not used in any development). Writes results/cert_budget.json; earlier protocols' results are kept.

    python scripts/run_cert_budget.py r4.2 r6.2 r6.1
"""
import json, multiprocessing as mp, pathlib, pickle, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from evaluate_release import cfg_for  # noqa: E402

ARCHS = ["zt_alert", "zt_auto", "zt_strong", "zt_alert@v0.9", "zt_auto@v0.9", "zt_strong@v0.9", "nt v0.7", "nt v0.9"]
RESTRICT = 1.0
GRID = (1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4, 6, 8, 12, 16, 24)


def cache(rel):
    p = pathlib.Path(f"data/cert/derived/{rel.replace('.', '')}_events.pkl")
    if not p.exists():
        from npcore.cert import load
        p.write_bytes(pickle.dumps(load(release=rel)))
    return p


def run(args):
    rel, a = args
    from npcore import policy as P
    from npcore.cert import replay, score, prepare, calibrate, notices, with_notices
    data = pickle.loads(cache(rel).read_bytes())
    events, partners, _ = prepare(data, 60)
    events = with_notices(events, notices(release=rel))
    cfg = cfg_for(a)
    cfg.device_attribution = False
    cfg.warmup_days = 60
    n = len(data.users) / 1000
    f = calibrate(data, cfg, partners, events, budget_per_week=5.0 * n, grid=GRID, restrict_per_week=RESTRICT * n)
    cfg.policy = P.PolicyConfig(thresholds=tuple(x * f for x in cfg.policy.thresholds))
    cfg.alert_threshold *= f
    r = score(data, replay(data, cfg, partners=partners, events=events), a)
    r["threshold_scale"] = f
    print(rel, a, r["detected_pct"], r["prevented_pct"], r["false_l3_users_per_1000"], flush=True)
    return rel, a, r


if __name__ == "__main__":
    rels = sys.argv[1:] or ["r4.2", "r6.2", "r6.1"]
    for rel in rels:
        cache(rel)
    out_p = pathlib.Path("results/cert_budget.json")
    out = json.loads(out_p.read_text()) if out_p.exists() else {}
    with mp.Pool(4) as pool:
        for rel, a, r in pool.map(run, [(rel, a) for rel in rels for a in ARCHS]):
            out.setdefault(rel, {})[a] = r
    out["protocol"] = {"cases_per_week_per_1000": 5.0, "restricted_per_week_per_1000": RESTRICT, "window_days": [60, 150],
                       "grid": list(GRID), "hr_notice": "LDAP departures, known 30 days before the last month"}
    out_p.write_text(json.dumps(out, indent=1))
