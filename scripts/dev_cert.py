# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Development replay: python scripts/dev_cert.py r6.2 "nt v0.9" "zt_strong@v0.9" ...
Same protocol as the release (calibration to 5 cases / week / 1,000 users in days 60-150, HR notice periods for all).
Prints detected, prevented and innocent users restricted (L3+) per 1,000. Optional weights: W:kind=value."""
import multiprocessing as mp, pathlib, pickle, sys, json
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from evaluate_release import cfg_for  # noqa: E402


def run(args):
    rel, a, weights, rb = args
    fixed = None
    if "|S" in a:
        a, fixed = a.split("|S")[0], float(a.split("|S")[1])
    from npcore import policy as P, signals as S
    from npcore.cert import replay, score, prepare, calibrate, notices, with_notices
    S.W.update(weights)
    data = pickle.loads(pathlib.Path(f"data/cert/derived/{rel.replace('.', '')}_events.pkl").read_bytes())
    events, partners, _ = prepare(data, 60)
    events = with_notices(events, notices(release=rel))
    cfg = cfg_for(a)
    cfg.device_attribution = False
    cfg.warmup_days = 60
    f = fixed or calibrate(data, cfg, partners, events, budget_per_week=5.0 * len(data.users) / 1000,
                           grid=(1, 1.25, 1.5, 1.75, 2, 2.5, 3, 4, 6, 8, 12, 16, 24),
                           restrict_per_week=None if rb is None else rb * len(data.users) / 1000)
    cfg.policy = P.PolicyConfig(thresholds=tuple(x * f for x in cfg.policy.thresholds))
    cfg.alert_threshold *= f
    r = score(data, replay(data, cfg, partners=partners, events=events), a)
    det = [s for s in range(1, 6) if r.get(f"s{s}:detected_pct")]
    return (f"{rel} {a:22s} {json.dumps(weights) if weights else '':28s} scale {f:<4} detected {r['detected_pct']:5.1f}% "
            f"{det if rel != 'r4.2' else ''} prevented {r['prevented_pct']:5.1f}% innocents L3+/1000 {r['false_l3_users_per_1000']:6.1f} "
            f"cases {r['cases_total']}")


if __name__ == "__main__":
    rel = sys.argv[1]
    weights = dict((k[2:].split("=")[0], float(k.split("=")[1])) for k in sys.argv[2:] if k.startswith("W:"))
    rb = next((float(a[2:]) for a in sys.argv[2:] if a.startswith("B:")), None)   # restriction budget / week / 1,000
    archs = [a for a in sys.argv[2:] if not a.startswith(("W:", "B:"))]
    with mp.Pool(min(5, len(archs))) as pool:
        for line in pool.map(run, [(rel, a, weights, rb) for a in archs]):
            print(line, flush=True)
