# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""CERT Insider Threat Test Dataset r6.2 (4,000 users, 5 labelled insiders, one per scenario), same protocol as the
r4.2 release replay (HR notice periods from the LDAP snapshots are given to every architecture; v0.8 weights come
from results/train_v08.json, trained on r4.2 only): 60-day learning period, threshold calibration in days 60-150 (before the first labelled incident,
day 223) to a budget of 5 cases per week per 1,000 users, labels used only for scoring. Writes results/release_cert_r62_v08.json (the v0.7 run is kept in
results/release_cert_r62_v07.json).

    python scripts/run_cert_r62.py
"""
import json, multiprocessing as mp, pathlib, pickle, sys, time
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from evaluate_release import cfg_for  # noqa: E402

CACHE = pathlib.Path("data/cert/derived/r62_events.pkl")
ARCHS = ["zt_alert", "zt_auto", "zt_strong", "nt v0.2", "nt v0.3", "nt v0.7", "nt v0.8", "nt v0.8 notice-1.2"]
TRAINED = pathlib.Path("results/train_v08.json")      # v0.8 weights trained on r4.2 only


def _run(a):
    from npcore import policy as P, signals as S
    from npcore.cert import replay, score, prepare, calibrate, notices, with_notices
    best = json.loads(TRAINED.read_text())["best"]
    S.W["channel_burst"], S.W["leaver_egress"] = best["channel_burst"], best["leaver_egress"]
    if a.endswith("notice-1.2"):          # variant shown for comparison: better on r4.2 detection, +1.1 false L3 / 1,000
        S.W["channel_burst"], S.W["leaver_egress"] = 0.0, 1.2
    data = pickle.loads(CACHE.read_bytes())
    events, partners, _ = prepare(data, 60)
    events = with_notices(events, notices(release="r6.2"))     # same HR input for every architecture
    cfg = cfg_for(a.split(" notice")[0])
    cfg.device_attribution = False
    cfg.warmup_days = 60
    f = calibrate(data, cfg, partners, events, budget_per_week=5.0 * len(data.users) / 1000)
    cfg.policy = P.PolicyConfig(thresholds=tuple(x * f for x in cfg.policy.thresholds))
    cfg.alert_threshold *= f
    t0 = time.time()
    sc = score(data, replay(data, cfg, partners=partners, events=events), a)
    sc["threshold_scale"] = f
    sc["replay_seconds"] = round(time.time() - t0)
    print(a, "done", flush=True)
    return a, sc


if __name__ == "__main__":
    if not CACHE.exists():
        from npcore.cert import load
        CACHE.write_bytes(pickle.dumps(load(release="r6.2")))
    d = pickle.loads(CACHE.read_bytes())
    print(len(d.users), "users", len(d.events), "events", [(i["scenario"], i["user"]) for i in d.insiders], flush=True)
    del d
    with mp.Pool(int(sys.argv[1]) if len(sys.argv) > 1 else 3) as pool:
        res = dict(pool.map(_run, ARCHS))
    pathlib.Path("results/release_cert_r62_v08.json").write_text(json.dumps(res, indent=1))
