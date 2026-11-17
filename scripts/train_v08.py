# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Train the two v0.8 signal weights on CERT r4.2 (70 incidents) only; r6.2 is held out.

Grid: channel_burst x leaver_egress weights. Each point is a full calibrated shadow-mode replay of r4.2 (same protocol
as the release). Objective, fixed before training:
    U = detected % + 0.5 x prevented % - innocent users restricted (L3+) per 1,000
Writes results/train_v08.json.
"""
import itertools, json, multiprocessing as mp, pathlib, pickle, sys
sys.path.insert(0, str(pathlib.Path(__file__).parent))
from evaluate_release import cfg_for  # noqa: E402

GRID_BURST = (0.5, 1.0, 1.5, 2.0)
GRID_LEAVER = (0.0, 0.2, 0.5, 0.8)


def objective(r):
    return r["detected_pct"] + 0.5 * r["prevented_pct"] - r["false_l3_users_per_1000"]


def run(args):
    wb, wl, release, version = args[:4]
    from npcore import policy as P, signals as S
    if len(args) > 4:
        S.BURST_P, S.BURST_MIN = args[4], args[5]
    from npcore.cert import replay, score, prepare, calibrate, notices, with_notices
    S.W["channel_burst"], S.W["leaver_egress"] = wb, wl
    data = pickle.loads(pathlib.Path(f"data/cert/derived/{release.replace('.', '')}_events.pkl").read_bytes())
    events, partners, _ = prepare(data, 60)
    events = with_notices(events, notices(release=release))
    cfg = cfg_for(version)
    cfg.device_attribution = False
    cfg.warmup_days = 60
    f = calibrate(data, cfg, partners, events, budget_per_week=5.0 * len(data.users) / 1000)
    cfg.policy = P.PolicyConfig(thresholds=tuple(x * f for x in cfg.policy.thresholds))
    cfg.alert_threshold *= f
    r = score(data, replay(data, cfg, partners=partners, events=events), version)
    r.update(threshold_scale=f, w_burst=wb, w_leaver=wl, U=round(objective(r), 2),
             burst_p=S.BURST_P, burst_min=S.BURST_MIN)
    print(version, release, wb, wl, r["detected_pct"], r["prevented_pct"], r["false_l3_users_per_1000"], r["U"], flush=True)
    return r


if __name__ == "__main__":
    jobs = [(1.0, 0.5, "r4.2", "nt v0.7")] + [(wb, wl, "r4.2", "nt v0.8") for wb, wl in itertools.product(GRID_BURST, GRID_LEAVER)]
    if "--grid2" in sys.argv:      # second round: notice signal alone, and a stricter burst rule
        jobs = [(1.0, 0.5, "r4.2", "nt v0.7")] + [(0.0, wl, "r4.2", "nt v0.8") for wl in (0.5, 0.8, 1.2, 1.6)] + \
               [(wb, wl, "r4.2", "nt v0.8", 1e-5, 10) for wb in (0.5, 1.0) for wl in (0.8, 1.2)]
    with mp.Pool(5) as pool:
        res = pool.map(run, jobs)
    base = res[0]
    ok = [r for r in res[1:] if r["detected_pct"] >= base["detected_pct"]
          and r["false_l3_users_per_1000"] <= base["false_l3_users_per_1000"]]          # never worse than v0.7 on r4.2
    best = max(ok, key=lambda r: r["U"]) if ok else None
    if best is None:
        print("no weights keep r4.2 at least as good as v0.7; v0.8 signals stay off"); best = {"w_burst": 0.0, "w_leaver": 0.0, "U": None}
    out = {"objective": "detected % + 0.5 x prevented % - innocent users L3+ per 1,000", "baseline_v07": res[0],
           "grid": res[1:], "best": {"channel_burst": best["w_burst"], "leaver_egress": best["w_leaver"], "U": best["U"]}}
    prev = pathlib.Path("results/train_v08.json")
    if "--grid2" in sys.argv and prev.exists():          # keep every grid point from earlier rounds
        old = json.loads(prev.read_text())
        out["grid"] = old["grid"] + out["grid"]
        allok = [r for r in out["grid"] if r["detected_pct"] >= base["detected_pct"]
                 and r["false_l3_users_per_1000"] <= base["false_l3_users_per_1000"]]
        if allok:
            b = max(allok, key=lambda r: r["U"])
            out["best"] = {"channel_burst": b["w_burst"], "leaver_egress": b["w_leaver"], "U": b["U"],
                           "burst_p": b.get("burst_p", 1e-3), "burst_min": b.get("burst_min", 5)}
        else:
            out["best"] = {"channel_burst": 0.0, "leaver_egress": 0.0, "U": None, "note": "no weights keep r4.2 at least as good as v0.7"}
    pathlib.Path("results/train_v08.json").write_text(json.dumps(out, indent=1))
    print("best", out["best"], "baseline U", res[0]["U"])
