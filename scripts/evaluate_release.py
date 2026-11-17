# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Release evaluation (all numbers in README and docs/evaluation.md).

    python scripts/evaluate_release.py sim     # fresh seeds: office 301-320, unseen profiles 601-610
    python scripts/evaluate_release.py cert    # CERT r4.2, calibrated shadow-mode replay
    python scripts/evaluate_release.py scale   # 1,000 employees x 90 days, 36 attacks per organisation

Writes results/release_<part>.json.
"""
import json, multiprocessing as mp, pathlib, pickle, sys, time
from npcore.engine import preset, version_preset
from npcore.evaluate import run_one, summarise
from npcore.sim import generate

OUT = pathlib.Path("results")
ARCHS = ["zt_alert", "zt_auto", "zt_strong", "nt v0.1", "nt v0.2", "nt v0.3", "nt v0.4"]
SETS = ("standard", "adaptive", "cases")
GROUPS = {"office": ("office", range(301, 321)), "unseen_profiles": (("remote_first", "night_shift"), range(601, 611))}
OUTFILE = "release_sim.json"


def cfg_for(a):
    """'nt v0.x' -> NullProtocol Negative Trust version; 'zt_strong' -> baseline with the v0.4 signals;
    'zt_strong@v0.9' -> baseline with the signals of that version (same inputs as Negative Trust)."""
    if a.startswith("nt "):
        return version_preset(a.split()[1])
    if "@" in a:
        name, v = a.split("@")
        return preset(name, **{"v0" + v.split(".")[1]: True})
    return preset(a, v04=True)


def _sim(args):
    group, profile, seed, ss = args
    data = generate(seed, scenario_set=ss, profile=profile)
    out = []
    for a in ARCHS:
        r = run_one(seed, a, cfg=cfg_for(a), scenario_set=ss, data=data)
        r.pop("cases", None); r.update(group=group, set=ss, profile=profile)
        out.append(r)
    return out


def sim():
    tasks = []
    for g, (profiles, seeds) in GROUPS.items():
        for pf in (profiles if isinstance(profiles, tuple) else (profiles,)):
            tasks += [(g, pf, s, ss) for s in seeds for ss in SETS]
    with mp.Pool(9) as pool:
        runs = [r for rs in pool.map(_sim, tasks) for r in rs]
    res = {g: {ss: summarise([r for r in runs if r["group"] == g and r["set"] == ss]) for ss in SETS}
           for g in GROUPS}
    res["config"] = {g: {"profiles": p if isinstance(p, tuple) else [p], "seeds": [s.start, s.stop - 1]} for g, (p, s) in GROUPS.items()}
    (OUT / OUTFILE).write_text(json.dumps(res, indent=1))


def _cert(a):
    from npcore import policy as P
    from npcore.cert import replay, score, prepare, calibrate
    from npcore.tune import apply_weights, make_cfg
    cache = pathlib.Path("data/cert/derived/r42_events.pkl")
    if not cache.exists():
        from npcore.cert import load
        cache.write_bytes(pickle.dumps(load()))
    data = pickle.loads(cache.read_bytes())
    events, partners, _ = prepare(data, 60)
    if a == "nt v0.3 tuned":
        params = json.loads((OUT / "tuning.json").read_text())["nt_no_sentiment"]["best_params"]
        apply_weights(params)
        cfg = make_cfg("nt_no_sentiment", params)
    else:
        cfg = cfg_for(a)
    cfg.device_attribution = False
    cfg.warmup_days = 60
    f = calibrate(data, cfg, partners, events)
    cfg.policy = P.PolicyConfig(thresholds=tuple(x * f for x in cfg.policy.thresholds))
    cfg.alert_threshold *= f
    sc = score(data, replay(data, cfg, partners=partners, events=events), a)
    sc["threshold_scale"] = f
    return a, sc


def cert():
    archs = ["zt_alert", "zt_auto", "zt_strong", "nt v0.2", "nt v0.3", "nt v0.4"]
    with mp.Pool(4) as pool:
        res = dict(pool.map(_cert, archs))
    (OUT / "release_cert.json").write_text(json.dumps(res, indent=1))


def _scale(args):
    seed, a = args
    data = generate(seed, 1000, 90, "all", 3)
    t0 = time.time()
    r = run_one(seed, a, cfg=cfg_for(a), scenario_set="all", instances=3, data=data)
    r.pop("cases", None); r["events"] = len(data[1]); r["seconds"] = time.time() - t0
    return r


def scale():
    with mp.Pool(6) as pool:
        runs = pool.map(_scale, [(s, a) for s in (201, 202, 203) for a in ("zt_strong", "nt v0.3", "nt v0.4")])
    res = {"summary": summarise(runs), "events_per_run": runs[0]["events"],
           "events_per_second": {a: round(sum(r["events"] for r in runs if r["preset"] == a) / sum(r["seconds"] for r in runs if r["preset"] == a))
                                 for a in ("zt_strong", "nt v0.3", "nt v0.4")}}
    (OUT / "release_scale.json").write_text(json.dumps(res, indent=1))


if __name__ == "__main__":
    t0 = time.time()
    {"sim": sim, "cert": cert, "scale": scale}[sys.argv[1]]()
    print(sys.argv[1], "done", round(time.time() - t0), "s")
