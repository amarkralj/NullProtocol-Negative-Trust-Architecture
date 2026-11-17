# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Cross-organisation tuning: learn parameters on some kinds of organisation, test on kinds never seen.

The parameters are few and stay human-readable: a threshold scale, the half-lives of strong and weak
evidence, the cap on earned trust, and five group multipliers on the signal weights (identity, access,
egress, staging, deception). The result is still a fixed table of weights that a works council or an
auditor can read; it is tuned offline, not learned online.

Objective (higher is better), averaged over all training runs:

    U = harm prevented (%) - 25 x innocents contained per 1,000 user-days - 0.15 x innocent step-ups per
        1,000 user-days - 0.2 x victims blamed (%) - 0.1 x negligent employees over-contained (%)

The coefficients express a policy: one innocent person contained per 1,000 user-days costs as much as 25
points of harm prevented. Every architecture is tuned with the same objective and the same budget.
"""
from __future__ import annotations

import math
import random
from typing import List

from . import deception as D
from . import policy as P
from . import signals as S
from .engine import EngineConfig, preset
from .evaluate import run_one, summarise
from .sim import generate
from .trust import TrustConfig

GROUPS = {
    "identity": ["off_hours_login", "new_device", "foreign_ip", "impossible_context"],
    "access": ["cross_dept_sensitive_read", "read_volume_spike", "cross_dept_grant"],
    "egress": ["egress_removable", "egress_personal_cloud", "egress_cloud", "email_personal", "email_unknown_external",
               "email_sensitive_attachment", "lookalike_domain", "lookalike_repeat", "egress_rate_spike"],
    "staging": ["bulk_copy", "archive", "clone_spike"],
}
BASE_W = dict(S.W)
BASE_D = dict(D.WEIGHTS)
TRAIN_PROFILES = ("office", "usb_culture", "finance_heavy")
TEST_PROFILES = ("remote_first", "night_shift")
DEFAULT = {"scale": 1.0, "h_strong_d": 30.0, "h_weak_d": 4.0, "pos_cap": 0.6,
           "identity": 1.0, "access": 1.0, "egress": 1.0, "staging": 1.0, "deception": 1.0}
DEFAULT_ZT = {"scale": 1.0, "half_life_d": 7.0, "identity": 1.0, "access": 1.0, "egress": 1.0, "staging": 1.0, "deception": 1.0}


def utility(row: dict) -> float:
    return (row["harm_prevented_pct"] - 25 * row["innocent_contained_per_1000_user_days"][0]
            - 0.15 * row["innocent_stepups_per_1000_user_days"] - 0.2 * (row["victim_blamed_pct"] or 0)
            - 0.1 * (row["negligent_over_contained_pct"] or 0))


def apply_weights(params: dict) -> None:
    """Set the global signal and deception weights for this process."""
    S.W.clear(); S.W.update(BASE_W)
    for g, kinds in GROUPS.items():
        for k in kinds:
            if k in S.W:
                S.W[k] = BASE_W[k] * params.get(g, 1.0)
    D.WEIGHTS.clear(); D.WEIGHTS.update({k: v * params.get("deception", 1.0) for k, v in BASE_D.items()})


def make_cfg(arch: str, params: dict) -> EngineConfig:
    cfg = preset(arch, v03=True)
    if arch.startswith("nt"):
        cfg.trust = TrustConfig(h_neg=24 * params["h_strong_d"], h_neg_weak=24 * params["h_weak_d"], pos_cap=params["pos_cap"])
    else:
        cfg.trust = TrustConfig.symmetric(24 * params["half_life_d"])
    cfg.policy = P.PolicyConfig(thresholds=tuple(x * params["scale"] for x in P.PolicyConfig().thresholds))
    cfg.alert_threshold = -2.5 * params["scale"]
    return cfg


def _run(args):
    arch, params, seed, ss, profile = args
    apply_weights(params)
    try:
        data = generate(seed, scenario_set=ss, profile=profile)
        r = run_one(seed, None, cfg=make_cfg(arch, params), scenario_set=ss, data=data)
    finally:
        apply_weights(DEFAULT)
    r.pop("cases", None)
    r["profile"], r["set"] = profile, ss
    return r


def evaluate(arch: str, params: dict, profiles, seeds, pool=None, sets=("standard", "adaptive")) -> dict:
    tasks = [(arch, params, s, ss, pf) for pf in profiles for ss in sets for s in seeds]
    runs = list(pool.map(_run, tasks)) if pool else [_run(t) for t in tasks]
    per_set = {}
    for ss in sets:
        rs = [r for r in runs if r["set"] == ss]
        for r in rs:
            r["preset"] = arch
        per_set[ss] = summarise(rs)[arch]
    return {"per_set": per_set, "utility": sum(utility(v) for v in per_set.values()) / len(per_set)}


def _sample(rng, base: dict, arch: str, local: float = 0.0) -> dict:
    def lu(lo, hi, cur):
        if local:
            return min(hi, max(lo, cur * math.exp(rng.gauss(0, local))))
        return math.exp(rng.uniform(math.log(lo), math.log(hi)))
    p = dict(base)
    p["scale"] = lu(0.6, 2.5, base["scale"])
    if arch.startswith("nt"):
        p["h_strong_d"] = lu(10, 60, base["h_strong_d"])
        p["h_weak_d"] = lu(2, 10, base["h_weak_d"])
        p["pos_cap"] = lu(0.2, 1.2, base["pos_cap"])
    else:
        p["half_life_d"] = lu(3, 30, base["half_life_d"])
    for g in ("identity", "access", "egress", "staging", "deception"):
        p[g] = lu(0.5, 2.0, base[g])
    return p


def search(arch: str, n_random=40, n_local=20, seeds=(401, 402), pool=None, rng_seed=7, log=print) -> dict:
    rng = random.Random(rng_seed)
    base = dict(DEFAULT if arch.startswith("nt") else DEFAULT_ZT)
    tried: List[dict] = []
    cands = [base] + [_sample(rng, base, arch) for _ in range(n_random)]
    for i, c in enumerate(cands):
        res = evaluate(arch, c, TRAIN_PROFILES, seeds, pool)
        tried.append({"params": c, "utility": res["utility"]})
        log(f"{arch} random {i:3d} U={res['utility']:7.2f}")
    top = sorted(tried, key=lambda x: -x["utility"])[:3]
    for i in range(n_local):
        c = _sample(rng, top[i % 3]["params"], arch, local=0.25)
        res = evaluate(arch, c, TRAIN_PROFILES, seeds, pool)
        tried.append({"params": c, "utility": res["utility"]})
        log(f"{arch} local  {i:3d} U={res['utility']:7.2f}")
    best = max(tried, key=lambda x: x["utility"])
    return {"arch": arch, "best": best, "default_utility": tried[0]["utility"], "tried": len(tried),
            "train_profiles": TRAIN_PROFILES, "train_seeds": list(seeds), "history": tried}
