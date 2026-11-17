# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Experiment harness: runs the simulator against each architecture and computes metrics.

The harness plays the humans: it answers step-up prompts, second-approver requests and case
reviews using ground truth, with the same imperfect rates for every architecture:

    step-up       owner always passes; an insider on their own account passes (it is them);
                  anyone else acting maliciously on an account (outside attacker, colleague using
                  stolen credentials) passes with probability 0.5; benign helpers pass
    dual control  approver approves a benign request with p = 0.97 (3 % wrongly denied)
                  and denies a harmful one with p = 0.70 (approvers are not perfect)
    case review   reviewer confirms if the subject is truly hostile (malicious or disgruntled
                  insider, or a compromised account); negligent employees are dismissed with training
"""
from __future__ import annotations

import json
import math
import random
import statistics
from collections import defaultdict
from typing import Dict, List

from . import policy as P
from .engine import Engine, EngineConfig, preset, category, PRESETS
from .sim import generate, PARTNER_DOMAINS, NEGLIGENT_TYPES, ACCOUNT_TAKEOVER_TYPES

HOSTILE = {"exfil_sweep", "disgruntled", "collusion", "low_slow"}        # standard-set insider types (kept for the demo)


def _type(s) -> str:
    return s.get("type", s["name"])


def responsible(org) -> Dict[str, List[str]]:
    out = {}
    for s in org.scenarios:
        out[s["name"]] = ["acct:" + s["victim"]] if _type(s) in ACCOUNT_TAKEOVER_TYPES else list(s["actors"])
    return out


def hostile_subjects_of(org) -> set:
    hs = set()
    for s in org.scenarios:
        t = _type(s)
        if t in NEGLIGENT_TYPES:
            continue
        if t in ACCOUNT_TAKEOVER_TYPES:
            hs.add("acct:" + s["victim"])
        else:
            hs.update(a for a in s["actors"] if a != "external")
    return hs


def run_one(seed: int, preset_name, n_people: int = 150, days: int = 60, scenario_set: str = "standard",
            instances: int = 1, cfg: EngineConfig = None, extra_noise=None, data=None) -> dict:
    org, events = data if data is not None else generate(seed, n_people, days, scenario_set, instances, extra_noise)
    owners = {p: p for p in org.people}
    depts = {p: org.people[p].dept for p in org.people}
    cfg = cfg or preset(preset_name)
    preset_name = cfg.name if preset_name is None else preset_name
    eng = Engine(cfg, owners, depts, org.decoys, partner_domains=PARTNER_DOMAINS,
                 support_staff=[p for p in org.people if org.people[p].it_support],
                 workloads=[p for p in org.people if org.people[p].workload])
    rng = random.Random(seed * 7919 + 13)
    resp = responsible(org)
    hostile_subjects = hostile_subjects_of(org)
    scenario_people = {a for s in org.scenarios for a in s["actors"]} | {s["victim"] for s in org.scenarios if "victim" in s}
    innocents = {p for p in org.people if not org.people[p].workload} - scenario_people

    stats = defaultdict(float)
    harm = defaultdict(lambda: {"planned": 0, "realized": 0})
    contained_at: Dict[str, float] = {}
    day = 1
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day)
            day += 1
        for c in eng.due_cases(e.t):
            eng.review(c["subject"], c["subject"] in hostile_subjects, c["due"])
        d = eng.decide(e)
        allowed = True
        innocent_ev = not e.malicious
        innocent_person = e.true_actor in innocents
        if d == P.STEP_UP:
            stats["stepups_innocent" if innocent_person else "stepups_other"] += 1
            if e.malicious and e.true_actor != owners.get(e.account, e.account):
                allowed = rng.random() < 0.5
            if allowed:
                eng.confirm_stepup(e.account, e.t)
        elif d == P.DUAL_CONTROL:
            stats["dual_innocent" if innocent_person else "dual_other"] += 1
            allowed = (rng.random() < 0.97) if innocent_ev else (rng.random() >= 0.70)
            if innocent_person and not allowed:
                stats["innocent_denied"] += 1
        elif d == P.DENY:
            allowed = False
            if innocent_person:
                stats["innocent_denied"] += 1
        if e.scenario and (category(e) == P.EGRESS or e.kind == "record_read"):
            harm[e.scenario]["planned"] += e.nbytes
            if allowed:
                harm[e.scenario]["realized"] += e.nbytes
        eng.observe(e, allowed)
        # effective containment of every responsible subject
        for subs in resp.values():
            for s in subs:
                if s not in contained_at:
                    lvl = eng.subject_level(s)
                    if lvl >= P.Level.L3_READ_ONLY:
                        contained_at[s] = e.t
    eng.end_of_day(day)

    # max computed level and containment for every subject
    max_level = defaultdict(int)
    for (_t, s, _old, new) in eng.level_log:
        max_level[s] = max(max_level[s], new)
    eff_contained = set(contained_at)
    if eng.cfg.enforce == "auto":
        for (_t, s, _old, new) in eng.level_log:
            if new >= 3:
                eff_contained.add(s)
    for s in eng.forced:
        eff_contained.add(s)

    per = {}
    for s in org.scenarios:
        name = s["name"]
        typ = _type(s)
        subs = resp[name]
        onset_t = (s["onset"] - 1) * 24
        tc = [contained_at[x] - onset_t for x in subs if x in contained_at]
        flagged = any(max_level[x] >= 1 for x in subs) or any(c["subject"] in subs for c in eng.case_log)
        per[name] = {
            "type": typ,
            "contained": bool(tc),
            "hours_to_contain": round(min(tc), 1) if tc else None,
            "flagged": flagged,
            "max_level": max(max_level[x] for x in subs),
            "planned_bytes": harm[name]["planned"],
            "realized_bytes": harm[name]["realized"],
        }
        if "victim" in s:
            per[name]["victim_person_contained"] = s["victim"] in eff_contained
            per[name]["victim_person_max_level"] = max_level[s["victim"]]
        if typ in NEGLIGENT_TYPES:
            per[name]["over_contained"] = any(x in eff_contained for x in subs)

    inn_contained = [p for p in innocents if p in eff_contained or ("acct:" + p) in eff_contained]
    inn_l2 = [p for p in innocents if max_level[p] >= 2]
    inn_cases = [c for c in eng.case_log if c["subject"] in innocents or c["subject"].replace("acct:", "") in innocents]
    all_cases = list(eng.case_log) + list(eng.cases.values())
    hostile_cases = [c for c in all_cases if c["subject"] in hostile_subjects]
    user_days = len(innocents) * days
    ok, _ = eng.ledger.verify()
    return {
        "seed": seed, "preset": preset_name, "scenarios": per,
        "innocents": len(innocents), "user_days": user_days,
        "innocent_contained": len(inn_contained),
        "innocent_l2_or_more": len(inn_l2),
        "innocent_cases": len(inn_cases),
        "cases_total": len(all_cases), "cases_hostile": len(hostile_cases),
        "innocent_stepups_per_1000_user_days": round(1000 * stats["stepups_innocent"] / user_days, 2),
        "innocent_dual_control_per_1000_user_days": round(1000 * stats["dual_innocent"] / user_days, 2),
        "innocent_denied_actions": int(stats["innocent_denied"]),
        "ledger_entries": len(eng.ledger.entries), "ledger_ok": ok,
        "cases": eng.case_log,
    }


def _mean_ci(xs):
    xs = [x for x in xs if x is not None]
    if not xs:
        return None, None
    m = statistics.mean(xs)
    if len(xs) < 2:
        return m, 0.0
    return m, 1.96 * statistics.stdev(xs) / math.sqrt(len(xs))


def summarise(runs: List[dict]) -> dict:
    """Aggregate per architecture. Scenario instances are pooled by scenario type."""
    by = defaultdict(list)
    for r in runs:
        by[r["preset"]].append(r)
    out = {}
    for pr, rs in by.items():
        inst = [v for r in rs for v in r["scenarios"].values()]
        types = list(dict.fromkeys(v.get("type") for v in rs[0]["scenarios"].values()))
        hostile = [v for v in inst if v.get("type") not in NEGLIGENT_TYPES]
        row = {"runs": len(rs), "scenario_instances": len(inst)}
        planned = sum(v["planned_bytes"] for v in hostile)
        realized = sum(v["realized_bytes"] for v in hostile)
        row["harm_prevented_pct"] = round(100 * (1 - realized / planned), 1) if planned else None
        row["containment_rate_pct"] = round(100 * statistics.mean(v["contained"] for v in hostile), 1)
        hs = [v["hours_to_contain"] for v in hostile if v["contained"]]
        row["median_hours_to_contain"] = round(statistics.median(hs), 1) if hs else None
        for n in types:
            vs = [v for v in inst if v.get("type") == n]
            pl = sum(v["planned_bytes"] for v in vs)
            rl = sum(v["realized_bytes"] for v in vs)
            row[f"{n}:contained_pct"] = round(100 * statistics.mean(v["contained"] for v in vs), 1)
            row[f"{n}:flagged_pct"] = round(100 * statistics.mean(v["flagged"] for v in vs), 1)
            row[f"{n}:harm_prevented_pct"] = round(100 * (1 - rl / pl), 1) if pl else None
            h = [v["hours_to_contain"] for v in vs if v["contained"]]
            row[f"{n}:median_hours"] = round(statistics.median(h), 1) if h else None
            if any("victim_person_contained" in v for v in vs):
                row[f"{n}:victim_blamed_pct"] = round(100 * statistics.mean(v["victim_person_contained"] for v in vs), 1)
        vict = [v["victim_person_contained"] for v in inst if "victim_person_contained" in v]
        row["victim_blamed_pct"] = round(100 * statistics.mean(vict), 1) if vict else None
        neg = [v["over_contained"] for v in inst if "over_contained" in v]
        row["negligent_over_contained_pct"] = round(100 * statistics.mean(neg), 1) if neg else None
        m, ci = _mean_ci([r["innocent_contained"] / r["user_days"] * 1000 for r in rs])
        row["innocent_contained_per_1000_user_days"] = (round(m, 3), round(ci, 3))
        m, ci = _mean_ci([r["innocent_cases"] / r["user_days"] * 1000 for r in rs])
        row["innocent_cases_per_1000_user_days"] = (round(m, 3), round(ci, 3))
        tot = sum(r.get("cases_total", 0) for r in rs)
        row["case_precision_pct"] = round(100 * sum(r.get("cases_hostile", 0) for r in rs) / tot, 1) if tot else None
        row["innocent_stepups_per_1000_user_days"] = round(statistics.mean(r["innocent_stepups_per_1000_user_days"] for r in rs), 2)
        row["innocent_dual_control_per_1000_user_days"] = round(statistics.mean(r["innocent_dual_control_per_1000_user_days"] for r in rs), 2)
        row["innocent_denied_actions_per_run"] = round(statistics.mean(r["innocent_denied_actions"] for r in rs), 2)
        row["ledger_ok_all"] = all(r["ledger_ok"] for r in rs)
        out[pr] = row
    return out


def run_suite(seeds=range(1, 11), presets=PRESETS, n_people=150, days=60, progress=True,
              scenario_set="standard", instances=1, v03: bool = False) -> dict:
    runs = []
    for s in seeds:
        data = generate(s, n_people, days, scenario_set, instances)
        for pr in presets:
            r = run_one(s, pr, n_people, days, scenario_set, instances, data=data,
                        cfg=preset(pr, v03=True) if v03 else None)
            runs.append(r)
            if progress:
                print(f"seed {s:2d} {pr:18s} contained={sum(v['contained'] for v in r['scenarios'].values())}/{len(r['scenarios'])} "
                      f"innocent_contained={r['innocent_contained']} cases={len(r['cases'])}", flush=True)
    return {"config": {"seeds": list(seeds), "presets": list(presets), "n_people": n_people, "days": days,
                       "scenario_set": scenario_set, "instances": instances},
            "summary": summarise(runs), "runs": [{k: v for k, v in r.items() if k != "cases"} for r in runs]}


if __name__ == "__main__":
    import sys
    res = run_suite(seeds=range(1, int(sys.argv[1]) + 1) if len(sys.argv) > 1 else range(1, 4))
    print(json.dumps(res["summary"], indent=1))
