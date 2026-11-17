# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Independent machine-learning baseline: Isolation Forest UEBA.

The zero-trust baseline presets in engine.py share the architecture's signal library. This baseline
shares no code with it, as an independent reference point. This baseline shares nothing with the NT engine
except the raw events: it computes generic per-account-day features (counts and volumes, the kind
of features published CERT-dataset UEBA baselines use), learns what normal looks like from the
learning period with an Isolation Forest (Liu, Ting, Zhou 2008), and raises a daily alert for
account-days that are more anomalous than a chosen quantile of the learning period.

Two response modes, mirroring the zero-trust presets:
    soc   alert -> analyst review after 24 h -> containment if confirmed
    auto  alert -> immediate read-only containment (end of the day) -> review after 8 h

It is a daily batch model: it cannot react inside the day on which an attack starts, which is a
real property of batch UEBA and is reported as such. No decoys, no attribution, no correlation.
"""
from __future__ import annotations

from collections import defaultdict
from typing import Dict

import numpy as np

from . import policy as P
from .engine import category
from .evaluate import hostile_subjects_of, responsible, _type
from .sim import generate, NEGLIGENT_TYPES

FEATURES = ["logins", "first_login_h", "last_login_h", "new_device", "foreign_ip", "reads", "sensitive_reads",
            "cross_dept_reads", "cross_dept_sensitive", "ext_mail_att", "ext_mail_att_sensitive", "new_ext_domains",
            "usb_mb", "cloud_mb", "copy_mb", "archive_mb", "clones", "grants", "internal_fwd_sensitive"]


def _features(day_events, seen_dev, seen_dom, depts) -> np.ndarray:
    f = dict.fromkeys(FEATURES, 0.0)
    f["first_login_h"], f["last_login_h"] = 12.0, 12.0
    hours = []
    for e in day_events:
        acct = e.account
        k = e.kind
        if k == "login":
            f["logins"] += 1
            hours.append(e.t % 24)
            dev = e.attrs.get("device")
            if dev not in seen_dev[acct]:
                f["new_device"] += 1
            if e.attrs.get("ip_type") == "foreign":
                f["foreign_ip"] += 1
        elif k == "read":
            f["reads"] += 1
            f["sensitive_reads"] += e.sensitive
            cross = e.rdept is not None and e.rdept != depts.get(acct)
            f["cross_dept_reads"] += cross
            f["cross_dept_sensitive"] += cross and e.sensitive
        elif k == "email":
            if e.attrs.get("external") and e.attrs.get("attachment"):
                f["ext_mail_att"] += 1
                f["ext_mail_att_sensitive"] += e.sensitive
                dom = str(e.attrs.get("to", "")).split("@")[-1]
                f["new_ext_domains"] += dom not in seen_dom[acct]
            elif e.attrs.get("attachment") and e.sensitive:
                f["internal_fwd_sensitive"] += 1
        elif k == "egress_usb":
            f["usb_mb"] += e.nbytes / 1e6
        elif k == "egress_cloud":
            f["cloud_mb"] += e.nbytes / 1e6
        elif k == "copy":
            f["copy_mb"] += e.nbytes / 1e6
        elif k == "archive":
            f["archive_mb"] += e.nbytes / 1e6
        elif k == "clone":
            f["clones"] += e.attrs.get("count", 1)
        elif k == "grant":
            f["grants"] += 1
    if hours:
        f["first_login_h"], f["last_login_h"] = min(hours), max(hours)
    return np.array([f[x] for x in FEATURES], dtype=float)


def run_iforest(seed: int, n_people: int = 150, days: int = 60, scenario_set: str = "standard", instances: int = 1,
                quantile: float = 0.995, mode: str = "auto", learn_days: int = 14, data=None) -> dict:
    from sklearn.ensemble import IsolationForest

    org, events = data if data is not None else generate(seed, n_people, days, scenario_set, instances)
    depts = {p: org.people[p].dept for p in org.people}
    hostile = hostile_subjects_of(org)
    resp = responsible(org)
    by_day = defaultdict(lambda: defaultdict(list))
    for e in events:
        if e.account in depts:
            by_day[int(e.t // 24) + 1][e.account].append(e)
    seen_dev, seen_dom = defaultdict(set), defaultdict(set)

    def update_seen(evs):
        for e in evs:
            if e.kind == "login":
                seen_dev[e.account].add(e.attrs.get("device"))
            elif e.kind == "email" and e.attrs.get("external"):
                seen_dom[e.account].add(str(e.attrs.get("to", "")).split("@")[-1])

    X = []
    for d in range(1, learn_days + 1):
        for _acct, evs in by_day[d].items():
            X.append(_features(evs, seen_dev, seen_dom, depts))
            update_seen(evs)
    model = IsolationForest(n_estimators=200, random_state=seed).fit(np.array(X))
    thr = np.quantile(-model.score_samples(np.array(X)), quantile)

    contained: Dict[str, float] = {}           # account -> time containment starts
    cases = []                                 # (account, opened, due)
    confirmed = set()
    released: Dict[str, float] = {}           # account -> time a dismissal lifted containment
    resolved = set()
    scenario_people = {a for s in org.scenarios for a in s["actors"]} | {s["victim"] for s in org.scenarios if "victim" in s}
    innocents = set(org.people) - scenario_people
    harm = defaultdict(lambda: {"planned": 0, "realized": 0})
    contained_at: Dict[str, float] = {}
    alerted = set()
    innocent_alerts = 0
    for d in range(1, days + 1):
        day_feats = []
        for acct, evs in sorted(by_day[d].items()):
            for e in evs:
                # enforcement on planned events
                c_t = contained.get(acct)
                r_t = released.get(acct)
                active = c_t is not None and e.t >= c_t and not (r_t is not None and r_t >= c_t and e.t >= r_t)
                allowed = not (active and category(e) in (P.EGRESS, P.BULK, P.SENSITIVE_READ, P.ADMIN))
                if e.scenario and category(e) == P.EGRESS:
                    harm[e.scenario]["planned"] += e.nbytes
                    if allowed:
                        harm[e.scenario]["realized"] += e.nbytes
            if d > learn_days:
                day_feats.append((acct, _features(evs, seen_dev, seen_dom, depts)))
            update_seen(evs)
        if day_feats:
            scores = -model.score_samples(np.array([x for _, x in day_feats]))
            end = d * 24
            for (acct, _), sc in zip(day_feats, scores, strict=True):
                if sc <= thr or acct in confirmed or any(c[0] == acct and c[2] > end for c in cases):
                    continue
                alerted.add(acct)
                innocent_alerts += acct in innocents
                due = end + (24 if mode == "soc" else 8)
                cases.append((acct, end, due))
                if mode == "auto":
                    contained[acct] = end
                    released.pop(acct, None)
        # reviews that fall due by the end of the next day (the next day's events see the outcome in time)
        for idx, (acct, _opened, due) in enumerate(cases):
            if idx in resolved or due > (d + 1) * 24:
                continue
            resolved.add(idx)
            if acct in hostile or ("acct:" + acct) in hostile:
                confirmed.add(acct)
                contained[acct] = min(contained.get(acct, due), due)
                released.pop(acct, None)
            else:
                released[acct] = due
    # containment times of responsible subjects (UEBA has only accounts = persons)
    for acct, t in contained.items():
        contained_at[acct] = t
    per = {}
    for s in org.scenarios:
        name, typ = s["name"], _type(s)
        subs = resp[name]
        accts = [x.replace("acct:", "") for x in subs]
        onset_t = (s["onset"] - 1) * 24
        tc = [contained_at[a] - onset_t for a in accts if a in contained_at and a in confirmed]
        per[name] = {"type": typ, "contained": bool(tc), "hours_to_contain": round(min(tc), 1) if tc else None,
                     "flagged": any(a in alerted for a in accts), "max_level": 0,
                     "planned_bytes": harm[name]["planned"], "realized_bytes": harm[name]["realized"]}
        if "victim" in s:
            per[name]["victim_person_contained"] = s["victim"] in confirmed
        if typ in NEGLIGENT_TYPES:
            per[name]["over_contained"] = any(a in contained for a in accts)
    user_days = len(innocents) * days
    inn_contained = len([a for a in innocents if a in contained])
    hostile_cases = sum(1 for c in cases if c[0] in hostile or ("acct:" + c[0]) in hostile)
    return {"seed": seed, "preset": f"iforest_{mode}_q{quantile}", "scenarios": per, "innocents": len(innocents),
            "user_days": user_days, "innocent_contained": inn_contained if mode == "auto" else 0,
            "innocent_l2_or_more": 0, "innocent_cases": len({c[0] for c in cases if c[0] in innocents}),
            "cases_total": len(cases), "cases_hostile": hostile_cases,
            "innocent_stepups_per_1000_user_days": 0.0, "innocent_dual_control_per_1000_user_days": 0.0,
            "innocent_denied_actions": 0, "ledger_entries": 0, "ledger_ok": True}
