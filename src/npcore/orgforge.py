# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Adapter and scorer for the public OrgForge-IT insider threat benchmark.

Dataset: huggingface.co/datasets/aeriesec/orgforge-insider-threat (MIT), paper arXiv:2603.22499.
The scoring functions below re-implement `score_triage` and `score_verdicts` from
github.com/aeriesec/orgforge eval/insider_threat/eval_insider_threat.py (MIT licence) so that
results are comparable with the published leaderboard.

Important differences to the leaderboard entries:
* The leaderboard runs LLM pipelines. This adapter is deterministic and uses no LLM.
* Detection uses only the observable telemetry; ground truth is used only by the scorer.
* Weights are the same generic weights as the simulator (npcore.signals.W). The adapter only maps
  OrgForge fields to those signals. The author did inspect the dataset README and the telemetry
  schema before writing the mapping, so this is not a blind evaluation; see docs/04-evaluation.md.
* OrgForge contains no decoys, so the deception part of NullProtocol Negative Trust is not exercised here.
"""
from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import List

from .evidence import Evidence, ACCOUNT, PERSON
from .signals import W, PERSONAL_DOMAINS
from .trust import TrustConfig, TrustModel
from .policy import PolicyConfig, level_for, Level

# Onset days from the dataset card (used by the scorer only)
ONSET = {"Jordan": 5, "Tasha": 10, "Jax": 18}

BEHAVIOR_MAP = {
    "off_hours_login": "unusual_hours_access", "off_hours_repo": "unusual_hours_access",
    "ghost_login": "unusual_hours_access", "negative_sentiment": "sentiment_drift",
    "email_personal": "data_exfil_email", "bulk_copy": "host_data_hoarding", "archive": "host_data_hoarding",
    "egress_personal_cloud": "host_data_hoarding", "egress_removable": "host_data_hoarding",
    "exfil_chain": "host_data_hoarding", "social_engineering": "social_engineering",
    "pretext_message": "social_engineering", "new_device": "idp_anomaly", "foreign_ip": "idp_anomaly",
    "impossible_context": "idp_anomaly", "account_compromise": "idp_anomaly", "secret_in_commit": "secret_in_commit",
}


def _b(v) -> bool:
    return v is True or v == 1 or (isinstance(v, str) and v.lower() == "true")


def _f(v):
    try:
        x = float(v)
        return None if x != x else x
    except (TypeError, ValueError):
        return None


def load(data_dir: str | Path):
    import pandas as pd
    d = Path(data_dir)
    obs = pd.read_parquet(d / "telemetry" / "access_log-00000.parquet")
    base = pd.read_parquet(d / "telemetry" / "baseline_telemetry-00000.parquet")
    gt = pd.read_parquet(d / "ground_truth" / "ground_truth-00000.parquet")

    def recs(df):
        out = []
        for r in df.to_dict("records"):
            out.append({k: v for k, v in r.items() if not (isinstance(v, float) and v != v) and v is not None})
        return out
    return recs(obs), recs(base), recs(gt)


def _hour(r) -> float:
    h = _f(r.get("access_hour"))
    if h is None:
        ts = str(r.get("timestamp", ""))
        try:
            h = int(ts[11:13]) + int(ts[14:16]) / 60
        except ValueError:
            h = 12.0
    return h


def detect(observed: List[dict], baseline: List[dict], trust_cfg: TrustConfig | None = None,
           policy: PolicyConfig | None = None, disabled=(), attribution: bool = True) -> dict:
    """Run NullProtocol Negative Trust over OrgForge telemetry. Returns triage + verdicts in the official format."""
    tm = TrustModel(trust_cfg or TrustConfig())
    pol = policy or PolicyConfig()
    # personal baselines from the clean period
    msgs, negs = defaultdict(int), defaultdict(int)
    for r in baseline:
        if r.get("record_type") == "slack_message":
            msgs[r["actor"]] += 1
            negs[r["actor"]] += r.get("sentiment") == "negative"
    base_neg = {a: negs[a] / msgs[a] for a in msgs if msgs[a]}

    recs = sorted(observed, key=lambda r: (r.get("day", 0), _hour(r)))
    calls = []                       # (t, caller, target)
    staged = defaultdict(list)
    spent = defaultdict(float)
    neg_day = defaultdict(bool)
    act_day = defaultdict(int)
    actors = set()
    evidence: List[Evidence] = []

    def add(t, subj, kind, desc, weight=None, kind_subject=PERSON, cap=None, source="signal"):
        if kind in disabled:
            return
        w = W.get(kind, 0.4) if weight is None else weight
        day = int(t // 24) + 1
        if cap is not None:
            if spent[(subj, day, kind)] >= cap:
                return
            w = min(w, cap - spent[(subj, day, kind)])
            spent[(subj, day, kind)] += w
        e = Evidence(t, subj, kind, w, desc, kind_subject, BEHAVIOR_MAP.get(kind), source=source)
        tm.add(e); evidence.append(e)
        if w > 0:
            neg_day[(subj, day)] = True

    last_day = 0
    for r in recs:
        day = int(r.get("day", 1)); h = _hour(r); t = (day - 1) * 24 + h
        while last_day < day - 1:
            last_day += 1
            for a in actors:
                if act_day[(a, last_day)] >= 3 and not neg_day[(a, last_day)]:
                    add(last_day * 24 - 0.01, a, "clean_day", "working day without negative evidence")
        a = r.get("actor", "?"); actors.add(a); act_day[(a, day)] += 1
        rt = r.get("record_type")
        if rt == "idp_auth":
            vishing = _b(r.get("preceded_by_call_record"))
            unproven = vishing or (_b(r.get("new_device")) and _b(r.get("anomalous_ip")))
            subj, sk = ("acct:" + a, ACCOUNT) if (attribution and unproven) else (a, PERSON)
            if _b(r.get("outside_business_hours")):
                add(t, subj, "off_hours_login", f"IdP login to {r.get('dst_app')} at {h:04.1f}h, outside business hours", kind_subject=sk, cap=W["off_hours_login"])
            if _b(r.get("ghost_login")) or r.get("corroborating_activity_expected") is False:
                add(t, subj, "ghost_login", f"IdP login at {h:04.1f}h with no corroborating Slack/Jira/email activity (ghost login)", 0.4, sk, cap=0.4)
            if _b(r.get("new_device")):
                add(t, subj, "new_device", f"IdP auth from device {r.get('device_id')} not in the employee's profile", kind_subject=sk)
            if _b(r.get("anomalous_ip")):
                add(t, subj, "foreign_ip", f"IdP auth from {r.get('src_ip')} ({r.get('ip_type')}), outside the corporate range", kind_subject=sk, cap=W["foreign_ip"])
            if _b(r.get("new_device")) and _b(r.get("anomalous_ip")):
                add(t, subj, "impossible_context", "unknown device and anomalous IP in the same authentication", kind_subject=sk)
            if r.get("auth_result") == "mfa_failure":
                add(t, subj, "mfa_failure", "MFA failure", 0.3, sk)
            if vishing:
                gap = _f(r.get("call_to_auth_gap_minutes"))
                for (tc, caller, tgt) in calls:
                    if tgt == a and t - tc <= 2.0:
                        add(t, ("acct:" + a) if attribution else a, "account_compromise",
                            f"auth on {a}'s account to {r.get('dst_app')} {gap or 60*(t-tc):.0f} min after a vishing phone call aimed at {a}; credential treated as compromised, {a} as victim",
                            3.0, ACCOUNT if attribution else PERSON, source="correlation")
                        add(t, caller, "social_engineering",
                            f"placed a vishing phone call to {a} (spoofed caller ID); {gap or 60*(t-tc):.0f} min later {a}'s account authenticated from a new device/anomalous IP (call preceded auth)",
                            2.0, source="correlation")
        elif rt == "phone_call":
            if r.get("target"):
                calls.append((t, a, r["target"]))
        elif rt == "slack_message":
            if r.get("pattern"):
                ex = {}
                try:
                    ex = json.loads(r.get("extra") or "{}")
                except json.JSONDecodeError:
                    pass
                add(t, a, "pretext_message", f"{r['pattern']} message to {r.get('target')} impersonating {ex.get('impersonates_role', 'another role')}", 1.0)
                if r.get("target"):
                    calls.append((t, a, r["target"]))
            elif r.get("sentiment") == "negative" and base_neg.get(a, 0) < 0.15:
                add(t, a, "negative_sentiment", f"negative Slack message in #{r.get('channel')} (baseline negative rate {100*base_neg.get(a,0):.0f} %)", cap=0.4)
        elif rt == "email_send":
            to = str(r.get("to", "")).lower(); dom = to.split("@")[-1]
            if _b(r.get("is_external")) and any(dom.startswith(p) or p in dom for p in PERSONAL_DOMAINS):
                add(t, a, "email_personal", f"email '{r.get('subject')}' sent to personal webmail {to}" + (" outside business hours" if _b(r.get("off_hours")) else ""))
        elif rt == "repo_access":
            if _b(r.get("outside_business_hours")):
                add(t, a, "off_hours_repo", f"repository access at {h:04.1f}h, outside business hours", 0.35, cap=0.35)
            n = _f(r.get("repos_cloned"))
            if n and n >= 10:
                add(t, a, "clone_spike", f"{int(n)} repositories cloned")
        elif rt == "host_event":
            act = r.get("action")
            if act == "bulk_file_copy":
                staged[a].append(t)
                add(t, a, "bulk_copy", f"bulk copy of {int(_f(r.get('file_count')) or 0)} files ({(_f(r.get('total_bytes')) or 0)/1e6:.0f} MB) staged to {r.get('staged_path')} from {r.get('source_shares')}")
            elif act == "archive_creation":
                add(t, a, "archive", f"archive {r.get('archive_name')} created (compress / zip) from staged data")
            elif act == "archive_move":
                dest = r.get("destination_path") or r.get("cloud_sync_dir") or ""
                kind = "egress_removable" if _b(r.get("removable_media")) else "egress_personal_cloud"
                add(t, a, kind, f"archive {r.get('archive_name')} moved to {dest} ({r.get('destination_type')}, sync / move)")
                if staged[a]:
                    add(t, a, "exfil_chain", f"three-phase hoarding trail: bulk copy (day {int(_f(r.get('hoarding_trail_start_day')) or 0)}) -> compress/archive -> move to {dest}",
                        1.5, source="correlation")
        elif rt in ("commit", "pr_description") and _b(r.get("secret_in_commit")):
            add(t, a, "secret_in_commit", "credential committed to a repository", 0.7)

    # verdicts
    subjects = set(tm.subjects()) | actors
    triage, verdicts, min_trust = {}, [], {}
    for s in sorted(subjects):
        evs = sorted(tm.evidence(s), key=lambda x: x.t)
        mins, first_l2 = 0.0, None
        for x in evs:
            tr = tm.trust(s, x.t)
            if tr < mins:
                mins = tr
            if first_l2 is None and level_for(tr, pol) >= Level.L2_DUAL_CONTROL:
                first_l2 = x.t
        min_trust[s] = mins
        if s.startswith("acct:"):
            continue
        triage[s] = [{"escalate": first_l2 is not None, "first_escalation_day": int(first_l2 // 24) + 1 if first_l2 else None,
                      "min_trust": round(mins, 2)}]
        lvl = level_for(mins, pol)
        verdict = "likely_threat" if lvl >= Level.L4_ISOLATE else ("suspicious" if lvl >= Level.L2_DUAL_CONTROL else "innocent")
        beh = sorted({x.behavior for x in evs if x.weight > 0 and x.behavior and x.behavior != "idp_anomaly"})
        verdicts.append({"name": s, "verdict": verdict, "behaviors_observed": beh if verdict != "innocent" else [],
                         "evidence": [{"day": int(x.t // 24) + 1, "description": x.desc} for x in evs if x.weight > 0][:40],
                         "recommended_action": {"likely_threat": "isolate session, open case for human review",
                                                "suspicious": "dual control on egress, step-up auth",
                                                "innocent": "none"}[verdict],
                         "min_trust": round(mins, 2)})
    accounts = {s: round(v, 2) for s, v in min_trust.items() if s.startswith("acct:")}
    return {"triage": triage, "verdicts": verdicts, "compromised_accounts": accounts, "n_evidence": len(evidence)}


# ------------------------------------------------------------------ official scoring (re-implemented)
def ground_truth(gt_records: List[dict]):
    gt, full = {}, {}
    for r in gt_records:
        if r.get("true_positive"):
            a = r.get("actor", "")
            b = r.get("behavior", "")
            if a and b:
                gt.setdefault(a, set()).add(b)
            if a:
                full.setdefault(a, {"behaviors": set(), "threat_class": r.get("threat_class", "unknown")})
                if b:
                    full[a]["behaviors"].add(b)
    return gt, full


def score_triage(triage, gt, onset_days, access_log):
    threat = set(gt); seen = set(triage); innocent = seen - threat
    esc = {a for a, ds in triage.items() if any(d.get("escalate") for d in ds)}
    tp, fp, fn = len(esc & threat), len(esc - threat), len(threat - esc)
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    bfp = len(esc & innocent) / len(innocent) if innocent else 0.0
    # onset sensitivity exactly as in the official script
    prem = tot = 0
    for a in esc & threat:
        tot += 1
        if [x for x in access_log if x.get("actor") == a and x.get("day", 999) < onset_days.get(a, 1)]:
            prem += 1
    # an additional, stricter variant: escalation decided before the onset day
    early = sum(1 for a in esc & threat if (triage[a][0].get("first_escalation_day") or 999) < onset_days.get(a, 1))
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn,
            "baseline_fp_rate": round(bfp, 4), "onset_sensitivity_official": round(prem / tot, 4) if tot else 0.0,
            "escalated_before_onset": early, "escalated": sorted(esc)}


def score_verdicts(verdicts, gt, full, access_log):
    threat = set(gt)
    vm = {v["name"]: v for v in verdicts}
    tp = fp = fn = 0
    for name, v in vm.items():
        flagged = v.get("verdict") in ("suspicious", "likely_threat")
        if flagged and name in threat:
            tp += 1
        elif flagged:
            fp += 1
    for a in threat:
        v = vm.get(a)
        if v is None or v.get("verdict") not in ("suspicious", "likely_threat"):
            fn += 1
    p = tp / (tp + fp) if tp + fp else 0.0
    r = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * p * r / (p + r) if p + r else 0.0
    vishing = False
    if any(x.get("record_type") == "phone_call" for x in access_log):
        for v in verdicts:
            if "social_engineering" in v.get("behaviors_observed", []):
                if any(any(k in e.get("description", "").lower() for k in ["phone", "call", "vish", "auth", "preceded"]) for e in v.get("evidence", [])):
                    vishing = True
    trail = False
    hosts = [x for x in access_log if x.get("record_type") == "host_event"]
    if hosts and {"bulk_file_copy", "archive_creation", "archive_move"} <= {x.get("action") for x in hosts}:
        for v in verdicts:
            if "host_data_hoarding" in v.get("behaviors_observed", []):
                d = " ".join(e.get("description", "").lower() for e in v.get("evidence", []))
                hits = sum([any(k in d for k in ["copy", "bulk", "staged"]),
                            any(k in d for k in ["compress", "archive", "zip", "7z"]),
                            any(k in d for k in ["move", "dropbox", "drive", "onedrive", "usb", "sync"])])
                if hits >= 3:
                    trail = True
    by_beh = defaultdict(lambda: {"tp": 0, "fp": 0})
    for name, v in vm.items():
        if v.get("verdict") in ("suspicious", "likely_threat") and name in threat:
            for b in v.get("behaviors_observed", []):
                by_beh[b]["tp" if b in gt.get(name, set()) else "fp"] += 1
    return {"precision": round(p, 4), "recall": round(r, 4), "f1": round(f1, 4), "tp": tp, "fp": fp, "fn": fn,
            "vishing_detected": vishing, "host_trail_reconstructed": trail,
            "by_behavior": {k: dict(v) for k, v in by_beh.items()},
            "flagged": sorted(n for n, v in vm.items() if v.get("verdict") != "innocent")}


def evaluate(data_dir: str | Path, disabled=(), trust_cfg: TrustConfig | None = None, attribution: bool = True) -> dict:
    obs, base, gtr = load(data_dir)
    out = detect(obs, base, trust_cfg=trust_cfg, disabled=disabled, attribution=attribution)
    gt, full = ground_truth(gtr)
    res = {"triage": score_triage(out["triage"], gt, ONSET, obs),
           "verdict": score_verdicts(out["verdicts"], gt, full, obs),
           "compromised_accounts": out["compromised_accounts"],
           "threat_actors_in_ground_truth": sorted(gt),
           "n_actors": len(out["triage"]), "n_evidence": out["n_evidence"]}
    # clean-period check: run on the baseline telemetry alone, nobody should be escalated
    clean = detect(base, base, trust_cfg=trust_cfg, disabled=disabled)
    esc = [a for a, ds in clean["triage"].items() if any(d["escalate"] for d in ds)]
    res["clean_period_escalations"] = esc
    res["clean_period_fp_rate"] = round(len(esc) / max(1, len(clean["triage"])), 4)
    res["verdicts"] = out["verdicts"]
    return res
