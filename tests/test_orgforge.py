# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
from pathlib import Path

import pytest

from npcore.orgforge import detect, score_triage, score_verdicts

DATA = Path(__file__).resolve().parent.parent / "data" / "orgforge"


def test_scorer_matches_official_logic_on_toy_input():
    triage = {"A": [{"escalate": True}], "B": [{"escalate": True}], "C": [{"escalate": False}]}
    s = score_triage(triage, {"A": {"x"}}, {"A": 1}, [])
    assert (s["tp"], s["fp"], s["fn"]) == (1, 1, 0) and s["baseline_fp_rate"] == 0.5
    v = score_verdicts([{"name": "A", "verdict": "suspicious", "behaviors_observed": ["x"], "evidence": []},
                        {"name": "C", "verdict": "innocent"}], {"A": {"x"}}, {}, [])
    assert v["f1"] == 1.0


def test_vishing_victim_is_not_flagged_in_toy_stream():
    recs = [{"record_type": "phone_call", "day": 3, "actor": "Eve", "target": "Bob", "access_hour": 12},
            {"record_type": "idp_auth", "day": 3, "actor": "Bob", "access_hour": 12.3, "new_device": True,
             "anomalous_ip": True, "preceded_by_call_record": True, "call_to_auth_gap_minutes": 17}]
    out = detect(recs, [])
    v = {x["name"]: x for x in out["verdicts"]}
    assert v["Bob"]["verdict"] == "innocent"
    assert "acct:Bob" in out["compromised_accounts"]
    assert "social_engineering" in v["Eve"]["behaviors_observed"] or v["Eve"]["min_trust"] < 0


@pytest.mark.skipif(not (DATA / "telemetry").exists(), reason="OrgForge data not downloaded (scripts/fetch_orgforge.py)")
def test_orgforge_benchmark_scores():
    from npcore.orgforge import evaluate
    r = evaluate(DATA)
    assert r["triage"]["f1"] >= 0.8 and r["verdict"]["f1"] >= 0.8
    assert r["clean_period_fp_rate"] == 0.0
