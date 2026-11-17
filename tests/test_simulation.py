# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
from npcore.evaluate import run_one
from npcore.sim import generate


def test_simulation_is_deterministic():
    _, a = generate(3, n_people=40, days=30)
    _, b = generate(3, n_people=40, days=30)
    assert [(e.t, e.account, e.kind) for e in a[:500]] == [(e.t, e.account, e.kind) for e in b[:500]]


def test_nt_beats_perimeter_on_small_org():
    nt = run_one(5, "nt", n_people=60, days=50)
    per = run_one(5, "perimeter", n_people=60, days=50)
    hostile = [k for k in nt["scenarios"] if k != "negligent"]
    nt_real = sum(nt["scenarios"][k]["realized_bytes"] for k in hostile)
    per_real = sum(per["scenarios"][k]["realized_bytes"] for k in hostile)
    assert nt_real < 0.5 * per_real
    assert nt["scenarios"]["compromised"]["victim_person_contained"] is False
    assert nt["ledger_ok"]
