# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
from npcore.anon import pseudonymize


def test_identities_replaced_and_stable():
    r = {"ds": {"expected": ["idp_risk"], "events_mapped": 3,
                "v0.6": {"detections": {"idp_risk": ["acct:alice@lab.onmicrosoft.com", "acct:jdoe"]},
                         "levels": {"acct:alice@lab.onmicrosoft.com": 2, "jdoe": 3, "acct:unknown": 1},
                         "note": "arn:aws:sts::123456789012:assumed-role/x/alice@lab.onmicrosoft.com by jdoe"}}}
    a = pseudonymize(r)
    t = str(a)
    assert "alice" not in t and "jdoe" not in t and "123456789012" not in t
    assert a["ds"]["expected"] == ["idp_risk"] and a["ds"]["events_mapped"] == 3
    assert "acct:unknown" in a["ds"]["v0.6"]["levels"]                    # generic names kept
    assert pseudonymize(r) == a                                           # stable
    lv = a["ds"]["v0.6"]["levels"]
    assert any(k.startswith("acct:user-") and k.endswith("@example.org") for k in lv)
    assert any(k.startswith("principal-") for k in lv)
