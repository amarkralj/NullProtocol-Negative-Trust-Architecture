# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""OrgForge-IT ablation: which Negative Trust principle makes the difference? -> results/orgforge_ablation.json"""
import json, pathlib, sys
from npcore.orgforge import evaluate
from npcore.trust import TrustConfig

data = sys.argv[1] if len(sys.argv) > 1 else "data/orgforge"
variants = {
    "nt (full)": {},
    "without person/account attribution": {"attribution": False},
    "without message-sentiment signal": {"disabled": ("negative_sentiment",)},
    "symmetric trust": {"trust_cfg": TrustConfig.symmetric()},
    "without correlation evidence (chain, vishing link)": {"disabled": ("account_compromise", "social_engineering", "exfil_chain")},
}
rows = {}
for name, kw in variants.items():
    r = evaluate(data, **kw)
    rows[name] = {"triage_f1": r["triage"]["f1"], "verdict_f1": r["verdict"]["f1"],
                  "baseline_fp_rate": r["triage"]["baseline_fp_rate"], "escalated": r["triage"]["escalated"],
                  "vishing_detected": r["verdict"]["vishing_detected"], "host_trail_reconstructed": r["verdict"]["host_trail_reconstructed"]}
    print(name, rows[name])
pathlib.Path("results").mkdir(exist_ok=True)
pathlib.Path("results/orgforge_ablation.json").write_text(json.dumps(rows, indent=1))
