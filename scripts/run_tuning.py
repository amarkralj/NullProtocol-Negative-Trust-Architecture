# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Tune NT and the zero-trust baseline with correlation and decoys on three organisation types, test on two unseen ones.
Writes results/tuning.json."""
import json, multiprocessing as mp, pathlib, time
from npcore.tune import search, evaluate, TEST_PROFILES, DEFAULT, DEFAULT_ZT

if __name__ == "__main__":
    t0 = time.time()
    out = {}
    with mp.Pool(9) as pool:
        for arch, default in (("nt_no_sentiment", DEFAULT), ("zt_strong", DEFAULT_ZT)):
            res = search(arch, pool=pool, log=lambda m: print(f"[{time.time()-t0:5.0f}s] {m}", flush=True))
            test_default = evaluate(arch, default, TEST_PROFILES, range(501, 511), pool)
            test_tuned = evaluate(arch, res["best"]["params"], TEST_PROFILES, range(501, 511), pool)
            out[arch] = {"best_params": res["best"]["params"], "train_utility_best": res["best"]["utility"],
                         "train_utility_default": res["default_utility"], "candidates": res["tried"],
                         "test_default": test_default, "test_tuned": test_tuned, "history": res["history"]}
            print(arch, "test U default", round(test_default["utility"], 2), "tuned", round(test_tuned["utility"], 2), flush=True)
    out["config"] = {"train_profiles": ["office", "usb_culture", "finance_heavy"], "train_seeds": [401, 402],
                     "test_profiles": list(TEST_PROFILES), "test_seeds": list(range(501, 511))}
    pathlib.Path("results/tuning.json").write_text(json.dumps(out, indent=1))
    print("done", round(time.time() - t0), "s")
