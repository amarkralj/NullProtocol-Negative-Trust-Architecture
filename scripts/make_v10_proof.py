# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Proof bundle for v1.0 (results/v10_proof.json): what anyone needs to check the v1.0 claims without trusting us.

    1. the git commit that fixed each pre-registration, and the commit that froze the rules before the hold-out download
       (check the order with `git log`; on GitHub the push time is independent of our clocks)
    2. SHA-256 of every recorded input file (download them with scripts/fetch_splunk_attack_data.py and compare)
    3. SHA-256 of the rule files at the freeze commit, and of every result file
    4. the commands that reproduce each number
"""
import hashlib, json, pathlib, subprocess

ROOT = pathlib.Path("data/splunk_attack_data")


def sha(p):
    return hashlib.sha256(pathlib.Path(p).read_bytes()).hexdigest()


def git(*a):
    return subprocess.run(["git", *a], capture_output=True, text=True, check=True).stdout.strip()


def first_commit(path):
    return git("log", "--diff-filter=A", "--format=%H %cI %s", "--", path).splitlines()[-1]


inputs = {}
for res in ("results/v10_first_run.json", "results/v10_holdout_run.json"):
    for key, row in json.loads(pathlib.Path(res).read_text())["datasets"].items():
        for f in row.get("files", []):
            inputs[f] = sha(ROOT / f)

freeze = git("log", "--format=%H", "--grep=rules frozen before the hold-out download").splitlines()[-1]
rule_files = ["src/npcore/engine.py", "src/npcore/sources.py", "src/npcore/aiguard.py"]
proof = {
    "claim": "v1.0 detections on recorded attack logs from splunk/attack_data, scored against expectations fixed before "
             "the data was downloaded; a hold-out scored once with rules frozen before its download",
    "pre_registrations": {p: {"sha256": sha(p), "added_in": first_commit(p)} for p in
                          ("results/v10_expected.json", "results/v10_holdout_expected.json")},
    "rules_frozen_in": git("show", "-s", "--format=%H %cI %s", freeze),
    "rule_files_sha256_at_freeze": {f: hashlib.sha256(subprocess.run(["git", "show", f"{freeze}:{f}"], capture_output=True,
                                                                      check=True).stdout).hexdigest() for f in rule_files},
    "first_runs": {p: {"sha256": sha(p), "added_in": first_commit(p)} for p in
                   ("results/v10_first_run.json", "results/v10_holdout_run.json")},
    "other_results_sha256": {p: sha(p) for p in ("results/v10_regression.json", "results/v10_sim.json")},
    "input_files_sha256": dict(sorted(inputs.items())),
    "reproduce": [
        "python scripts/fetch_splunk_attack_data.py dir:datasets/<each folder in the pre-registrations>",
        "sha256sum the files under data/splunk_attack_data and compare with input_files_sha256",
        "git checkout <rules_frozen_in> && python scripts/run_v10.py --holdout   # must equal v10_holdout_run.json",
        "python scripts/run_v10.py; python scripts/run_v10_regression.py; python scripts/run_v10_sim.py",
        "python -m pytest tests/test_v10.py",
    ],
}
pathlib.Path("results/v10_proof.json").write_text(json.dumps(proof, indent=1) + "\n")
print(json.dumps({k: v for k, v in proof.items() if k != "input_files_sha256"}, indent=1), "\ninput files:", len(inputs))
