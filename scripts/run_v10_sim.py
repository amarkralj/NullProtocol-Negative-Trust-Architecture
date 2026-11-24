# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.0 regression on the simulator: v0.9 and v1.0 on the release seeds (office 301-320, unseen profiles 601-610;
standard, adaptive and incident-case attack sets). The v1.0 rules must not lower prevention or containment and must
not restrict more innocent people. Writes results/v10_sim.json."""
import json, multiprocessing as mp, pathlib
from npcore.engine import version_preset
from npcore.evaluate import run_one, summarise
from npcore.sim import generate

ARCHS = ["nt v0.9", "nt v1.0"]
SETS = ("standard", "adaptive", "cases")
GROUPS = {"office": (("office",), range(301, 321)), "unseen_profiles": (("remote_first", "night_shift"), range(601, 611))}


def _one(args):
    group, profile, seed, ss = args
    data = generate(seed, scenario_set=ss, profile=profile)
    out = []
    for a in ARCHS:
        r = run_one(seed, a, cfg=version_preset(a.split()[1]), scenario_set=ss, data=data)
        r.pop("cases", None); r.update(group=group, set=ss)
        out.append(r)
    return out


if __name__ == "__main__":
    tasks = [(g, pf, s, ss) for g, (pfs, seeds) in GROUPS.items() for pf in pfs for s in seeds for ss in SETS]
    with mp.Pool(8) as pool:
        runs = [r for rs in pool.map(_one, tasks) for r in rs]
    res = {g: {ss: summarise([r for r in runs if r["group"] == g and r["set"] == ss]) for ss in SETS} for g in GROUPS}
    pathlib.Path("results/v10_sim.json").write_text(json.dumps(res, indent=1))
    for g in res:
        for ss in SETS:
            for a, m in res[g][ss].items():
                print(g, ss, a, {k: v for k, v in m.items() if isinstance(v, (int, float))})
