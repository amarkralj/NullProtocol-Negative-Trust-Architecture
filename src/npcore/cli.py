# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Command line interface.

    npcore suite    [--seeds 20] [--adaptive] quick comparison of all architectures (v0.3 signals) -> results/suite.json
    npcore orgforge [--data data/orgforge]    run the OrgForge-IT benchmark -> results/orgforge.json
    npcore demo     [--seed 1] [--scenario compromised]   human-readable timeline of one attack
    npcore report                              regenerate results/RESULTS.md from the JSON files
    npcore verify-ledger FILE                  verify a ledger JSONL file
    npcore stream --directory DIR.json [FILE]  run the engine on OCSF JSONL (stdin if no FILE); emits
                                               decisions, level changes and CAEP SETs as JSONL
    npcore export-ocsf [--seed 1] [--people 40] [--days 45]   simulator events as OCSF JSONL + directory
    npcore serve --directory DIR.json [--port 8080]            HTTP service (see npcore.serve)
    npcore selftest                            end-to-end check: synthetic attacks through OCSF -> engine -> CAEP
    npcore check-ocsf FILE --directory DIR.json   how much of your own OCSF data the engine can use
"""
from __future__ import annotations

import argparse
import json
import pathlib
import sys


def _demo(seed: int, scenario: str, preset_name: str) -> None:
    from . import policy as P
    from .engine import Engine, preset
    from .evaluate import responsible, HOSTILE
    from .sim import generate, PARTNER_DOMAINS
    import random

    org, events = generate(seed)
    sc = next(s for s in org.scenarios if s["name"] == scenario)
    subs = responsible(org)[scenario]
    watch = set(subs) | ({sc["victim"]} if "victim" in sc else set())
    eng = Engine(preset(preset_name, v09=True), {p: p for p in org.people}, {p: org.people[p].dept for p in org.people},
                 org.decoys, partner_domains=PARTNER_DOMAINS)
    hostile = {a for s in org.scenarios if s["name"] in HOSTILE for a in s["actors"]} | \
              {"acct:" + s["victim"] for s in org.scenarios if s["name"] == "compromised"}
    rng = random.Random(seed)
    print(f"Scenario '{scenario}' (seed {seed}, architecture {preset_name}, v0.9); onset day {sc['onset']}")
    print(f"Responsible subject(s): {', '.join(subs)}" + (f"; victim: {sc['victim']}" if "victim" in sc else ""))
    print("-" * 100)
    day = 1
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        for c in eng.due_cases(e.t):
            ok = c["subject"] in hostile
            eng.review(c["subject"], ok, c["due"])
            if c["subject"] in watch or c["subject"].replace("acct:", "") in watch:
                print(f"day {int(c['due']//24)+1:2d} {c['due']%24:05.2f}h  REVIEW  {c['subject']}: {'CONFIRMED -> isolated' if ok else 'dismissed -> containment lifted'}")
        d = eng.decide(e)
        allowed = d == P.ALLOW or (d == P.STEP_UP and e.true_actor != "external") or \
            (d == P.STEP_UP and rng.random() < 0.5) or (d == P.DUAL_CONTROL and (not e.malicious or rng.random() >= 0.7))
        if d == P.STEP_UP and allowed:
            eng.confirm_stepup(e.account, e.t)
        before = {s: eng.level[s] for s in list(eng.level)}
        ev = eng.observe(e, allowed)
        rel = [x for x in ev if x.subject in watch or x.subject.replace("acct:", "") in watch]
        if e.scenario == scenario or rel:
            if rel or d != P.ALLOW:
                tag = "" if d == P.ALLOW else f"  [{d.upper()}{'' if allowed else ' -> BLOCKED'}]"
                print(f"day {e.day:2d} {e.t%24:05.2f}h  {e.account:8s} {e.kind:12s}{tag}")
                for x in rel:
                    print(f"{'':20s}{x.weight:+.2f} {x.subject:10s} {x.kind}: {x.desc}")
        for s, lvl in eng.level.items():
            if (s in watch or s.replace("acct:", "") in watch) and before.get(s, 0) != lvl:
                print(f"{'':20s}==> {s} now at L{int(lvl)} (trust {eng.trust.trust(s, e.t):+.2f})")
    print("-" * 100)
    print(f"ledger entries: {len(eng.ledger.entries)}, integrity: {eng.ledger.verify()[0]}")


def _selftest() -> int:
    """Synthetic organisation -> OCSF -> NegativeTrust -> CAEP, with checks a deployment can rerun."""
    from .api import NegativeTrust
    from .integrations import Directory, to_ocsf
    from .sim import generate, DEPTS, PARTNER_DOMAINS
    org, events = generate(1, 60, 50)
    epoch = 1_767_225_600_000
    d = Directory({p: org.people[p].dept for p in org.people}, {f"//fs/{x}/": x for x in DEPTS},
                  partner_domains=PARTNER_DOMAINS, epoch_ms=epoch)
    nt = NegativeTrust(d, decoys=org.decoys)
    outs = list(nt.process_many(r for r in (to_ocsf(e, epoch) for e in events) if r))
    sc = {s["name"]: s for s in org.scenarios}
    victim = sc["compromised"]["victim"]
    revoked = {o["set"]["sub_id"]["id"] for o in outs if o["type"] == "caep" and any("session-revoked" in k for k in o["set"]["events"])}
    levels = {}
    for o in outs:
        if o["type"] == "level":
            levels[o["subject"]] = max(levels.get(o["subject"], 0), o["to"])
    checks = [
        ("OCSF records processed", len(events) > 0),
        ("hijacked account session revoked (CAEP)", "acct:" + victim in revoked),
        ("owner of the hijacked account not isolated", levels.get(victim, 0) < 4),
        ("malicious insider contained (L3+)", levels.get(sc["exfil_sweep"]["actors"][0], 0) >= 3),
        ("CAEP SETs well-formed", all({"iss", "jti", "iat", "aud", "sub_id", "events"} <= set(o["set"]) for o in outs if o["type"] == "caep")),
        ("ledger intact", nt.verify_ledger()["ok"]),
    ]
    for name, ok in checks:
        print(f"{'PASS' if ok else 'FAIL'}  {name}")
    print(f"{len(outs)} outputs, {sum(o['type'] == 'caep' for o in outs)} CAEP events")
    return 0 if all(ok for _, ok in checks) else 1


def _check_ocsf(path: str, directory: str) -> None:
    """Report which records of an OCSF file the engine can use and what is missing."""
    from collections import Counter
    from .integrations import Directory, from_ocsf
    d = Directory.load(directory)
    used, skipped, issues = Counter(), Counter(), Counter()
    for line in open(path):
        if not line.strip():
            continue
        r = json.loads(line)
        e = from_ocsf(r, d)
        key = f"class {r.get('class_uid')} activity {r.get('activity_id')}"
        if e is None:
            skipped[key] += 1
            continue
        used[e.kind] += 1
        if e.account not in d.departments:
            issues["user not in directory"] += 1
        if e.kind == "login" and not e.attrs.get("device"):
            issues["login without device.uid"] += 1
        if e.kind == "login" and not e.attrs.get("sid"):
            issues["login without actor.session.uid (no token-theft detection)"] += 1
        if e.kind == "read" and e.rdept is None:
            issues["file path not mapped to a department"] += 1
    print("used:", dict(used)); print("skipped:", dict(skipped)); print("issues:", dict(issues) or "none")


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="npcore", description="NullProtocol Negative Trust Architecture: NullProtocol Negative Trust reference implementation")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("suite"); s.add_argument("--seeds", type=int, default=20); s.add_argument("--people", type=int, default=150)
    s.add_argument("--adaptive", action="store_true", help="attackers who know the defences")
    o = sub.add_parser("orgforge"); o.add_argument("--data", default="data/orgforge")
    d = sub.add_parser("demo"); d.add_argument("--seed", type=int, default=1)
    d.add_argument("--scenario", default="compromised"); d.add_argument("--preset", default="nt")
    sub.add_parser("report")
    v = sub.add_parser("verify-ledger"); v.add_argument("file")
    st = sub.add_parser("stream"); st.add_argument("file", nargs="?"); st.add_argument("--directory", required=True)
    st.add_argument("--only", default="", help="comma list of output types to print (decision,level,caep)")
    ex = sub.add_parser("export-ocsf"); ex.add_argument("--seed", type=int, default=1)
    ex.add_argument("--people", type=int, default=40); ex.add_argument("--days", type=int, default=45)
    ex.add_argument("--out", default="examples/ocsf")
    sv = sub.add_parser("serve"); sv.add_argument("--directory", required=True)
    sv.add_argument("--host", default="127.0.0.1"); sv.add_argument("--port", type=int, default=8080)
    sub.add_parser("selftest")
    co = sub.add_parser("check-ocsf"); co.add_argument("file"); co.add_argument("--directory", required=True)
    rp = sub.add_parser("respond", help="v1.0: read recorded logs, decide, and plan (or run) the response actions")
    rp.add_argument("files", nargs="+")
    rp.add_argument("--systems", default="ssf", help="connectors that exist: ssf,entra,okta,google,aws,github,kubernetes,host")
    rp.add_argument("--okta-domain", default="example.okta.com"); rp.add_argument("--k8s-api", default="https://kubernetes.default.svc")
    rp.add_argument("--audience", default="https://receiver.example/ssf", help="SSF receiver URL for signed CAEP events")
    rp.add_argument("--execute", action="store_true", help="run actions whose connector token is set (NP_*_TOKEN); default: dry run")
    rp.add_argument("--approve", default="", help="comma list of action ids a person has approved")
    rp.add_argument("--out", default="results/response_plan.json")
    a = ap.parse_args(argv)
    out = pathlib.Path("results"); out.mkdir(exist_ok=True)
    if a.cmd == "suite":
        from .evaluate import run_suite
        res = run_suite(seeds=range(1, a.seeds + 1), n_people=a.people, v03=True,
                        scenario_set="adaptive" if a.adaptive else "standard")
        (out / "suite.json").write_text(json.dumps(res, indent=1))
        print(json.dumps(res["summary"], indent=1))
    elif a.cmd == "orgforge":
        from .orgforge import evaluate
        res = evaluate(a.data)
        (out / "orgforge.json").write_text(json.dumps(res, indent=1, default=list))
        print(json.dumps({k: v for k, v in res.items() if k != "verdicts"}, indent=1, default=list))
    elif a.cmd == "demo":
        _demo(a.seed, a.scenario, a.preset)
    elif a.cmd == "report":
        from .report import write_report
        print(write_report(out))
    elif a.cmd == "stream":
        from .integrations import Directory, stream
        d = Directory.load(a.directory)
        fh = open(a.file) if a.file else sys.stdin
        only = set(filter(None, a.only.split(",")))
        for rec in stream((json.loads(line) for line in fh if line.strip()), d):
            if not only or rec["type"] in only:
                print(json.dumps(rec))
    elif a.cmd == "export-ocsf":
        from .integrations import to_ocsf
        from .sim import generate, DEPTS, PARTNER_DOMAINS
        org, events = generate(a.seed, a.people, a.days)
        o = pathlib.Path(a.out); o.mkdir(parents=True, exist_ok=True)
        epoch = 1_767_225_600_000          # 2026-01-01T00:00:00Z
        n = 0
        with open(o / "events.ocsf.jsonl", "w") as fh:
            for e in events:
                r = to_ocsf(e, epoch)
                if r is not None:
                    fh.write(json.dumps(r) + "\n"); n += 1
        directory = {"departments": {p: org.people[p].dept for p in org.people},
                     "path_departments": {f"//fs/{d}/": d for d in DEPTS}, "partner_domains": list(PARTNER_DOMAINS),
                     "home_countries": ["DE"], "epoch_ms": epoch}
        (o / "directory.json").write_text(json.dumps(directory, indent=1))
        print(f"wrote {n} OCSF records to {o/'events.ocsf.jsonl'} and {o/'directory.json'}")
    elif a.cmd == "serve":
        from .serve import serve
        serve(a.directory, a.host, a.port)
    elif a.cmd == "selftest":
        return _selftest()
    elif a.cmd == "check-ocsf":
        _check_ocsf(a.file, a.directory)
    elif a.cmd == "respond":
        from . import sources
        from .respond import respond_replay
        events = sources.load([pathlib.Path(f) for f in a.files])
        if not events:
            print("no events could be read from", a.files); return 1
        eng, r = respond_replay(events, systems=tuple(a.systems.split(",")),
                                cfg={"okta_domain": a.okta_domain, "k8s_api": a.k8s_api})
        r.audience = a.audience
        for act in r.plan:
            print(f"{act.id}  {act.system:10s} {act.action:26s} {'NEEDS APPROVAL' if act.approval else 'auto':14s} "
                  f"{act.method} {act.url}")
        res = r.execute(approved=set(filter(None, a.approve.split(",")))) if a.execute else []
        for x in res:
            print("result", x)
        pathlib.Path(a.out).write_text(json.dumps({"actions": [x.to_dict() for x in r.plan], "results": res,
                                                   "ledger_ok": r.ledger.verify()[0]}, indent=1))
        r.ledger.dump_jsonl(pathlib.Path(a.out).with_suffix(".ledger.jsonl"))
        print(f"{len(r.plan)} actions ({'executed where possible' if a.execute else 'dry run'}); plan: {a.out}")
    elif a.cmd == "verify-ledger":
        from .ledger import Ledger
        ok, bad = Ledger.load_jsonl(a.file).verify()
        print("OK" if ok else f"TAMPERED at entry {bad}")
        return 0 if ok else 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
