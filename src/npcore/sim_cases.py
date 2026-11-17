# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Case scenarios modelled on publicly documented incidents (scenario_set="cases", v0.4).

Each scenario reproduces the attack path of a real incident in the simulated organisation, and each
comes with benign look-alikes, so a detector that simply flags the event type pays for it in false
alarms. Sources are listed in docs/04-evaluation.md.

    helpdesk_reset    MGM Resorts 2023: the help desk is talked into resetting a privileged user's MFA;
                      the attacker logs in from a new device and adds an identity provider
    mfa_fatigue       Uber 2022: a burst of MFA push prompts until one is approved
    har_session       Okta support 2023: an admin session token from an uploaded support file is
                      replayed from another browser while the owner is offline
    dormant_creds     Snowflake 2024: an old password from an infostealer log, no MFA, on an account
                      nobody has used for weeks; bulk export
    oauth_token       Salesloft Drift 2025: an integration's OAuth token is used from a new network for
                      bulk exports and secret searches
    bribed_support    Coinbase 2024/25: support agents paid to look up customer records without a ticket
    post_termination  Cash App 2022: a former employee keeps access and downloads reports
    fake_worker       KnowBe4 2024: a newly hired remote engineer's laptop runs an infostealer and a
                      remote-access tool

Benign look-alikes: verified and unverified password resets (some followed by a new laptop), single
mistaken push denials, a return from parental leave, support agents' rare look-ups without a ticket,
normal integration traffic with occasional peaks, harmless adware findings, a legitimate MFA policy
change by IT, and leavers who simply stop working. All case noise uses its own random streams, so the
standard and adaptive sets are unchanged.
"""
from __future__ import annotations

import random
from typing import List

CASE_SCENARIOS = ["helpdesk_reset", "mfa_fatigue", "har_session", "dormant_creds", "oauth_token",
                  "bribed_support", "post_termination", "fake_worker"]
CASE_CLASS = {"helpdesk_reset": "external", "mfa_fatigue": "external", "har_session": "external",
              "dormant_creds": "external", "oauth_token": "external", "bribed_support": "malicious",
              "post_termination": "malicious", "fake_worker": "malicious"}
CASE_TAKEOVER = {"helpdesk_reset", "mfa_fatigue", "har_session", "dormant_creds", "oauth_token"}
WORKLOAD = "svc-crm"
WORKLOAD_IP = "10.9.0.5"
SECRET_QUERIES = ("AKIA", "password", "secret_key", "vpn")


def setup(org, rng_seed: int, pick) -> None:
    """Roles and lifecycle facts the case scenarios and their noise need."""
    from .sim import Person
    r = random.Random(rng_seed * 41 + 3)
    people = org.people
    sales = [p for p in people.values() if p.dept == "Sales" and not p.manager]
    for p in r.sample(sales, min(6, len(sales))):
        p.support_agent = True
    # benign: one person on parental leave who comes back on a known device
    cand = [p for p in people.values() if not p.support_agent and not p.it_support]
    leave = r.choice(cand)
    leave.leave = (8, 46)
    # benign: two leavers who simply stop
    for p in r.sample([p for p in cand if p is not leave], 2):
        p.end_day = r.randint(24, 40)
    # the integration (a workload, not a person)
    people[WORKLOAD] = Person(WORKLOAD, "Sales", 0.0, ["svc-runtime"], WORKLOAD_IP, workload=True)


def benign(rng_seed: int, org, p, day: int, start: float, end: float, ip: str, dev: str, Event) -> List:
    """Case-set benign noise for one person-day (separate random stream)."""
    r = random.Random(f"case-{rng_seed}-{p.id}-{day}")
    ev = []
    if r.random() < 0.0025:                                   # forgotten password / new phone
        verified = r.random() < 0.8
        t = start - 0.3
        ev.append(Event(t, p.id, "mfa_reset", attrs={"via": "helpdesk", "verified": verified}, true_actor=p.id))
    if r.random() < 0.01:                                     # one mistaken push denial
        ev.append(Event(start - 0.05, p.id, "mfa_push", attrs={"result": "deny"}, true_actor=p.id))
    if r.random() < 0.002:                                    # adware, potentially unwanted program
        ev.append(Event(r.uniform(start, end), p.id, "detection", attrs={"severity": "low", "name": "adware", "device": dev},
                        true_actor=p.id))
    if getattr(p, "support_agent", False):
        for _ in range(r.randint(25, 45)):
            assigned = r.random() > 0.03
            ev.append(Event(r.uniform(start, end), p.id, "record_read", f"cust-{r.randint(1, 90000)}", "Sales", True, 1_000_000,
                            attrs={"ticket": f"T-{r.randint(1000, 9999)}" if assigned else None, "assigned": assigned},
                            true_actor=p.id))
    if p.it_support and day == 33 and r.random() < 0.5:     # a legitimate MFA policy change by IT
        ev.append(Event(r.uniform(start, end), p.id, "config_change", attrs={"what": "mfa_policy", "ticket": "CHG-2231"},
                        sensitive=True, true_actor=p.id))
    return ev


def workload_day(rng_seed: int, day: int, Event) -> List:
    r = random.Random(f"wl-{rng_seed}-{day}")
    base = (day - 1) * 24
    ev = []
    for _ in range(r.randint(18, 30)):
        n = r.randint(20, 60) * (3 if r.random() < 0.03 else 1)
        ev.append(Event(base + r.uniform(0, 24), WORKLOAD, "api_export", "crm/accounts", "Sales", False, n * 4000,
                        attrs={"ip": WORKLOAD_IP, "sip": WORKLOAD_IP, "objects": n, "query": "SELECT Id, Name FROM Account"},
                        true_actor=WORKLOAD))
    return ev


def scenario(rng, org, s: dict, name: str, label: str, onset: int, Event, ip_fn) -> List:
    P = org.people
    ev: List = []

    def E(t, acct, kind, actor, malicious=True, **kw):
        return Event(t, acct, kind, true_actor=actor, scenario=label, malicious=malicious, **kw)

    def restricted(dept):
        return [f for f in org.files[f"//fs/{dept}/restricted"] if not org.file_meta[f].get("decoy")]

    def loot(t, acct, actor, dept, ctx, n=12, mb=(200, 400)):
        out = []
        for f in rng.sample(restricted(dept), n):
            out.append(E(t + rng.uniform(0, .8), acct, "read", actor, resource=f, rdept=dept, sensitive=True,
                         nbytes=org.file_meta[f]["bytes"], attrs=dict(ctx)))
        out.append(E(t + 1.0, acct, "egress_cloud", actor, resource="bulk", rdept=dept, sensitive=True,
                     nbytes=rng.randint(*mb) * 1_000_000, attrs=dict(ctx, dest="file-share.example")))
        return out

    if name == "helpdesk_reset":                              # MGM 2023
        v = P[s["victim"]]
        t0 = (onset - 1) * 24 + rng.uniform(13, 16)
        ev.append(E(t0, v.id, "mfa_reset", "external", attrs={"via": "helpdesk", "verified": False}))
        ip = ip_fn(rng, "residential")
        ctx = {"device": "dev-unknown-hd", "ip": ip, "ip_type": "residential", "sid": f"s-hd-{v.id}", "sip": ip, "ua": "Chrome/124 Win"}
        t1 = t0 + rng.uniform(0.3, 1.0)
        ev.append(E(t1, v.id, "login", "external", attrs=dict(ctx)))
        ev.append(E(t1 + 0.4, v.id, "config_change", "external", sensitive=True, attrs=dict(ctx, what="add_identity_provider")))
        ev.append(E(t1 + 0.6, v.id, "grant", "external", resource=f"//fs/{v.dept}/restricted", rdept=v.dept, sensitive=True,
                    attrs=dict(ctx, grantee=v.id)))
        for k in range(3):
            ev += loot(t1 + 1 + k * 6, v.id, "external", rng.choice(["Finance", "HR", "Legal"]), ctx)
    elif name == "mfa_fatigue":                               # Uber 2022
        v = P[s["victim"]]
        t0 = (onset - 1) * 24 + rng.uniform(22, 23.5)
        for k in range(rng.randint(9, 16)):
            ev.append(E(t0 + k * 0.05, v.id, "mfa_push", "external", attrs={"result": "deny"}))
        ta = t0 + 1.0
        ev.append(E(ta, v.id, "mfa_push", "external", attrs={"result": "approve"}))
        ip = ip_fn(rng, "foreign")
        ctx = {"device": "dev-unknown-mf", "ip": ip, "ip_type": "foreign", "sid": f"s-mf-{v.id}", "sip": ip, "ua": "Firefox/125 Linux"}
        ev.append(E(ta + 0.05, v.id, "login", "external", attrs=dict(ctx)))
        for k in range(3):
            ev += loot(ta + 0.3 + k * 3, v.id, "external", rng.choice(["Engineering", "Finance"]), ctx)
    elif name == "har_session":                               # Okta support 2023
        v = P[s["victim"]]
        day = onset
        sid = f"s-{v.id}-{day}-har"
        own_ip = ip_fn(rng, "corporate")
        t_own = (day - 1) * 24 + 9.0
        ev.append(E(t_own, v.id, "login", v.id, False, attrs={"device": v.devices[0], "ip": own_ip, "ip_type": "corporate",
                                                                "sid": sid, "sip": own_ip, "ua": "Edge/124 Win"}))
        ip = ip_fn(rng, "residential")
        ctx = {"device": v.devices[0], "ip": ip, "ip_type": "residential", "sid": sid, "sip": ip, "ua": "python-requests/2.31"}
        t1 = (day - 1) * 24 + rng.uniform(20, 22)            # owner offline: no interleaving
        ev.append(E(t1, v.id, "config_change", "external", sensitive=True, attrs=dict(ctx, what="add_admin_api_token")))
        for k in range(2):
            ev += loot(t1 + 0.5 + k * 4, v.id, "external", rng.choice(["Engineering", "Legal"]), ctx)
    elif name == "dormant_creds":                             # Snowflake 2024
        v = P[s["victim"]]
        ip = ip_fn(rng, "foreign")
        ctx = {"device": "dev-unknown-dc", "ip": ip, "ip_type": "foreign", "sid": f"s-dc-{v.id}", "sip": ip, "ua": "DBeaver/24",
               "mfa": False}
        t1 = (onset - 1) * 24 + rng.uniform(1, 4)
        ev.append(E(t1, v.id, "login", "external", attrs=dict(ctx)))
        for k in range(3):
            ev.append(E(t1 + 0.5 + k * 5, v.id, "copy", "external", resource="warehouse", rdept=v.dept, sensitive=True,
                        nbytes=rng.randint(800, 1500) * 1_000_000, attrs=dict(ctx, files=1)))
            ev.append(E(t1 + 1.0 + k * 5, v.id, "egress_cloud", "external", resource="warehouse", rdept=v.dept, sensitive=True,
                        nbytes=rng.randint(600, 1200) * 1_000_000, attrs=dict(ctx, dest="mega.nz")))
    elif name == "oauth_token":                               # Salesloft Drift 2025
        ip = ip_fn(rng, "foreign")
        for k in range(14):
            t = (onset - 1) * 24 + rng.uniform(0, 72)
            q = "SELECT * FROM Case WHERE Description LIKE '%" + rng.choice(SECRET_QUERIES) + "%'" if k % 4 == 0 else "SELECT * FROM Account"
            n = rng.randint(400, 900)
            ev.append(E(t, WORKLOAD, "api_export", "external", resource="crm/all", rdept="Sales", sensitive=True,
                        nbytes=n * 4000 * 10, attrs={"ip": ip, "sip": ip, "objects": n, "query": q}))
    elif name == "bribed_support":                            # Coinbase 2024/25
        for a_id in s["actors"]:
            a = P[a_id]
            for d in range(onset, min(org.days, onset + 20) + 1):
                if (d - 1) % 7 >= 5:
                    continue
                for _ in range(rng.randint(8, 18)):
                    ev.append(E((d - 1) * 24 + rng.uniform(10, 17), a.id, "record_read", a.id, resource=f"cust-{rng.randint(1, 90000)}",
                                rdept="Sales", sensitive=True, nbytes=1_000_000, attrs={"ticket": None, "assigned": False}))
    elif name == "post_termination":                          # Cash App 2022
        a = P[s["actors"][0]]
        a.end_day = onset
        ev.append(E((onset - 1) * 24 + 17.5, a.id, "lifecycle", a.id, False, attrs={"status": "terminated"}))
        for k, d in enumerate(range(onset + 3, min(org.days, onset + 15) + 1, 4)):
            t = (d - 1) * 24 + rng.uniform(19, 22)
            ctx = {"device": a.devices[0], "ip": a.home_ip, "ip_type": "residential", "sid": f"s-pt-{a.id}-{k}", "sip": a.home_ip}
            ev.append(E(t, a.id, "login", a.id, attrs=dict(ctx)))
            ev.append(E(t + 0.5, a.id, "copy", a.id, resource="reports", rdept=a.dept, sensitive=True,
                        nbytes=rng.randint(300, 600) * 1_000_000, attrs=dict(ctx, files=30)))
            ev.append(E(t + 1.0, a.id, "egress_usb", a.id, resource="reports", rdept=a.dept, sensitive=True,
                        nbytes=rng.randint(300, 600) * 1_000_000, attrs=dict(ctx, removable=True)))
    elif name == "fake_worker":                               # KnowBe4 2024
        a = P[s["actors"][0]]
        a.start_day = onset
        dev = a.devices[0]
        t0 = (onset - 1) * 24 + 21.9
        ev.append(E(t0, a.id, "detection", a.id, attrs={"severity": "high", "name": "infostealer", "device": dev}))
        ev.append(E(t0 + 0.2, a.id, "detection", a.id, attrs={"severity": "medium", "name": "remote_access_tool", "device": dev}))
        for k in range(3):
            d = onset + 1 + k * 2
            t = (d - 1) * 24 + rng.uniform(10, 14)
            ctx = {"device": dev, "ip": a.home_ip, "ip_type": "residential"}
            ev.append(E(t, a.id, "clone", a.id, resource="repos", rdept="Engineering", sensitive=True, nbytes=15 * 40_000_000,
                        attrs=dict(ctx, count=15)))
            ev.append(E(t + 1, a.id, "egress_cloud", a.id, resource="repos", rdept="Engineering", sensitive=True,
                        nbytes=rng.randint(300, 700) * 1_000_000, attrs=dict(ctx, dest="file-share.example")))
    return ev
