# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Synthetic organisation with labelled insider scenarios.

The simulator produces *planned* events. The engine under test decides whether each one is
allowed, so containment really changes what an insider manages to exfiltrate. Ground truth
(who really acted, which scenario) is attached to each event but never shown to the engine.

Benign noise is deliberate: on-call night work, travel, new laptops, month-end exports to
auditors, bad weeks with negative messages, new projects with many repo clones, and rare
curiosity clicks on decoy files. Without it, any detector looks perfect.

Scenarios (one instance of each per seed by default):
    exfil_sweep        malicious insider sweeps shares off-hours, stages, archives, uploads
    disgruntled        negative sentiment, ghost/off-hours logins, snooping in HR/Finance, one leak
    negligent          secret committed to a repo, sensitive file mailed to a wrong external address
    compromised        external attacker vishes an employee, logs in with their account, enumerates
    collusion          Finance insider grants a Sales colleague access, the colleague exfiltrates via USB
    low_slow           careful insider: own files, business hours, small daily mails to personal webmail

Adaptive scenario set (scenario_set="adaptive", added in v0.2 as a red team against v0.1). The
insiders know the defences: they avoid decoys, stay in business hours and on their own devices,
keep volumes normal, warm up destinations, and avoid the signals the v0.1 engine is known to use.
The adaptive set also adds benign noise that v0.1 never saw: regular USB users, IT support staff
who log into colleagues' accounts from their own devices, and benign personal-cloud sync.

    quiet_exfil        own files, business hours, mail to a pre-warmed lookalike partner domain
    token_theft        external attacker replays a stolen session token: victim's own device id,
                       in-country residential IP, no phone call, egress to a business file-share
    impersonation      employee logs into a colleague's account from their own device and leaks
                       from it (CERT r4.2 scenario 3 pattern): who gets the blame?
    decoy_aware_sweep  avoids decoys and read spikes, own department only, weekly USB copies
    collusion_quiet    no access grant: internal forwards, the receiver mails them out weekly
    negligent_repeat   careless, not hostile: three mis-addressed mails and a USB copy for a client
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .deception import DecoyRegistry, FILE, CREDENTIAL, ACCOUNT as DECOY_ACCOUNT

DEPTS = ["Engineering", "Sales", "Finance", "HR", "Legal", "Product"]
PERSONAL_DOMAINS = ("gmail.com", "protonmail.com", "outlook.com", "gmx.de", "web.de")
PARTNER_DOMAINS = ("auditor-kpmg.example", "bank-partner.example", "supplier.example", "client.example")
SCENARIOS = ["exfil_sweep", "disgruntled", "negligent", "compromised", "collusion", "low_slow"]
ADAPTIVE_SCENARIOS = ["quiet_exfil", "token_theft", "impersonation", "decoy_aware_sweep", "collusion_quiet", "negligent_repeat"]
from . import sim_cases as SC
SCENARIO_SETS = {"standard": SCENARIOS, "adaptive": ADAPTIVE_SCENARIOS, "all": SCENARIOS + ADAPTIVE_SCENARIOS,
                 "cases": SC.CASE_SCENARIOS}
MALICIOUS_CLASS = {"exfil_sweep": "malicious", "disgruntled": "disgruntled", "negligent": "negligent",
                   "compromised": "external", "collusion": "malicious", "low_slow": "malicious",
                   "quiet_exfil": "malicious", "token_theft": "external", "impersonation": "malicious",
                   "decoy_aware_sweep": "malicious", "collusion_quiet": "malicious", "negligent_repeat": "negligent",
                   **SC.CASE_CLASS}
NEGLIGENT_TYPES = {t for t, c in MALICIOUS_CLASS.items() if c == "negligent"}
ACCOUNT_TAKEOVER_TYPES = {"compromised", "token_theft"} | SC.CASE_TAKEOVER      # responsible subject is the account, not a person
LOOKALIKE_DOMAIN = "client-example.co"

# Organisation profiles: different kinds of company. "office" is the default used for all v0.1/v0.2 results.
PROFILES = {
    "office":        dict(dept_w=[35, 20, 12, 8, 6, 19], oncall=0.2, remote=0.25, travel=0.012, new_laptop=0.003,
                          private_fwd=0.004, sens_high=0.25, sens_low=0.1, usb=0.08, cloud=0.03),
    "remote_first":  dict(dept_w=[40, 25, 10, 6, 4, 15], oncall=0.2, remote=0.75, travel=0.04, new_laptop=0.006,
                          private_fwd=0.008, sens_high=0.25, sens_low=0.1, usb=0.04, cloud=0.08),
    "usb_culture":   dict(dept_w=[30, 30, 10, 8, 4, 18], oncall=0.15, remote=0.15, travel=0.02, new_laptop=0.003,
                          private_fwd=0.004, sens_high=0.25, sens_low=0.1, usb=0.25, cloud=0.05),
    "finance_heavy": dict(dept_w=[15, 15, 35, 15, 12, 8], oncall=0.1, remote=0.2, travel=0.01, new_laptop=0.003,
                          private_fwd=0.004, sens_high=0.4, sens_low=0.15, usb=0.06, cloud=0.02),
    "night_shift":   dict(dept_w=[55, 10, 8, 6, 4, 17], oncall=0.5, remote=0.35, travel=0.015, new_laptop=0.004,
                          private_fwd=0.004, sens_high=0.25, sens_low=0.12, usb=0.1, cloud=0.04),
}


@dataclass
class Event:
    t: float                      # hours since start
    account: str                  # account the event is logged under (what the engine sees)
    kind: str                     # login, read, copy, archive, egress_usb, egress_cloud, email, clone, msg, grant, commit, call
    resource: Optional[str] = None
    rdept: Optional[str] = None   # department owning the resource
    sensitive: bool = False
    nbytes: int = 0
    attrs: dict = field(default_factory=dict)
    # ---- ground truth (hidden from the engine) ----
    true_actor: str = ""          # who really acted ("external" for outside attackers)
    scenario: Optional[str] = None  # scenario id if part of an insider scenario
    malicious: bool = False       # is this specific event harmful?

    @property
    def day(self) -> int:
        return int(self.t // 24) + 1


@dataclass
class Person:
    id: str
    dept: str
    start_h: float
    devices: List[str]
    home_ip: str
    oncall: bool = False
    manager: bool = False
    usb_user: bool = False        # adaptive-set noise: uses USB sticks for presentations
    it_support: bool = False      # adaptive-set noise: logs into colleagues' accounts to help them
    cloud_sync: bool = False      # adaptive-set noise: syncs general files to a personal cloud
    support_agent: bool = False   # cases set: looks up customer records for tickets
    workload: bool = False        # cases set: an integration account, not a person
    start_day: int = 1            # cases set: joins later (new hire)
    end_day: Optional[int] = None  # cases set: leaves the organisation
    leave: Optional[tuple] = None  # cases set: (first, last) day of leave
    scenario_term: bool = False


@dataclass
class Org:
    people: Dict[str, Person]
    files: Dict[str, List[str]]           # location -> file ids
    file_meta: Dict[str, dict]
    decoys: DecoyRegistry
    days: int
    scenarios: List[dict]
    extra_noise: bool = False
    profile: dict = field(default_factory=dict)
    case_mode: bool = False
    case_seed: int = 0


def _ip(rng, kind="corporate"):
    if kind == "corporate":
        return f"10.{rng.randint(0, 3)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    if kind == "residential":
        return f"91.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
    return f"185.{rng.randint(0, 255)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"   # foreign / VPS


def build_org(seed: int, n_people: int = 150, days: int = 60, files_per_loc: int = 60,
              scenario_set: str = "standard", instances: int = 1, extra_noise: Optional[bool] = None,
              profile: str = "office") -> Org:
    rng = random.Random(seed)
    pf = PROFILES[profile]
    people = {}
    for i in range(n_people):
        dept = DEPTS[i % len(DEPTS)] if i < len(DEPTS) * 2 else rng.choices(DEPTS, weights=pf["dept_w"])[0]
        pid = f"u{i:03d}"
        people[pid] = Person(pid, dept, rng.gauss(8.3, 0.8), [f"dev-{pid}-a"], _ip(rng, "residential"),
                             oncall=(dept == "Engineering" and rng.random() < pf["oncall"]), manager=rng.random() < 0.12)
    files, meta = {}, {}
    for d in DEPTS:
        for loc, sens in ((f"//fs/{d}/general", False), (f"//fs/{d}/restricted", True)):
            ids = []
            for k in range(files_per_loc):
                fid = f"{d[:3].lower()}-{'r' if sens else 'g'}-{k:03d}"
                meta[fid] = {"loc": loc, "dept": d, "sensitive": sens, "bytes": int(rng.lognormvariate(14.5, 1.2))}
                ids.append(fid)
            files[loc] = ids
    decoys = DecoyRegistry(seed=seed)
    decoys.deploy_for_org({d: [] for d in DEPTS}, per_dept=3)
    # place decoy files among the restricted files
    for dcy in decoys.decoys.values():
        if dcy.cls == FILE:
            files[dcy.location].append(dcy.id)
            meta[dcy.id] = {"loc": dcy.location, "dept": dcy.dept, "sensitive": True, "bytes": 250_000, "decoy": True}
    # choose scenario actors
    by_dept = {d: [p for p in people.values() if p.dept == d and not p.manager] for d in DEPTS}
    used = set()

    def pick(dept=None):
        pool = [p for p in (by_dept[dept] if dept else people.values()) if p.id not in used and not p.workload]
        p = rng.choice(pool); used.add(p.id); return p

    sc = []
    if extra_noise is None:
        extra_noise = scenario_set != "standard"
    if extra_noise:
        nrng = random.Random(seed * 31 + 7)
        eng_people = [p for p in people.values() if p.dept == "Engineering" and not p.manager]
        for p in nrng.sample(eng_people, min(len(eng_people), max(2, n_people // 50))):
            p.it_support = True
        for p in people.values():
            p.usb_user = nrng.random() < pf["usb"]
            p.cloud_sync = nrng.random() < pf["cloud"]
    case_mode = scenario_set == "cases"
    if case_mode:
        class _O: pass
        tmp = _O(); tmp.people = people
        SC.setup(tmp, seed, None)
        for p_ in people.values():
            if p_.support_agent or p_.leave or p_.end_day or p_.workload:
                used.add(p_.id)
    types = [t for t in SCENARIO_SETS[scenario_set] for _ in range(instances)]
    seen: Dict[str, int] = {}
    for name in types:
        seen[name] = seen.get(name, 0) + 1
        label = name if instances == 1 else f"{name}#{seen[name]}"
        onset = rng.randint(22, max(34, days - 26))
        n0 = len(sc)
        if name == "exfil_sweep":
            sc.append({"name": name, "actors": [pick("Engineering").id], "onset": onset})
        elif name == "disgruntled":
            sc.append({"name": name, "actors": [pick(rng.choice(["Sales", "Product"])).id], "onset": onset})
        elif name == "negligent":
            sc.append({"name": name, "actors": [pick("Engineering").id], "onset": onset})
        elif name == "compromised":
            sc.append({"name": name, "actors": ["external"], "victim": pick("Finance").id, "onset": onset})
        elif name == "collusion":
            sc.append({"name": name, "actors": [pick("Finance").id, pick("Sales").id], "onset": onset})
        elif name == "low_slow":
            sc.append({"name": name, "actors": [pick("Legal").id], "onset": onset})
        elif name == "quiet_exfil":
            sc.append({"name": name, "actors": [pick(rng.choice(["Finance", "Legal", "Product"])).id], "onset": onset})
        elif name == "token_theft":
            sc.append({"name": name, "actors": ["external"], "victim": pick(rng.choice(["Finance", "HR", "Legal"])).id, "onset": onset})
        elif name == "impersonation":
            sc.append({"name": name, "actors": [pick("Engineering").id], "victim": pick("Finance").id, "onset": onset})
        elif name == "decoy_aware_sweep":
            sc.append({"name": name, "actors": [pick(rng.choice(["Engineering", "Product"])).id], "onset": onset})
        elif name == "collusion_quiet":
            sc.append({"name": name, "actors": [pick("Finance").id, pick("Sales").id], "onset": onset})
        elif name == "negligent_repeat":
            sc.append({"name": name, "actors": [pick(rng.choice(["Sales", "Legal", "Finance"])).id], "onset": onset})
        elif name in ("helpdesk_reset", "har_session"):
            priv = [p_ for p_ in people.values() if (p_.it_support or p_.manager) and p_.id not in used]
            v = rng.choice(priv); used.add(v.id)
            sc.append({"name": name, "actors": ["external"], "victim": v.id, "onset": onset})
        elif name == "mfa_fatigue":
            sc.append({"name": name, "actors": ["external"], "victim": pick("Engineering").id, "onset": onset})
        elif name == "dormant_creds":
            v = pick(rng.choice(["Finance", "Product"])); v.leave = (4, days)
            sc.append({"name": name, "actors": ["external"], "victim": v.id, "onset": onset})
        elif name == "oauth_token":
            sc.append({"name": name, "actors": ["external"], "victim": SC.WORKLOAD, "onset": onset})
        elif name == "bribed_support":
            ag = [p_ for p_ in people.values() if p_.support_agent]
            sc.append({"name": name, "actors": [a.id for a in rng.sample(ag, 2)], "onset": onset})
        elif name == "post_termination":
            a = pick(rng.choice(["Finance", "Sales", "Product"])); a.end_day = onset; a.scenario_term = True
            sc.append({"name": name, "actors": [a.id], "onset": onset})
        elif name == "fake_worker":
            a = pick("Engineering"); a.start_day = onset
            sc.append({"name": name, "actors": [a.id], "onset": onset})
        sc[n0]["type"] = name
        sc[n0]["name"] = label
    for s_ in sc:
        for a in s_["actors"]:
            if a in people:
                people[a].it_support = False     # scenario actors are not support staff (keeps roles clean)
    org = Org(people, files, meta, decoys, days, sc, extra_noise)
    org.profile = pf
    org.case_mode, org.case_seed = case_mode, seed
    return org


# ----------------------------------------------------------------------------------------
def _benign_day(rng, org: Org, p: Person, day: int, mood_bad: bool) -> List[Event]:
    if org.case_mode:
        if p.workload:
            return SC.workload_day(org.case_seed, day, Event)
        if p.end_day is not None and day == p.end_day and not p.scenario_term:
            return [Event((day - 1) * 24 + 17.5, p.id, "lifecycle", attrs={"status": "terminated"}, true_actor=p.id)]
        if day < p.start_day or (p.end_day is not None and day > p.end_day) or (p.leave and p.leave[0] <= day <= p.leave[1]):
            return []
    ev = _benign_day_events(rng, org, p, day, mood_bad)
    _tag_sessions(org, p, day, ev)
    return ev


def _tag_sessions(org: Org, p: Person, day: int, ev: List[Event]) -> None:
    """Session id (sid) and request IP (sip) for every event, as an IdP/proxy would log them. A session is
    one login; IT-support sessions in a colleague's account are separate sessions. With extra noise, 5 %
    of remote days include a network handover (VPN reconnect, mobile): the session continues from a new IP
    and the old IP is not used again. Uses its own random stream, so the main simulation is unchanged."""
    sid, sip = None, None
    hrng = random.Random(f"handover-{org.decoys.seed}-{p.id}-{day}")
    handover_at = None
    support_ip = {}
    for e in sorted(ev, key=lambda x: x.t):
        if e.kind == "login":
            if e.account != p.id:                      # support session in a colleague's account
                support_ip[e.account] = e.attrs.get("ip")
                e.attrs = dict(e.attrs, sid=f"s-{e.account}-{day}-h{p.id}", sip=e.attrs.get("ip"))
                continue
            sid, sip = f"s-{p.id}-{day}-{int(e.t * 60)}", e.attrs.get("ip")
            if org.extra_noise and e.attrs.get("ip_type") == "residential" and hrng.random() < 0.05:
                handover_at = e.t + hrng.uniform(1, 5)
        if e.account != p.id:
            e.attrs = dict(e.attrs, sid=f"s-{e.account}-{day}-h{p.id}", sip=support_ip.get(e.account))
            continue
        if handover_at is not None and e.t >= handover_at and e.kind != "login":
            sip = f"92.{hrng.randint(0, 255)}.{hrng.randint(0, 255)}.{hrng.randint(1, 254)}"
            handover_at = None
        if sid is not None:
            e.attrs = dict(e.attrs, sid=sid, sip=sip)


def _benign_day_events(rng, org: Org, p: Person, day: int, mood_bad: bool) -> List[Event]:
    ev: List[Event] = []
    base = (day - 1) * 24
    weekday = (day - 1) % 7 < 5
    if not weekday:
        if p.oncall and rng.random() < 0.3:
            h = base + rng.uniform(9, 22)
            ev.append(Event(h, p.id, "login", attrs={"device": p.devices[0], "ip": p.home_ip, "ip_type": "residential"}, true_actor=p.id))
            for _ in range(rng.randint(2, 6)):
                f = rng.choice(org.files[f"//fs/{p.dept}/general"])
                ev.append(Event(h + rng.uniform(0, 1.5), p.id, "read", f, p.dept, False, org.file_meta[f]["bytes"], true_actor=p.id))
        return ev
    start = base + max(6.0, rng.gauss(p.start_h, 0.5))
    pf = org.profile
    remote = rng.random() < pf["remote"]
    travel = rng.random() < pf["travel"]
    if travel:
        ip, ip_type = _ip(rng, "foreign"), "foreign"
    elif remote:
        ip, ip_type = p.home_ip, "residential"
    else:
        ip, ip_type = _ip(rng, "corporate"), "corporate"
    if rng.random() < pf["new_laptop"]:
        p.devices.append(f"dev-{p.id}-{len(p.devices)}")       # new laptop (benign)
    dev = p.devices[-1]
    ev.append(Event(start, p.id, "login", attrs={"device": dev, "ip": ip, "ip_type": ip_type}, true_actor=p.id))
    end = start + rng.gauss(8.7, 0.6)
    if org.case_mode:
        ev += SC.benign(org.case_seed, org, p, day, start, end, ip, dev, Event)
    # reads in own department
    n_reads = rng.randint(12, 30)
    for _ in range(n_reads):
        sens = rng.random() < (pf["sens_high"] if p.dept in ("Finance", "HR", "Legal") else pf["sens_low"])
        loc = f"//fs/{p.dept}/{'restricted' if sens else 'general'}"
        f = rng.choice(org.files[loc])
        if org.file_meta[f].get("decoy"):
            # legitimate users only very rarely open a decoy (curiosity / misclick)
            if rng.random() > 0.08:
                f = org.files[loc][0]
        ev.append(Event(rng.uniform(start, end), p.id, "read", f, p.dept, org.file_meta[f]["sensitive"],
                        org.file_meta[f]["bytes"], attrs={"decoy_id": f} if org.file_meta[f].get("decoy") else {}, true_actor=p.id))
    # legitimate cross-department reads (shared general areas)
    for _ in range(rng.choices([0, 1, 2, 3], weights=[50, 30, 15, 5])[0]):
        d = rng.choice([x for x in DEPTS if x != p.dept])
        f = rng.choice(org.files[f"//fs/{d}/general"])
        ev.append(Event(rng.uniform(start, end), p.id, "read", f, d, False, org.file_meta[f]["bytes"], true_actor=p.id))
    # e-mail
    for _ in range(rng.randint(0, 2)):
        if p.dept == "Finance" and day % 30 in (28, 29, 0) and rng.random() < 0.6:
            dom, att = PARTNER_DOMAINS[0], True                     # month-end audit export
        else:
            dom, att = rng.choice(PARTNER_DOMAINS), rng.random() < 0.3
        f = rng.choice(org.files[f"//fs/{p.dept}/general"])
        ev.append(Event(rng.uniform(start, end), p.id, "email", f if att else None, p.dept, False,
                        org.file_meta[f]["bytes"] if att else 0, attrs={"to": f"contact@{dom}", "external": True, "attachment": att}, true_actor=p.id))
    if rng.random() < pf["private_fwd"]:   # rare: forwards something to own private address (benign but noisy)
        f = rng.choice(org.files[f"//fs/{p.dept}/general"])
        ev.append(Event(rng.uniform(start, end), p.id, "email", f, p.dept, False, org.file_meta[f]["bytes"],
                        attrs={"to": f"{p.id}@{rng.choice(PERSONAL_DOMAINS)}", "external": True, "attachment": True}, true_actor=p.id))
    # engineering repo clones
    if p.dept == "Engineering":
        n = rng.choices([0, 1, 2, 3, 15], weights=[30, 35, 20, 13, 2])[0]
        if n:
            ev.append(Event(rng.uniform(start, end), p.id, "clone", "repos", p.dept, False, n * 40_000_000, attrs={"count": n}, true_actor=p.id))
    # chat sentiment
    for _ in range(rng.randint(2, 8)):
        neg = rng.random() < (0.35 if mood_bad else 0.04)
        ev.append(Event(rng.uniform(start, end), p.id, "msg", attrs={"sentiment": "negative" if neg else "neutral"}, true_actor=p.id))
    # on-call night work
    if p.oncall and rng.random() < 0.12:
        h = base + rng.uniform(21, 26)
        ev.append(Event(h, p.id, "login", attrs={"device": dev, "ip": p.home_ip, "ip_type": "residential"}, true_actor=p.id))
        for _ in range(rng.randint(2, 5)):
            f = rng.choice(org.files[f"//fs/{p.dept}/general"])
            ev.append(Event(h + rng.uniform(0, 1.5), p.id, "read", f, p.dept, False, org.file_meta[f]["bytes"], true_actor=p.id))
    if org.extra_noise:
        if p.usb_user and rng.random() < 0.2:          # presentation / trade-fair material on a stick
            f = rng.choice(org.files[f"//fs/{p.dept}/general"])
            ev.append(Event(rng.uniform(start, end), p.id, "egress_usb", f, p.dept, False, rng.randint(20, 200) * 1_000_000,
                            attrs={"removable": True}, true_actor=p.id))
        if p.cloud_sync and rng.random() < 0.15:
            f = rng.choice(org.files[f"//fs/{p.dept}/general"])
            ev.append(Event(rng.uniform(start, end), p.id, "egress_cloud", f, p.dept, False, rng.randint(5, 60) * 1_000_000,
                            attrs={"dest": "~/Dropbox/personal"}, true_actor=p.id))
        if p.it_support and rng.random() < 0.6:        # helps a colleague: logs into their account from own device
            v = rng.choice([q for q in org.people.values() if q.id != p.id])
            h = rng.uniform(start, end - 1)
            ev.append(Event(h, v.id, "login", attrs={"device": p.devices[0], "ip": _ip(rng, "corporate"), "ip_type": "corporate"},
                            true_actor=p.id))
            for _ in range(rng.randint(1, 4)):
                f = rng.choice(org.files[f"//fs/{v.dept}/general"])
                ev.append(Event(h + rng.uniform(0, 0.8), v.id, "read", f, v.dept, False, org.file_meta[f]["bytes"],
                                attrs={"device": p.devices[0]}, true_actor=p.id))
    # managers grant access within their department now and then
    if p.manager and rng.random() < 0.05:
        other = rng.choice([q for q in org.people.values() if q.dept == p.dept and q.id != p.id] or [p])
        ev.append(Event(rng.uniform(start, end), p.id, "grant", f"//fs/{p.dept}/restricted", p.dept, True,
                        attrs={"grantee": other.id, "ticket": f"REQ-{rng.randint(1000, 9999)}"}, true_actor=p.id))
    return ev


def _sweep(rng, org, t, account, true_actor, sc, locs, k, extra=None):
    ev = []
    for loc in locs:
        for f in rng.sample(org.files[loc], min(k, len(org.files[loc]))):
            m = org.file_meta[f]
            at = dict(extra or {})
            if m.get("decoy"):
                at["decoy_id"] = f
            ev.append(Event(t + rng.uniform(0, 2), account, "read", f, m["dept"], m["sensitive"], m["bytes"],
                            attrs=at, true_actor=true_actor, scenario=sc, malicious=True))
    return ev


def _scenario_events(rng, org: Org, s: dict) -> List[Event]:
    name, onset = s.get("type", s["name"]), s["onset"]
    label = s["name"]
    ev: List[Event] = []
    P = org.people
    if name in ADAPTIVE_SCENARIOS:
        return _adaptive_events(rng, org, s, name, label, onset)
    if name in SC.CASE_SCENARIOS:
        return SC.scenario(rng, org, s, name, label, onset, Event, _ip)
    if name == "exfil_sweep":
        a = P[s["actors"][0]]
        for k, d in enumerate(range(onset, org.days + 1, 6)):
            t = (d - 1) * 24 + rng.uniform(21, 23.5)
            ev.append(Event(t, a.id, "login", attrs={"device": a.devices[0], "ip": a.home_ip, "ip_type": "residential"}, true_actor=a.id, scenario=label, malicious=True))
            locs = [f"//fs/{a.dept}/restricted", f"//fs/{rng.choice(['Product', 'Legal', 'Finance'])}/restricted"]
            ev += _sweep(rng, org, t, a.id, a.id, label, locs, rng.randint(15, 30))
            vol = rng.randint(300, 800) * 1_000_000
            ev.append(Event(t + 2.5, a.id, "copy", "bulk", a.dept, True, vol, attrs={"files": 40}, true_actor=a.id, scenario=label, malicious=True))
            ev.append(Event(t + 26, a.id, "archive", "bulk", a.dept, True, vol // 2, true_actor=a.id, scenario=label, malicious=True))
            ev.append(Event(t + 50, a.id, "egress_cloud", "bulk", a.dept, True, vol // 2, attrs={"dest": "~/Dropbox/personal"},
                            true_actor=a.id, scenario=label, malicious=True))
            if k == 1:   # finds a credential in the wiki and tries it
                cred = next(d for d in org.decoys.decoys.values() if d.cls == CREDENTIAL)
                ev.append(Event(t + 3, a.id, "login", attrs={"device": a.devices[0], "ip": a.home_ip, "ip_type": "residential",
                                                              "decoy_id": cred.id, "credential": True}, true_actor=a.id, scenario=label, malicious=True))
    elif name == "disgruntled":
        a = P[s["actors"][0]]
        for d in range(onset, org.days + 1):
            if (d - 1) % 7 >= 5:
                continue
            base = (d - 1) * 24
            for _ in range(rng.randint(1, 3)):
                ev.append(Event(base + rng.uniform(9, 17), a.id, "msg", attrs={"sentiment": "negative"}, true_actor=a.id, scenario=label, malicious=False))
            if rng.random() < 0.5:
                h = base + rng.choice([rng.uniform(5, 6.5), rng.uniform(20, 23)])
                ev.append(Event(h, a.id, "login", attrs={"device": a.devices[0], "ip": a.home_ip, "ip_type": "residential"}, true_actor=a.id, scenario=label, malicious=True))
                tgt = rng.choice(["HR", "Finance"])
                ev += _sweep(rng, org, h, a.id, a.id, label, [f"//fs/{tgt}/restricted"], rng.randint(2, 6))
        d_leak = min(onset + 15, org.days)
        f = rng.choice([x for x in org.files["//fs/HR/restricted"] if not org.file_meta[x].get("decoy")])
        ev.append(Event((d_leak - 1) * 24 + 22, a.id, "email", f, "HR", True, 4_000_000,
                        attrs={"to": f"{a.id}.priv@{rng.choice(PERSONAL_DOMAINS)}", "external": True, "attachment": True},
                        true_actor=a.id, scenario=label, malicious=True))
    elif name == "negligent":
        a = P[s["actors"][0]]
        ev.append(Event((onset - 1) * 24 + 14, a.id, "commit", "repos", a.dept, False, 0, attrs={"secret": True},
                        true_actor=a.id, scenario=label, malicious=True))
        f = rng.choice(org.files[f"//fs/{a.dept}/restricted"][:60])
        ev.append(Event((onset + 6) * 24 + 11, a.id, "email", f, a.dept, True, 2_000_000,
                        attrs={"to": "j.smith@clien.example", "external": True, "attachment": True},
                        true_actor=a.id, scenario=label, malicious=True))
    elif name == "compromised":
        v = P[s["victim"]]
        t0 = (onset - 1) * 24 + rng.uniform(10, 15)
        ev.append(Event(t0, "ext-caller", "call", attrs={"target": v.id, "spoofed_caller": "IT-Helpdesk"}, true_actor="external", scenario=label, malicious=True))
        dev, ip = "dev-unknown-x9", _ip(rng, "foreign")
        t1 = t0 + rng.uniform(0.2, 0.6)
        ev.append(Event(t1, v.id, "login", attrs={"device": dev, "ip": ip, "ip_type": "foreign"}, true_actor="external", scenario=label, malicious=True))
        locs = [f"//fs/{d}/restricted" for d in ("Finance", "HR", "Legal", "Engineering")]
        ctx = {"device": dev, "ip": ip, "ip_type": "foreign"}
        ev += _sweep(rng, org, t1, v.id, "external", label, locs, rng.randint(10, 20), extra=ctx)
        cred = next(d for d in org.decoys.decoys.values() if d.cls == CREDENTIAL)
        adm = next(d for d in org.decoys.decoys.values() if d.cls == DECOY_ACCOUNT)
        ev.append(Event(t1 + 2.2, v.id, "login", attrs={"device": dev, "ip": ip, "ip_type": "foreign", "decoy_id": cred.id, "credential": True},
                        true_actor="external", scenario=label, malicious=True))
        ev.append(Event(t1 + 2.5, v.id, "login", attrs={"device": dev, "ip": ip, "ip_type": "foreign", "decoy_id": adm.id, "credential": True},
                        true_actor="external", scenario=label, malicious=True))
        for k in range(3):
            ev.append(Event(t1 + 3 + k * 20, v.id, "copy", "bulk", "Finance", True, 400_000_000, attrs=dict(ctx, files=60), true_actor="external", scenario=label, malicious=True))
            ev.append(Event(t1 + 4 + k * 20, v.id, "egress_cloud", "bulk", "Finance", True, 300_000_000, attrs=dict(ctx, dest="mega.nz"), true_actor="external", scenario=label, malicious=True))
    elif name == "collusion":
        a, b = P[s["actors"][0]], P[s["actors"][1]]
        t0 = (onset - 1) * 24 + 15
        ev.append(Event(t0, a.id, "grant", f"//fs/{a.dept}/restricted", a.dept, True, attrs={"grantee": b.id}, true_actor=a.id, scenario=label, malicious=True))
        for k, d in enumerate(range(onset + 1, min(org.days, onset + 20), 3)):
            t = (d - 1) * 24 + rng.uniform(16, 18)
            ev += _sweep(rng, org, t, b.id, b.id, label, [f"//fs/{a.dept}/restricted"], rng.randint(5, 12))
            ev.append(Event(t + 1, b.id, "egress_usb", "bulk", a.dept, True, rng.randint(80, 200) * 1_000_000, attrs={"removable": True},
                            true_actor=b.id, scenario=label, malicious=True))
            if k % 2 == 0:  # a forwards an additional file internally
                f = rng.choice(org.files[f"//fs/{a.dept}/restricted"][:60])
                ev.append(Event(t - 2, a.id, "email", f, a.dept, True, org.file_meta[f]["bytes"],
                                attrs={"to": f"{b.id}@corp", "external": False, "attachment": True}, true_actor=a.id, scenario=label, malicious=True))
    elif name == "low_slow":
        a = P[s["actors"][0]]
        for d in range(onset, org.days + 1, 2):
            if (d - 1) % 7 >= 5:
                continue
            f = rng.choice(org.files[f"//fs/{a.dept}/restricted"][:60])
            ev.append(Event((d - 1) * 24 + rng.uniform(11, 16), a.id, "email", f, a.dept, True, rng.randint(5, 20) * 1_000_000,
                            attrs={"to": f"{a.id}@{rng.choice(PERSONAL_DOMAINS)}", "external": True, "attachment": True},
                            true_actor=a.id, scenario=label, malicious=True))
    return ev



def _workdays(org: Org, start: int, step: int = 1):
    d = start
    while d <= org.days:
        if (d - 1) % 7 < 5:
            yield d
        d += step


def _restricted(org: Org, dept: str) -> List[str]:
    return [f for f in org.files[f"//fs/{dept}/restricted"] if not org.file_meta[f].get("decoy")]


def _adaptive_events(rng, org: Org, s: dict, name: str, label: str, onset: int) -> List[Event]:
    """Red-team scenarios written against the v0.1 signal set (see module docstring)."""
    ev: List[Event] = []
    P = org.people

    def E(t, acct, kind, actor, malicious=True, **kw):
        return Event(t, acct, kind, true_actor=actor, scenario=label, malicious=malicious, **kw)

    if name == "quiet_exfil":
        a = P[s["actors"][0]]
        # warm-up: a harmless mail without attachment makes the lookalike domain "known"
        ev.append(E((max(onset - 3, 15) - 1) * 24 + 10.5, a.id, "email", a.id, False,
                    attrs={"to": f"ap@{LOOKALIKE_DOMAIN}", "external": True, "attachment": False}))
        for d in list(_workdays(org, onset))[::2]:
            t = (d - 1) * 24 + rng.uniform(10, 16)
            f = rng.choice(_restricted(org, a.dept))
            ev.append(E(t - 0.3, a.id, "read", a.id, resource=f, rdept=a.dept, sensitive=True, nbytes=org.file_meta[f]["bytes"]))
            ev.append(E(t, a.id, "email", a.id, resource=f, rdept=a.dept, sensitive=True, nbytes=rng.randint(3, 12) * 1_000_000,
                        attrs={"to": f"ap@{LOOKALIKE_DOMAIN}", "external": True, "attachment": True}))
    elif name == "token_theft":
        v = P[s["victim"]]
        dev, ip = v.devices[-1], _ip(rng, "residential")
        ctx = {"device": dev, "ip": ip, "ip_type": "residential"}
        for k in range(3):
            t = (onset - 1 + k) * 24 + rng.uniform(10, 15)
            # infostealer exfiltrates the victim's live session cookie; the attacker replays it (same session id)
            ctx = dict(ctx, sid=f"stolen:{v.id}:{onset - 1 + k + 1}", sip=ip)
            ev.append(E(t, v.id, "login", "external", attrs=dict(ctx)))
            for f in rng.sample(_restricted(org, v.dept), rng.randint(8, 15)):
                ev.append(E(t + rng.uniform(0, 1), v.id, "read", "external", resource=f, rdept=v.dept, sensitive=True,
                            nbytes=org.file_meta[f]["bytes"], attrs=dict(ctx)))
            ev.append(E(t + 1.5, v.id, "egress_cloud", "external", resource="bulk", rdept=v.dept, sensitive=True,
                        nbytes=rng.randint(150, 250) * 1_000_000, attrs=dict(ctx, dest="sharefile-transfer.example")))
    elif name == "impersonation":
        a, v = P[s["actors"][0]], P[s["victim"]]
        for k in range(4):
            d = onset + k * rng.randint(3, 4)
            if d > org.days:
                break
            t = (d - 1) * 24 + rng.uniform(18.5, 20.5)
            ctx = {"device": a.devices[0], "ip": _ip(rng, "corporate"), "ip_type": "corporate"}
            ev.append(E(t, v.id, "login", a.id, attrs=dict(ctx)))
            files = rng.sample(_restricted(org, v.dept), rng.randint(5, 10))
            for f in files:
                ev.append(E(t + rng.uniform(0, 0.7), v.id, "read", a.id, resource=f, rdept=v.dept, sensitive=True,
                            nbytes=org.file_meta[f]["bytes"], attrs=dict(ctx)))
            ev.append(E(t + 0.8, v.id, "email", a.id, resource=files[0], rdept=v.dept, sensitive=True,
                        nbytes=rng.randint(3, 8) * 1_000_000,
                        attrs=dict(ctx, to=f"{a.id}.drop@protonmail.com", external=True, attachment=True)))
    elif name == "decoy_aware_sweep":
        a = P[s["actors"][0]]
        for d in list(_workdays(org, onset))[::5]:
            t = (d - 1) * 24 + rng.uniform(10, 15)
            for f in rng.sample(_restricted(org, a.dept), rng.randint(10, 18)):
                ev.append(E(t + rng.uniform(0, 1.5), a.id, "read", a.id, resource=f, rdept=a.dept, sensitive=True,
                            nbytes=org.file_meta[f]["bytes"]))
            ev.append(E(t + 2, a.id, "egress_usb", a.id, resource="bulk", rdept=a.dept, sensitive=True,
                        nbytes=rng.randint(80, 200) * 1_000_000, attrs={"removable": True}))
    elif name == "collusion_quiet":
        a, b = P[s["actors"][0]], P[s["actors"][1]]
        for d in list(_workdays(org, onset))[::3]:
            t = (d - 1) * 24 + rng.uniform(10, 14)
            f = rng.choice(_restricted(org, a.dept))
            ev.append(E(t, a.id, "email", a.id, resource=f, rdept=a.dept, sensitive=True, nbytes=org.file_meta[f]["bytes"],
                        attrs={"to": f"{b.id}@corp", "external": False, "attachment": True}))
            ev.append(E(t + rng.uniform(1, 3), b.id, "email", b.id, resource=f, rdept=a.dept, sensitive=True,
                        nbytes=rng.randint(2, 10) * 1_000_000,
                        attrs={"to": f"{b.id}.home@{rng.choice(PERSONAL_DOMAINS)}", "external": True, "attachment": True}))
    elif name == "negligent_repeat":
        a = P[s["actors"][0]]
        typos = ["j.smith@clien.example", "orders@suplier.example", "desk@bank-partnr.example"]
        for k, to in enumerate(typos):
            d = min(onset + 7 * k, org.days)
            f = rng.choice(_restricted(org, a.dept))
            ev.append(E((d - 1) * 24 + rng.uniform(10, 16), a.id, "email", a.id, resource=f, rdept=a.dept, sensitive=True,
                        nbytes=rng.randint(1, 4) * 1_000_000, attrs={"to": to, "external": True, "attachment": True}))
        d = min(onset + 10, org.days)
        ev.append(E((d - 1) * 24 + 9, a.id, "egress_usb", a.id, resource="client-deck", rdept=a.dept, sensitive=True,
                    nbytes=50_000_000, attrs={"removable": True}))
    return ev

def generate(seed: int, n_people: int = 150, days: int = 60, scenario_set: str = "standard",
             instances: int = 1, extra_noise: Optional[bool] = None, profile: str = "office") -> tuple[Org, List[Event]]:
    org = build_org(seed, n_people, days, scenario_set=scenario_set, instances=instances, extra_noise=extra_noise,
                    profile=profile)
    rng = random.Random(seed * 1009 + 1)
    bad_weeks = {p: set() for p in org.people}
    for p in org.people:
        if rng.random() < 0.08:
            w = rng.randint(0, days // 7)
            bad_weeks[p] = set(range(w * 7 + 1, w * 7 + 8))
    events: List[Event] = []
    for day in range(1, days + 1):
        for p in org.people.values():
            events += _benign_day(rng, org, p, day, day in bad_weeks[p.id])
    for s in org.scenarios:
        events += _scenario_events(rng, org, s)
    events.sort(key=lambda e: e.t)
    _resolve_stolen_sessions(events)
    return org, events


def _resolve_stolen_sessions(events: List[Event]) -> None:
    """A stolen cookie carries the victim's own session id of that day (if the victim worked that day)."""
    first_sid = {}
    for e in events:
        sid = e.attrs.get("sid")
        if sid and sid.startswith("s-") and e.kind == "login" and e.true_actor == e.account:
            first_sid.setdefault((e.account, e.day), sid)
    for e in events:
        sid = e.attrs.get("sid")
        if sid and sid.startswith("stolen:"):
            _, acct, day = sid.split(":")
            e.attrs = dict(e.attrs, sid=first_sid.get((acct, int(day)), f"s-{acct}-{day}-replayed"))
