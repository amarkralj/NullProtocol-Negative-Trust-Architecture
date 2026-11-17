# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""CERT Insider Threat Test Dataset r4.2 (Carnegie Mellon SEI / ExactData) as a shadow-mode replay.

The dataset is not redistributed (licence: research use, no redistribution); fetch it with
`scripts/fetch_cert.sh`. r4.2 has 1,000 users over 17 months and 70 labelled insider incidents
(30 x scenario 1, 30 x scenario 2, 10 x scenario 3; see answers/scenarios.txt).

Replay mode: the logs already happened, so nothing can be blocked. Every event is observed as
"allowed" and we measure what *would* have happened: when the responsible user would have reached
containment (L3) and a case (L4), and how much of each incident came after that point.

Mapping from CERT logs to engine events (all generic; no field encodes the label):

    logon.csv  Logon             -> login  (device = PC; one corporate network, no IP data)
    file.csv   copy to removable -> egress_usb (1 file; size and classification unknown)
    email.csv  external recipient with attachments -> email external attachment; a recipient
               address that the same user has *sent from* (their own non-work account) is
               classed as personal webmail, other external domains by name
    http.csv   only two secure-web-gateway style categories are used: anonymous disclosure /
               leak sites and spyware/keylogger vendors. Job-search sites are deliberately not
               used (privacy principle: whether an employee looks for another job is not a security
               signal); this costs detection of scenario 2, which is reported.
    LDAP       users, departments, role ITAdmin = IT support (role registry)
    psychometric.csv is not used (personality scores are not legitimate monitoring input).

Known differences from the simulator: there are no decoys, no file classification, no IPs, and
PCs are shared lab machines for some users, so device-owner attribution (v0.2) is disabled here.
"""
from __future__ import annotations

import csv
import pathlib
import statistics
import time as _time
from collections import Counter, defaultdict
from dataclasses import dataclass
from typing import Optional, Dict, List

from . import policy as P
from .engine import Engine, EngineConfig
from .sim import Event

LEAK_SITES = ("wikileaks.",)
SPYWARE = ("keylog", "spectorsoft", "refog", "webwatcher", "spyware", "keystroke")
EPOCH_DAYS = None


def _t(s: str) -> float:
    """'MM/DD/YYYY HH:MM:SS' -> hours since 2010-01-01 00:00."""
    import datetime as dt
    m, d, y = int(s[0:2]), int(s[3:5]), int(s[6:10])
    days = (dt.date(y, m, d) - dt.date(2010, 1, 1)).days
    return days * 24 + int(s[11:13]) + int(s[14:16]) / 60 + int(s[17:19]) / 3600


@dataclass
class CertData:
    users: Dict[str, dict]
    events: List[Event]
    insiders: List[dict]
    personal_addrs: Dict[str, set]


def load(root="data/cert", release="r4.2", progress=True) -> CertData:
    root = pathlib.Path(root)
    base = root / release
    t0 = _time.time()

    def log(msg):
        if progress:
            print(f"[{_time.time()-t0:5.0f}s] {msg}", flush=True)

    # users from LDAP (union over months; last known department)
    users: Dict[str, dict] = {}
    for f in sorted((base / "LDAP").glob("*.csv")):
        with open(f, newline="") as fh:
            for r in csv.DictReader(fh):
                users[r["user_id"]] = {"dept": f'{r["functional_unit"]}/{r["department"]}', "role": r["role"],
                                       "email": r["email"].lower(), "supervisor": r["supervisor"]}
    log(f"LDAP: {len(users)} users")

    ev: List[Event] = []
    with open(base / "logon.csv", newline="") as fh:
        rd = csv.reader(fh); next(rd)
        for _id, date, user, pc, act in rd:
            if act == "Logon" and user in users:
                ev.append(Event(_t(date), user, "login", attrs={"device": pc, "ip": "corp", "ip_type": "corporate"}))
    log(f"logon: {len(ev)}")
    n = len(ev)
    with open(base / "file.csv", newline="") as fh:
        rd = csv.reader(fh)
        hdr = next(rd)
        rem = hdr.index("to_removable_media") if "to_removable_media" in hdr else None   # r5+: all file activity
        for row in rd:
            if rem is not None and (len(row) <= rem or row[rem] != "True"):
                continue
            if row[2] in users:
                ev.append(Event(_t(row[1]), row[2], "egress_usb", resource=row[4], nbytes=1_000_000,
                                attrs={"removable": True, "device": row[3]}))
    log(f"file copies to removable media: {len(ev)-n}")

    # e-mail: first pass learns each user's own non-work addresses (addresses they send from)
    personal: Dict[str, set] = defaultdict(set)
    ext_att = []
    n = len(ev)
    with open(base / "email.csv", newline="", errors="replace") as fh:
        hdr = fh.readline().strip().split(",")
        ci = {k: i for i, k in enumerate(hdr)}
        ncol = ci["content"] if "content" in ci else len(hdr)
        for line in fh:
            parts = line.split(",", ncol)
            if len(parts) < ncol:
                continue
            date, user, pc = parts[ci["date"]], parts[ci["user"]], parts[ci["pc"]]
            to, cc, bcc, frm = parts[ci["to"]], parts[ci["cc"]], parts[ci["bcc"]], parts[ci["from"]]
            att = parts[ci["attachments"]].strip()
            if "activity" in ci and parts[ci["activity"]] not in ("Send", ""):
                continue                                       # r5+: only sent messages, not views
            if not att.isdigit():                              # r5+: attachment file names separated by ;
                att = str(len([a for a in att.split(";") if a.strip()]))
            if user not in users:
                continue
            frm = frm.lower()
            if not frm.endswith("@dtaa.com"):
                personal[user].add(frm)
            if att != "0":
                rcpts = [x.lower() for x in (to + ";" + cc + ";" + bcc).split(";") if x]
                ext = [x for x in rcpts if not x.endswith("@dtaa.com")]
                if ext:
                    ext_att.append((_t(date), user, pc, ext, int(att)))
    for t, user, pc, ext, natt in ext_att:
        own = [x for x in ext if x in personal[user]]
        to = f"{user.lower()}.home@gmail.com" if own else ext[0]     # own non-work account -> personal webmail class
        ev.append(Event(t, user, "email", attrs={"to": to, "external": True, "attachment": True, "device": pc,
                                                  "n_attachments": natt, "own_address": bool(own)}))
    log(f"external e-mails with attachments: {len(ev)-n}")

    n = len(ev)
    fp = root / "derived" / ("http_filtered.csv" if release == "r4.2" else f"{release}/http_filtered.csv")
    with open(fp, newline="") as fh:
        for line in fh:
            date, user, pc, url = line.rstrip("\n").split(",", 3)
            u = url.lower()
            cat = "leak_site" if any(x in u for x in LEAK_SITES) else ("spyware" if any(x in u for x in SPYWARE) else None)
            if cat and user in users:
                ev.append(Event(_t(date), user, "web", resource=url, attrs={"category": cat, "device": pc}))
    log(f"web (leak site / spyware categories): {len(ev)-n}")
    n = len(ev)
    fp = root / "derived" / release / "http_uploads.csv"        # r5+: the web log marks uploads ("WWW Upload")
    if fp.exists():
        from urllib.parse import urlparse
        with open(fp, newline="") as fh:
            for line in fh:
                date, user, pc, url = line.rstrip("\n").split(",", 3)
                if user in users:
                    host = urlparse(url if "//" in url else "http://" + url).netloc.lower()
                    ev.append(Event(_t(date), user, "egress_cloud", resource=url, nbytes=1_000_000,
                                    attrs={"dest": host, "device": pc}))
        log(f"web uploads: {len(ev)-n}")

    ev.sort(key=lambda e: e.t)
    ins = []
    with open(root / "answers" / "insiders.csv", newline="") as fh:
        for r in csv.DictReader(fh):
            if r["dataset"] == release[1:]:
                def ts(x):
                    try:
                        return _t(_norm(x))
                    except ValueError:                         # malformed date in the answer key (r6.2 scenario 4)
                        return float("nan")
                ins.append({"scenario": int(r["scenario"]), "user": r["user"], "file": r["details"],
                            "start": ts(r["start"]), "end": ts(r["end"])})
    # victims of scenario 3 (account used by the insider): accounts other than the insider in the incident file
    for i in ins:
        f = root / "answers" / f"{release}-{i['scenario']}" / i["file"]
        if not f.exists():                                     # r6.x: one file per scenario, quoted CSV
            f = root / "answers" / i["file"]
        accts = Counter()
        times = []
        if f.exists():
            with open(f, newline="", errors="replace") as fh:
                for p in csv.reader(fh):
                    if len(p) > 3:
                        accts[p[3]] += 1
                        times.append(_t(_norm(p[2])))
        i["accounts"] = [a for a in accts if a != i["user"]]
        i["event_times"] = sorted(times)
        if times and not (min(times) - 48 <= i["start"] <= max(times) + 48):     # also true for NaN
            i["start"], i["end"] = min(times), max(times)     # malformed date in the answer key
    log(f"insider incidents: {len(ins)}; total events {len(ev)}")
    return CertData(users, ev, ins, personal)


def notices(root="data/cert", release="r4.2", days_before: int = 30) -> List[Event]:
    """HR notice periods from the monthly LDAP snapshots. A user missing from the final snapshot left during their
    last listed month; the resignation is assumed to be recorded `days_before` days before that month starts (an
    assumption: CERT has no resignation dates). Returns lifecycle events with status "notice"."""
    import datetime as dt
    files = sorted((pathlib.Path(root) / release / "LDAP").glob("*.csv"))
    last = {}
    for f in files:
        with open(f, newline="") as fh:
            for r in csv.DictReader(fh):
                last[r["user_id"]] = f.stem[:7]
    final = files[-1].stem[:7]
    out = []
    for u, m in last.items():
        if m != final:
            y, mo = map(int, m.split("-"))
            t = ((dt.date(y, mo, 1) - dt.date(2010, 1, 1)).days - days_before) * 24
            out.append(Event(t, u, "lifecycle", attrs={"status": "notice"}))
    return out


def with_notices(events: List[Event], extra: List[Event]) -> List[Event]:
    import heapq
    return list(heapq.merge(events, sorted(extra, key=lambda e: e.t), key=lambda e: e.t))


def _norm(s: str) -> str:
    """Normalise 'M/D/YYYY H:MM:SS' to 'MM/DD/YYYY HH:MM:SS'."""
    d, tm = s.strip().split(" ")
    m, dd, y = d.split("/")
    h, mi, se = tm.split(":")
    return f"{int(m):02d}/{int(dd):02d}/{y} {int(h):02d}:{mi}:{se}"


def replay(data: CertData, cfg: EngineConfig, review_delay_h: float = 8.0, partners=(), events=None) -> dict:
    """Shadow-mode replay with human review of L4 cases (reviewer knows ground truth)."""
    users = data.users
    owners = {u: u for u in users}
    depts = {u: users[u]["dept"] for u in users}
    support = [u for u in users if users[u]["role"] == "ITAdmin"]
    eng = Engine(cfg, owners, depts, None, partner_domains=partners, support_staff=support)
    insider_users = {i["user"] for i in data.insiders}
    day = int(data.events[0].t // 24) + 1
    first_case: Dict[str, float] = {}
    first_l3: Dict[str, float] = {}
    for e in (events if events is not None else data.events):
        while e.t >= day * 24:
            eng.end_of_day(day)
            day += 1
        for c in eng.due_cases(e.t):
            subj = c["subject"].replace("acct:", "")
            eng.review(c["subject"], subj in insider_users, c["due"])
        eng.observe(e, True)
        for s in (e.account, "acct:" + e.account):
            lvl = eng.level.get(s)
            if lvl is not None:
                if lvl >= P.Level.L3_READ_ONLY and s not in first_l3:
                    first_l3[s] = e.t
                if lvl >= P.Level.L4_ISOLATE and s not in first_case:
                    first_case[s] = e.t
    cases = list(eng.case_log) + list(eng.cases.values())
    return {"first_case": first_case, "first_l3": first_l3, "cases": cases, "ledger_ok": eng.ledger.verify()[0],
            "ledger_entries": len(eng.ledger.entries)}


def score(data: CertData, rep: dict, name: str) -> dict:
    """Incident-level and user-level metrics.

    detected      the insider (person or their account) reached L4 (a case) no later than 7 days
                  after the incident ended
    early         ... before the incident ended
    prevented     share of the incident's logged events that happened after the insider reached L3
                  (what containment would have stopped; an upper bound, since the replay cannot
                  model how the insider would have reacted)
    false cases   benign users (never an insider) for whom a case was opened, per 1,000 users
    """
    insider_users = {i["user"] for i in data.insiders}
    per_sc = defaultdict(list)
    for i in data.insiders:
        u = i["user"]
        tc = min([rep["first_case"][s] for s in (u, "acct:" + u) if s in rep["first_case"] and rep["first_case"][s] >= i["start"] - 24 * 30]
                 or [None], key=lambda x: x if x is not None else 1e18)
        t3 = min([rep["first_l3"][s] for s in (u, "acct:" + u) if s in rep["first_l3"] and rep["first_l3"][s] >= i["start"] - 24 * 30]
                 or [None], key=lambda x: x if x is not None else 1e18)
        det = tc is not None and tc <= i["end"] + 24 * 7
        times = i["event_times"] or [i["start"], i["end"]]
        prevented = (sum(1 for t in times if t3 is not None and t > t3) / len(times)) if times else 0.0
        victims = i.get("accounts", [])
        victim_blamed = any(v in rep["first_case"] and v not in insider_users and rep["first_case"][v] >= i["start"] - 24
                            for v in victims)
        per_sc[i["scenario"]].append({"user": u, "detected": det, "early": tc is not None and tc <= i["end"],
                                      "hours_to_case": (tc - i["start"]) if det else None,
                                      "prevented": prevented, "victim_blamed": victim_blamed if victims else None})
    benign = [u for u in data.users if u not in insider_users]
    false_case_users = {c["subject"].replace("acct:", "") for c in rep["cases"]} - insider_users
    false_l3 = {s.replace("acct:", "") for s in rep["first_l3"]} - insider_users
    out = {"name": name, "incidents": sum(len(v) for v in per_sc.values()),
           "users": len(data.users), "benign_users": len(benign),
           "false_case_users": len(false_case_users), "false_case_users_per_1000": round(1000 * len(false_case_users) / len(benign), 1),
           "false_l3_users_per_1000": round(1000 * len(false_l3) / len(benign), 1),
           "cases_total": len(rep["cases"]), "ledger_ok": rep["ledger_ok"]}
    allx = [x for v in per_sc.values() for x in v]
    out["detected_pct"] = round(100 * statistics.mean(x["detected"] for x in allx), 1)
    out["detected_before_end_pct"] = round(100 * statistics.mean(x["early"] for x in allx), 1)
    out["prevented_pct"] = round(100 * statistics.mean(x["prevented"] for x in allx), 1)
    for sc, xs in sorted(per_sc.items()):
        out[f"s{sc}:n"] = len(xs)
        out[f"s{sc}:detected_pct"] = round(100 * statistics.mean(x["detected"] for x in xs), 1)
        out[f"s{sc}:prevented_pct"] = round(100 * statistics.mean(x["prevented"] for x in xs), 1)
        h = [x["hours_to_case"] for x in xs if x["hours_to_case"] is not None]
        out[f"s{sc}:median_hours_to_case"] = round(statistics.median(h), 1) if h else None
        vb = [x["victim_blamed"] for x in xs if x["victim_blamed"] is not None]
        if vb:
            out[f"s{sc}:victim_blamed_pct"] = round(100 * statistics.mean(vb), 1)
    tp_cases = sum(1 for c in rep["cases"] if c["subject"].replace("acct:", "") in insider_users)
    out["case_precision_pct"] = round(100 * tp_cases / len(rep["cases"]), 1) if rep["cases"] else None
    return out


# ------------------------------------------------------------------------------------------
# Deployment calibration (shadow mode). Uses only the first days of logs, never the labels.
def prepare(data: CertData, learn_days: int = 60) -> tuple:
    """Learn organisation-level context from the first `learn_days`:
    * partner domains: external domains that at least 5 different users sent attachments to
    * shared PCs: machines that at least 3 different users logged into
    Returns (events rewritten so that shared PCs are one known device class, partner domains)."""
    lim = learn_days * 24 + data.events[0].t
    dom_users, pc_users = defaultdict(set), defaultdict(set)
    for e in data.events:
        if e.t > lim:
            break
        if e.kind == "email":
            dom_users[e.attrs["to"].split("@")[-1]].add(e.account)
        elif e.kind == "login":
            pc_users[e.attrs["device"]].add(e.account)
    partners = tuple(d for d, us in dom_users.items() if len(us) >= 5 and not d.endswith("gmail.com"))
    shared = {pc for pc, us in pc_users.items() if len(us) >= 3}
    out = []
    for e in data.events:
        if e.kind == "login" and e.attrs.get("device") in shared:
            e = Event(e.t, e.account, e.kind, e.resource, e.rdept, e.sensitive, e.nbytes,
                      dict(e.attrs, device="shared-pc"), e.true_actor, e.scenario, e.malicious)
        out.append(e)
    return out, partners, shared


def calibrate(data: CertData, cfg: EngineConfig, partners, events, budget_per_week: float = 5.0,
              window_days=(60, 150), grid=(1, 1.5, 2, 3, 4, 6, 8, 12, 16, 24),
              restrict_per_week: Optional[float] = None) -> float:
    """Smallest threshold scale whose case rate in the calibration window is within the budget
    (cases per week for the whole organisation). Window ends before the first labelled incident
    (day 160 of r4.2); a real deployment would calibrate on its own shadow-mode period.
    restrict_per_week (v0.9 protocol): also limit how many users reach L3 or above per week in the window."""
    import copy
    lim = data.events[0].t + window_days[1] * 24
    sub = [e for e in events if e.t <= lim]
    weeks = (window_days[1] - window_days[0]) / 7
    for f in grid:
        c = copy.deepcopy(cfg)
        c.policy = P.PolicyConfig(thresholds=tuple(x * f for x in cfg.policy.thresholds))
        c.alert_threshold = cfg.alert_threshold * f
        rep = replay(CertData(data.users, sub, [], data.personal_addrs), c, partners=partners)
        w0 = data.events[0].t + window_days[0] * 24
        n = sum(1 for x in rep["cases"] if x["opened"] >= w0)
        r = len({s.replace("acct:", "") for s, t in rep["first_l3"].items() if t >= w0})
        if n / weeks <= budget_per_week and (restrict_per_week is None or r / weeks <= restrict_per_week):
            return f
    return grid[-1]
