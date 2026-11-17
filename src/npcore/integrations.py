# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Standards-based integration: OCSF events in, OpenID CAEP signals out.

This is how NullProtocol Negative Trust Architecture runs *outside* its own simulator: any log pipeline that can emit the
Open Cybersecurity Schema Framework (OCSF, https://schema.ocsf.io, v1.x; used by AWS Security Lake,
Splunk, IBM QRadar and others) can feed the engine, and any identity provider or SaaS that receives
OpenID Shared Signals can act on its output (CAEP 1.0, 29 Aug 2025: `risk-level-change`,
`session-revoked`).

Supported OCSF classes (class_uid):
    3002 Authentication          activity 1 Logon, status 1 Success    -> login
    1001 File System Activity    activity 2 Read / 14 Open              -> read
                                 activity 1 Create on a removable volume -> egress_usb
    4009 Email Activity          activity 1 Send, direction 2 Outbound  -> external e-mail
    4002 HTTP Activity           Post/Put to a file-sharing category     -> egress_cloud
    (v0.4)
    3001 Account Change          4 Password Reset, 10/11 MFA factor change -> mfa_reset (help desk if the actor
                                 is not the user; unmapped.verified)
                                 5 Disable, 6 Delete, or unmapped.employment_status "terminated" -> lifecycle
                                 7/8 Attach/Detach Policy with unmapped.what -> config_change
    3002 Authentication          status 2 with unmapped.mfa_result "deny" -> mfa_push deny; is_mfa false
    2004 Detection Finding       severity_id >= 4 -> high finding; title/malware name -> name
    6003 API Activity            Read/List by a workload -> api_export (src_endpoint.ip, unmapped.objects,
                                 api.request.data query); resources type "customer_record" -> record_read

Field mapping (OCSF attribute paths): time (ms since epoch), user.uid or actor.user.uid, device.uid /
device.hostname, src_endpoint.ip, src_endpoint.location.country, file.path, file.size,
file.confidentiality_id (>= 2 counts as restricted), email.to / email.from / email.files,
http_request.url.hostname, http_request.url.categories, traffic.bytes_out.

CAEP output is produced as unsigned SET payloads (JSON). In production they must be signed (JWS)
and delivered via an SSF stream (push or poll); that transport is out of scope here.
"""
from __future__ import annotations

import ipaddress
import json
import time as _time
import uuid
from dataclasses import dataclass, field
from typing import Dict, Iterable, Iterator, List, Optional

from .engine import EngineConfig
from .sim import Event

CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
RISK = {0: "LOW", 1: "LOW", 2: "MEDIUM", 3: "HIGH", 4: "HIGH"}
FILE_SHARING_CATEGORIES = ("file sharing", "personal storage", "online storage", "cloud storage")


@dataclass
class Directory:
    """Organisation context the engine needs and logs do not carry."""
    departments: Dict[str, str]                       # user id -> department
    path_departments: Dict[str, str] = field(default_factory=dict)   # path prefix -> owning department
    home_countries: tuple = ("DE",)
    partner_domains: tuple = ()
    removable_prefixes: tuple = ("/Volumes/", "E:\\", "F:\\", "/media/")
    support_staff: tuple = ()
    workloads: tuple = ()
    internal_domains: tuple = ("corp",)
    epoch_ms: Optional[int] = None                    # time origin (first event if None)

    @classmethod
    def load(cls, path: str) -> "Directory":
        d = json.load(open(path))
        return cls(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in d.items()})

    def dept_of_path(self, path: str) -> Optional[str]:
        best = None
        for pre, dept in self.path_departments.items():
            if path.startswith(pre) and (best is None or len(pre) > len(best[0])):
                best = (pre, dept)
        return best[1] if best else None


def _get(rec: dict, path: str, default=None):
    cur = rec
    for p in path.split("."):
        if isinstance(cur, list) and p.isdigit() and int(p) < len(cur):
            cur = cur[int(p)]
        elif isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            return default
    return cur


def _user(rec):
    return _get(rec, "user.uid") or _get(rec, "actor.user.uid") or _get(rec, "user.name") or _get(rec, "actor.user.name")


def _ip_type(ip: Optional[str], country: Optional[str], d: Directory) -> str:
    if ip:
        try:
            if ipaddress.ip_address(ip).is_private:
                return "corporate"
        except ValueError:
            pass
    if country and country.upper() not in d.home_countries:
        return "foreign"
    return "residential"


def from_ocsf(rec: dict, d: Directory) -> Optional[Event]:
    """Map one OCSF record to an engine event, or None if the record is not used."""
    cls = rec.get("class_uid")
    act = rec.get("activity_id")
    user = _user(rec)
    if user is None or "time" not in rec:
        return None
    if d.epoch_ms is None:
        d.epoch_ms = rec["time"]
    t = (rec["time"] - d.epoch_ms) / 3_600_000
    dev = _get(rec, "device.uid") or _get(rec, "device.hostname")
    ip = _get(rec, "src_endpoint.ip")
    sid = _get(rec, "actor.session.uid") or _get(rec, "session.uid")
    ua = _get(rec, "http_request.user_agent")
    if cls == 3002:
        if act == 1 and rec.get("status_id") == 2 and _get(rec, "unmapped.mfa_result") in ("deny", "approve"):
            return Event(t, user, "mfa_push", attrs={"result": _get(rec, "unmapped.mfa_result")})
        if act == 1 and _get(rec, "unmapped.mfa_result") == "approve":
            return Event(t, user, "mfa_push", attrs={"result": "approve"})
        if act != 1 or rec.get("status_id", 1) != 1:
            return None
        country = _get(rec, "src_endpoint.location.country")
        attrs = {"device": dev, "ip": ip, "ip_type": _ip_type(ip, country, d)}
        if sid:
            attrs.update(sid=sid, sip=ip)
        if ua:
            attrs["ua"] = ua
        if rec.get("is_mfa") is False:
            attrs["mfa"] = False
        return Event(t, user, "login", attrs=attrs)
    if cls == 3001:
        target = _get(rec, "user.uid") or user
        actor = _get(rec, "actor.user.uid")
        if act in (4, 10, 11):
            return Event(t, target, "mfa_reset", attrs={"via": "helpdesk" if actor and actor != target else "self",
                                                        "verified": bool(_get(rec, "unmapped.verified", False))})
        if act in (5, 6) or _get(rec, "unmapped.employment_status") == "terminated":
            return Event(t, target, "lifecycle", attrs={"status": "terminated"})
        if act in (7, 8) and _get(rec, "unmapped.what"):
            a = {"what": _get(rec, "unmapped.what"), "device": dev}
            if ip:
                a.update(ip=ip)
            if sid:
                a.update(sid=sid, sip=ip)
            if ua:
                a["ua"] = ua
            if _get(rec, "unmapped.ticket"):
                a["ticket"] = _get(rec, "unmapped.ticket")
            return Event(t, actor or target, "config_change", attrs=a, sensitive=True)
        return None
    if cls == 2004:
        sev = int(rec.get("severity_id", 1) or 1)
        name = (_get(rec, "malware.0.name") or _get(rec, "finding_info.title") or "").lower()
        if "remote" in name and "access" in name:
            name = "remote_access_tool"
        return Event(t, user, "detection", attrs={"severity": "high" if sev >= 4 else ("medium" if sev == 3 else "low"),
                                                   "name": name or "finding", "device": dev})
    if cls == 6003:
        if act not in (2, 5):
            return None
        rtype = _get(rec, "resources.0.type")
        if rtype == "customer_record":
            ticket = _get(rec, "unmapped.ticket")
            return Event(t, user, "record_read", _get(rec, "resources.0.uid"), d.dept_of_path(_get(rec, "resources.0.uid") or "")
                         or _get(rec, "unmapped.dept"), True, 1_000_000,
                         {"ticket": ticket, "assigned": bool(_get(rec, "unmapped.assigned", bool(ticket)))})
        n = int(_get(rec, "unmapped.objects", 0) or 0)
        q = _get(rec, "api.request.data") or ""
        return Event(t, user, "api_export", _get(rec, "api.operation"), _get(rec, "unmapped.dept"),
                     bool(_get(rec, "unmapped.sensitive", False)), int(_get(rec, "traffic.bytes_out", 0) or 0),
                     {"ip": ip, "sip": ip, "objects": n, "query": q})
    ctx = {"device": dev}
    if ip:
        ctx["ip"] = ip
    if sid:
        ctx.update(sid=sid, sip=_get(rec, "unmapped.session_ip") or ip)
    if cls == 1001:
        path = _get(rec, "file.path") or _get(rec, "file.name") or ""
        size = int(_get(rec, "file.size", 0) or 0)
        sensitive = int(_get(rec, "file.confidentiality_id", 0) or 0) >= 2
        attrs = dict(ctx)
        if _get(rec, "file.uid", "").startswith("dcy-") or _get(rec, "unmapped.decoy_id"):
            attrs["decoy_id"] = _get(rec, "unmapped.decoy_id") or _get(rec, "file.uid")
        if act == 1 and any(path.startswith(p) for p in d.removable_prefixes):
            src = _get(rec, "unmapped.source_path") or path        # DLP agents report the source of a copy
            return Event(t, user, "egress_usb", path, d.dept_of_path(src), sensitive, size, dict(attrs, removable=True))
        if act in (2, 14):
            return Event(t, user, "read", path, d.dept_of_path(path), sensitive, size, attrs)
        return None
    if cls == 4009:
        if act != 1:
            return None
        to = _get(rec, "email.to") or []
        to = to if isinstance(to, list) else [to]
        files = _get(rec, "email.files") or []
        ext = [x for x in to if not any(str(x).lower().endswith("@" + dm) for dm in d.internal_domains)]
        external = rec.get("direction_id") == 2 and bool(ext)
        sensitive = any(int(f.get("confidentiality_id", 0) or 0) >= 2 for f in files)
        size = sum(int(f.get("size", 0) or 0) for f in files)
        rcpt = (ext or to or [""])[0]
        res = files[0].get("path") or files[0].get("name") if files else None
        return Event(t, user, "email", res, d.dept_of_path(res or ""), sensitive, size,
                     dict(ctx, to=rcpt, external=external, attachment=bool(files)))
    if cls == 4002:
        if act not in (6, 7):
            return None
        cats = [str(c).lower() for c in (_get(rec, "http_request.url.categories") or [])]
        host = _get(rec, "http_request.url.hostname") or ""
        if not any(c in FILE_SHARING_CATEGORIES for c in cats):
            return None
        size = int(_get(rec, "traffic.bytes_out", 0) or 0)
        personal = "personal storage" in cats
        return Event(t, user, "egress_cloud", host, None, False, size,
                     dict(ctx, dest=f"{host} (personal)" if personal else host))
    return None


def caep_set(subject: str, old: int, new: int, t_epoch: float, issuer: str, audience: str, reason: str) -> List[dict]:
    """CAEP 1.0 SET payloads for a containment change of a person or an account."""
    is_acct = subject.startswith("acct:")
    sub_id = {"format": "opaque", "id": subject}
    base = {"iss": issuer, "jti": uuid.uuid4().hex, "iat": int(_time.time()), "aud": audience, "sub_id": sub_id}
    out = []
    if RISK[old] != RISK[new]:
        out.append(dict(base, events={CAEP + "risk-level-change": {
            "principal": "SESSION" if is_acct else "USER", "current_level": RISK[new], "previous_level": RISK[old],
            "risk_reason": reason[:120], "event_timestamp": int(t_epoch)}}))
    if new >= 4 and old < 4:
        out.append(dict(base, jti=uuid.uuid4().hex, events={CAEP + "session-revoked": {
            "event_timestamp": int(t_epoch), "initiating_entity": "policy",
            "reason_admin": {"en": f"NullProtocol Negative Trust containment L4 ({reason[:80]})"}}}))
    return out


def stream(records: Iterable[dict], d: Directory, cfg: Optional[EngineConfig] = None,
           issuer: str = "https://nt.example/", audience: str = "https://idp.example/caep", decoys=None) -> Iterator[dict]:
    """Run the engine over OCSF records and yield decision records, level changes and CAEP SETs.
    Step-up challenges are assumed to succeed (the IdP enforces them); see npcore.api for the full API."""
    from .api import NegativeTrust
    nt = NegativeTrust(d, cfg=cfg, decoys=decoys, issuer=issuer, audience=audience)
    yield from nt.process_many(records)


# --------------------------------------------------------------------------- simulator -> OCSF
def to_ocsf(e: Event, epoch_ms: int, files_dept_prefix: str = "//fs/") -> Optional[dict]:
    """Export a simulator event as an OCSF record (used for the end-to-end integration test and demo)."""
    base = {"time": int(epoch_ms + e.t * 3_600_000), "metadata": {"version": "1.9.0", "product": {"name": "npcore-sim"}},
            "user": {"uid": e.account}, "device": {"uid": e.attrs.get("device")} if e.attrs.get("device") else {}}
    if e.attrs.get("ip") and e.kind != "login":
        base["src_endpoint"] = {"ip": e.attrs["ip"]}
    if e.attrs.get("sip") and e.attrs.get("sip") != e.attrs.get("ip"):
        base["unmapped"] = {"session_ip": e.attrs["sip"]}      # simulator detail: request IP of the session
    if e.attrs.get("sid"):
        base["actor"] = {"session": {"uid": e.attrs["sid"]}}
    if e.attrs.get("ua"):
        base["http_request"] = {"user_agent": e.attrs["ua"]}
    conf = 3 if e.sensitive else 1
    if e.kind == "login":
        ipt = e.attrs.get("ip_type")
        ip = {"corporate": "10.0.0.1", "residential": "91.0.0.1", "foreign": "185.0.0.1"}.get(ipt, "91.0.0.1") \
            if not e.attrs.get("ip") else e.attrs["ip"]
        rec = dict(base, class_uid=3002, activity_id=1, status_id=1,
                   src_endpoint={"ip": ip, "location": {"country": "RU" if ipt == "foreign" else "DE"}})
        if e.attrs.get("mfa") is False:
            rec["is_mfa"] = False
        return rec
    if e.kind == "read":
        rec = dict(base, class_uid=1001, activity_id=2, file={"path": f"{files_dept_prefix}{e.rdept}/{'restricted' if e.sensitive else 'general'}/{e.resource}",
                                                               "uid": e.resource, "size": e.nbytes, "confidentiality_id": conf})
        if e.attrs.get("decoy_id"):
            rec["unmapped"] = {"decoy_id": e.attrs["decoy_id"]}
        return rec
    if e.kind == "egress_usb":
        return dict(base, class_uid=1001, activity_id=1, file={"path": f"/Volumes/USB/{e.resource}", "size": e.nbytes, "confidentiality_id": conf},
                    unmapped={"source_path": f"{files_dept_prefix}{e.rdept}/x/{e.resource}"})
    if e.kind == "email":
        files = [{"name": e.resource, "path": f"{files_dept_prefix}{e.rdept}/x/{e.resource}", "size": e.nbytes, "confidentiality_id": conf}] \
            if e.attrs.get("attachment") else []
        return dict(base, class_uid=4009, activity_id=1, direction_id=2 if e.attrs.get("external") else 3,
                    email={"to": [e.attrs.get("to")], "files": files})
    if e.kind == "mfa_push":
        return dict(base, class_uid=3002, activity_id=1, status_id=2 if e.attrs.get("result") == "deny" else 1,
                    unmapped={"mfa_result": e.attrs.get("result")})
    if e.kind == "mfa_reset":
        actor = "helpdesk-agent" if e.attrs.get("via") == "helpdesk" else e.account
        return dict(base, class_uid=3001, activity_id=4, actor={"user": {"uid": actor}},
                    unmapped={"verified": bool(e.attrs.get("verified"))})
    if e.kind == "lifecycle":
        return dict(base, class_uid=3001, activity_id=5, unmapped={"employment_status": "terminated"})
    if e.kind == "config_change":
        um = {"what": e.attrs.get("what")}
        if e.attrs.get("ticket"):
            um["ticket"] = e.attrs["ticket"]
        rec = dict(base, class_uid=3001, activity_id=7, actor={"user": {"uid": e.account}}, unmapped=um)
        if e.attrs.get("sid"):
            rec["actor"]["session"] = {"uid": e.attrs["sid"]}
        return rec
    if e.kind == "detection":
        sev = {"high": 4, "medium": 3}.get(e.attrs.get("severity"), 2)
        return dict(base, class_uid=2004, severity_id=sev, finding_info={"title": e.attrs.get("name", "")})
    if e.kind == "record_read":
        return dict(base, class_uid=6003, activity_id=2, resources=[{"type": "customer_record", "uid": e.resource}],
                    unmapped=dict(base.get("unmapped", {}), ticket=e.attrs.get("ticket"), assigned=bool(e.attrs.get("assigned")), dept=e.rdept))
    if e.kind == "api_export":
        return dict(base, class_uid=6003, activity_id=5, api={"operation": e.resource, "request": {"data": e.attrs.get("query", "")}},
                    src_endpoint={"ip": e.attrs.get("ip")}, traffic={"bytes_out": e.nbytes},
                    unmapped={"objects": e.attrs.get("objects", 0), "dept": e.rdept, "sensitive": e.sensitive})
    if e.kind == "egress_cloud":
        dest = str(e.attrs.get("dest", ""))
        cat = "Personal Storage" if any(x in dest.lower() for x in ("personal", "dropbox", "mega")) else "File Sharing"
        return dict(base, class_uid=4002, activity_id=6, http_request={"url": {"hostname": dest, "categories": [cat]}},
                    traffic={"bytes_out": e.nbytes})
    return None
