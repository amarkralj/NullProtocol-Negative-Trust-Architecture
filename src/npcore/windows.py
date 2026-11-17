# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Windows endpoint adapter (v0.7): Windows Security, Sysmon and PowerShell event logs -> engine events.

NullProtocol Negative Trust does not replace endpoint detection and response (EDR). This adapter turns a small set of
well-known, public indicators (as used in the open Sigma rule set) into the engine's existing endpoint evidence, so
organisations without an EDR product can use the logs Windows already writes, and so findings are attributed to the
person or account behind the process.

    Sysmon 10, LSASS opened with memory-read rights by a non-system process        -> detection high  credential dumping
    command lines / PowerShell with dumping tools (mimikatz, procdump lsass, comsvcs
      MiniDump, ntdsutil ifm, shadow copies of NTDS/SAM, reg save of SAM/SECURITY,
      rubeus, kerberoasting)                                                         -> detection high  credential theft
    Security 4662 directory replication rights by a user account (DCSync)            -> detection high  DCSync
    Security 1102, System 104, EventLog service changes, wevtutil cl, auditpol       -> audit_change
    PsExec, remote WMI process creation, WinRM shells, service installs (7045)      -> detection medium remote execution
    remote-access tools (AnyDesk, TeamViewer, ScreenConnect ...)                     -> detection remote_access_tool
    Security 4720 user created; 4728/4732/4756 member added to a group               -> config_change
    rar / 7z / Compress-Archive                                                      -> archive
    Security 4624 / 4625 interactive or remote logons                                -> login / login_failure

Events without a user (Sysmon 10) are attributed to the user who started the process (Sysmon 1 / Security 4688), or
to the host's interactive user.
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
import re
from collections import Counter, defaultdict
from typing import Iterable, List, Optional

from .sim import Event

LSASS_RIGHTS = {"0x1010", "0x1410", "0x1418", "0x1438", "0x143a", "0x1f3fff", "0x1fffff", "0x1f1fff", "0x1f2fff", "0x40",
                "0x1f0fff"}
SYSTEM_IMAGES = ("\\msmpeng.exe", "\\csrss.exe", "\\wininit.exe", "\\lsm.exe", "\\services.exe", "\\mrt.exe",
                 "\\wmiprvse.exe", "\\svchost.exe")
CRED = [r"mimikatz", r"sekurlsa", r"lsadump", r"kerberos::", r"procdump.*lsass", r"comsvcs(\.dll)?[ ,]+#?(minidump|24)",
        r"ntdsutil.*\bifm\b", r"vssadmin.*create\s+shadow", r"esentutl.*(ntds|\\sam)", r"reg(\.exe)?\s+save\s+hklm\\(sam|security|system)",
        r"rubeus", r"invoke-kerberoast", r"invoke-ninjacopy", r"invoke-powerdump", r"get-gpppassword", r"dumpcreds",
        r"out-minidump", r"invoke-dcsync", r"secretsdump", r"nanodump", r"dumpert", r"\bsafetykatz\b",
        r"windows\.security\.credentials\.passwordvault", r"promptforcredential"]
AUDIT = [r"wevtutil(\.exe)?\s+(cl|clear-log)", r"clear-eventlog", r"auditpol.*(/clear|/remove|disable)",
         r"remove-eventlog", r"services\\eventlog"]
REMOTE_EXEC = [r"psexe(c|svc)", r"wmic.*/node:.*process\s+call\s+create", r"invoke-wmimethod.*-computername",
               r"winrs(\.exe)?\s+-r:", r"invoke-command.*-computername", r"enter-pssession", r"new-pssession"]
RAT = [r"anydesk", r"teamviewer", r"screenconnect", r"atera", r"splashtop", r"rustdesk", r"remoteutilities"]
ARCHIVE = [r"\b7z(a|\.exe)?\s+a\b", r"\brar(\.exe)?\s+a\b", r"compress-archive"]
DCSYNC = ("1131f6aa-9c07-11d1-f79f-00c04fc2dcd2", "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2", "89e95b76-444d-4c62-991a-0facbeda640c")
SKIP_USERS = {"system", "local service", "network service", "anonymous logon", "-", "", "dwm-1", "umfd-0", "umfd-1"}


def _rx(pats):
    return re.compile("|".join(f"(?:{p})" for p in pats), re.I)


R_CRED, R_AUDIT, R_REMOTE, R_RAT, R_ARCH = map(_rx, (CRED, AUDIT, REMOTE_EXEC, RAT, ARCHIVE))


def _t(e: dict) -> Optional[float]:
    s = e.get("@timestamp") or e.get("TimeCreated") or e.get("UtcTime") or e.get("EventTime")
    if not s:
        return None
    s = str(s).replace("Z", "+00:00").replace(" ", "T", 1)
    if "." in s:
        head, frac = s.split(".", 1)
        digits = "".join(ch for ch in frac if ch.isdigit())
        s = head + "." + digits[:6] + frac[len(digits):]
    try:
        d = dt.datetime.fromisoformat(s)
    except ValueError:
        return None
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.timestamp() / 3600


def _user(v) -> Optional[str]:
    if not v:
        return None
    u = str(v).split("\\")[-1].split("@")[0].strip().lower()
    return None if u in SKIP_USERS or u.endswith("$") else u


def _text(e: dict) -> str:
    return " ".join(str(e.get(k, "")) for k in ("CommandLine", "ParentCommandLine", "Image", "ScriptBlockText",
                                                "Payload", "HostApplication", "ServiceName", "ImagePath", "TargetObject",
                                                "Message" if e.get("EventID") in (800, 4103, 4104, 4688, 7045) else "_"))


def load(paths: Iterable[pathlib.Path]) -> List[Event]:
    rows = []
    for p in paths:
        with open(p, encoding="utf-8", errors="replace") as fh:
            for line in fh:
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
    # process -> user, and each host's interactive user
    proc_user, host_users = {}, defaultdict(Counter)
    for e in rows:
        eid, host = e.get("EventID"), str(e.get("Hostname") or e.get("host") or "").split(".")[0].lower()
        u = _user(e.get("User")) or (_user(e.get("SubjectUserName")) if eid == 4688 else None)
        if eid == 1 and u:
            proc_user[str(e.get("ProcessGuid", "")).lower()] = u
            host_users[host][u] += 1
        elif eid == 4688 and u:
            proc_user[(host, str(e.get("NewProcessId", "")).lower())] = u
            host_users[host][u] += 1
        elif eid == 4624 and str(e.get("LogonType")) in ("2", "10", "11"):
            tu = _user(e.get("TargetUserName"))
            if tu:
                host_users[host][tu] += 1
    owner = {h: c.most_common(1)[0][0] for h, c in host_users.items() if c}

    evs: List[Event] = []
    seen = set()
    for e in rows:
        t = _t(e)
        if t is None:
            continue
        eid = e.get("EventID")
        ch = str(e.get("Channel", "")).lower()
        host = str(e.get("Hostname") or e.get("host") or "").split(".")[0].lower()
        user = (_user(e.get("User")) or _user(e.get("SourceUser")) or proc_user.get(str(e.get("SourceProcessGUID", "")).lower())
                or (_user(e.get("SubjectUserName")) if "security" in ch else None) or _user(e.get("UserID"))
                or owner.get(host))
        if not user:
            continue
        ctx = {"device": host, "ip": e.get("IpAddress") or e.get("SourceAddress") or "corp", "ip_type": "corporate"}

        def add(kind, key, **attrs):                               # called within this iteration only
            k = (kind, user, key, int(t * 12))                     # noqa: B023  (one per kind and key every 5 min)
            if k not in seen:
                seen.add(k)
                evs.append(Event(t, user, kind, sensitive=kind != "login", attrs=dict(ctx, **attrs)))  # noqa: B023

        if "sysmon" in ch and eid == 10 and str(e.get("TargetImage", "")).lower().endswith("\\lsass.exe"):
            src = str(e.get("SourceImage", "")).lower()
            if str(e.get("GrantedAccess", "")).lower() in LSASS_RIGHTS and not src.endswith(SYSTEM_IMAGES):
                add("detection", "lsass", severity="high", name="credential dumping (LSASS memory access)")
            continue
        if "security" in ch and eid == 4662 and any(g in str(e.get("Properties", "")).lower() for g in DCSYNC):
            u2 = _user(e.get("SubjectUserName"))
            if u2:
                user = u2
                add("detection", "dcsync", severity="high", name="directory replication by a user account (DCSync)")
            continue
        if ("security" in ch and eid == 1102) or (eid == 104 and "system" in ch):
            add("audit_change", "log_cleared", what="event log cleared")
            continue
        if "security" in ch and eid in (4720,):
            add("config_change", "4720", what="new_principal")
            continue
        if "security" in ch and eid in (4728, 4732, 4756):
            add("config_change", str(eid), what="privilege_grant")
            continue
        if "security" in ch and eid in (4624, 4625) and str(e.get("LogonType")) in ("2", "3", "10", "11"):
            tu = _user(e.get("TargetUserName"))
            if tu:
                user = tu
                add("login" if eid == 4624 else "login_failure", e.get("LogonType"), logon_type=str(e.get("LogonType")))
            continue
        if eid not in (1, 4688, 800, 4103, 4104, 7045, 13, 12):
            continue
        txt = _text(e)
        if eid in (12, 13):
            if R_AUDIT.search(str(e.get("TargetObject", ""))):
                add("audit_change", "eventlog_registry", what="event log service changed in the registry")
            continue
        m = R_CRED.search(txt)
        if m:
            add("detection", "cred:" + m.group(0).lower()[:20], severity="high", name=f"credential theft ({m.group(0)[:40]})")
        elif R_AUDIT.search(txt):
            add("audit_change", "audit_cmd", what="logging disabled or cleared")
        elif R_RAT.search(txt):
            add("detection", "rat", severity="medium", name="remote_access_tool")
        elif R_REMOTE.search(txt) or eid == 7045:
            add("detection", "remote_exec", severity="medium", name="remote execution")
        elif R_ARCH.search(txt):
            add("archive", "archive", count=1)
    evs.sort(key=lambda x: x.t)
    if evs:
        t0 = evs[0].t - 24 * 20
        for x in evs:
            x.t -= t0
    return evs
