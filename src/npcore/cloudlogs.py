# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Cloud identity and audit log adapters (v0.6): Microsoft Entra ID, Microsoft 365, Microsoft Graph sign-ins,
AWS CloudTrail (native and OCSF) -> engine events.

Every operation name is mapped explicitly; unlisted operations are ignored. Resulting event kinds:

    login / login_failure / mfa_push   sign-ins (Entra sign-in logs, Graph sign-ins, M365 UserLoggedIn, AWS ConsoleLogin)
    config_change  what=privilege_grant | credential_added | federation | mfa_method | disable_mfa | new_principal
    audit_change   logging, detectors, firewall rules or protection policies switched off or deleted
    mail_rule      inbox, transport or mailbox forwarding rules
    data_access    what=<operation>: exports, mailbox access by apps or admins, secret and password retrieval,
                   snapshots or images shared, bucket permissions, log retrieval, key deletion
    api_read       read-only cloud API calls (List*, Describe*, Get*), with error code (for discovery bursts)
    idp_risk       risk detections and security alerts produced by the provider
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
from typing import Iterable, List

from .sim import Event

PRIV = ("add member to role", "add eligible member to role", "add app role assignment", "add delegated permission grant",
        "consent to application", "add owner to", "set-rolegroup", "update-rolegroupmember", "sitecollectionadminadded",
        "add-mailboxpermission", "add-mailboxfolderpermission", "addfolderpermissions", "modifyfolderpermissions",
        "set-mailboxfolderpermission", "update-ediscoverycaseadmin", "caseadminupdated", "createpolicyversion",
        "setdefaultpolicyversion", "createpolicy", "createrole", "attachuserpolicy", "attachrolepolicy", "putuserpolicy",
        "putrolepolicy", "update service principal", "update application", "update user")
CRED = ("add service principal credentials", "certificates and secrets", "create application password",
        "createaccesskey", "createloginprofile", "updateloginprofile", "temporary access pass", "reset password (by admin)",
        "reset user password", "change user password", "sendsshpublickey", "enable account", "update stsrefreshtoken")
FED = ("add-federateddomain", "add unverified domain", "set company information", "cross-tenant access",
       "updatesamlprovider", "createsamlprovider", "update authorization policy")
MFA = ("user registered security info", "register device", "user started security info registration")
NEW = ("add service principal", "add application", "add user", "invite external user", "add group")
AUDIT = ("stoplogging", "deletetrail", "updatetrail", "deletedetector", "deleteloggroup", "deletelogstream", "deletewebacl",
         "deleteipset", "deleterule", "putbucketlifecycle", "disable-safelinksrule", "set-safelinksrule",
         "deletenetworkaclentry", "createnetworkaclentry", "replacenetworkaclentry", "set-antiphishpolicy",
         "deleteconfigurationrecorder", "stopconfigurationrecorder", "deleteflowlogs")
MAILRULE = ("new-inboxrule", "set-inboxrule", "updateinboxrules", "new-transportrule", "set-transportrule")
DATA = ("mailitemsaccessed", "adminmailaccess", "searchexported", "searchexportdownloaded", "new-compliancesearchaction",
        "start-compliancesearch", "new-compliancesearch", "searchqueryinitiatedsharepoint", "getpassworddata",
        "batchgetsecretvalue", "getsecretvalue", "getlogevents", "modifysnapshotattribute", "modifyimageattribute",
        "putbucketacl", "putbucketpolicy", "schedulekeydeletion", "putkeypolicy", "filedownloaded", "fileaccessed",
        "sharedsnapshotvolumecreated", "copyobject", "microsoft graph activity")
ALERT = ("alerttriggered", "alertentitygenerated", "atpdetection", "risky user")


def _t(ts) -> float:
    if isinstance(ts, (int, float)):
        return ts / 3_600_000 if ts > 1e11 else ts / 3600
    s = str(ts).replace("Z", "+00:00")
    if "." in s:                                  # trim fractions beyond microseconds
        head, frac = s.split(".", 1)
        digits = "".join(ch for ch in frac if ch.isdigit())
        s = head + "." + digits[:6] + frac[len(digits):]
    d = dt.datetime.fromisoformat(s)
    if d.tzinfo is None:
        d = d.replace(tzinfo=dt.timezone.utc)
    return d.timestamp() / 3600


def _has(op: str, keys) -> bool:
    return any(k in op for k in keys)


def classify(op: str):
    """Operation name -> (kind, what) for audit operations; None if not mapped."""
    o = op.lower().strip()
    if "disable strong authentication" in o:
        return "config_change", "disable_mfa"
    if _has(o, AUDIT):
        return "audit_change", o
    if _has(o, MAILRULE):
        return "mail_rule", o
    if _has(o, CRED):
        return "config_change", "credential_added"
    if _has(o, FED):
        return "config_change", "federation"
    if _has(o, MFA):
        return "config_change", "mfa_method"
    if _has(o, PRIV):
        return "config_change", "privilege_grant"
    if _has(o, NEW):
        return "config_change", "new_principal"
    if _has(o, DATA):
        return "data_access", o
    if _has(o, ALERT):
        return "idp_risk", o
    if o.startswith(("list", "describe", "get")):
        return "api_read", o
    return None


def _ev(t, user, kind, **attrs) -> Event:
    return Event(t, user, kind, sensitive=kind in ("config_change", "audit_change", "data_access"), attrs=attrs)


def _signin(t, user, ok_code, ip, ua, lat, lon, sid, mfa_denied=False, risk=None, extra=None):
    ctx = {"ip": ip, "ip_type": "residential", "lat": lat, "lon": lon, "ua": ua, "device": ua, "sid": sid, "sip": ip}
    ctx.update(extra or {})
    out = []
    if mfa_denied:
        out.append(_ev(t, user, "mfa_push", result="deny", **ctx))
    elif ok_code:
        out.append(_ev(t, user, "login", mfa=True, **ctx))
    else:
        out.append(_ev(t, user, "login_failure", **ctx))
    if risk in ("high", "medium"):
        out.append(_ev(t, user, "idp_risk", severity=risk, source="identity provider risk detection", **ctx))
    return out


def from_entra(e: dict) -> List[Event]:
    p = e.get("properties") or {}
    cat = e.get("category", "")
    t = _t(e.get("time") or p.get("createdDateTime"))
    if cat.endswith("SignInLogs"):
        user = p.get("userPrincipalName") or p.get("servicePrincipalName") or p.get("servicePrincipalId") or e.get("identity")
        st = p.get("status") or {}
        code = _code(st.get("errorCode"))
        geo = _d(_d(p.get("location")).get("geoCoordinates"))
        return _signin(t, user, code == 0, p.get("ipAddress") or e.get("callerIpAddress"), p.get("userAgent"),
                       geo.get("latitude"), geo.get("longitude"), p.get("sessionId") or p.get("correlationId"),
                       mfa_denied=code in (500121, 50074) and "denied" in str(st.get("additionalDetails", "")).lower(),
                       risk=p.get("riskLevelDuringSignIn"))
    if cat == "RiskyUsers":
        return [_ev(t, p.get("userPrincipalName") or "unknown", "idp_risk", severity=p.get("riskLevel", "high"),
                    source="Entra ID risky user")]
    if cat == "MicrosoftGraphActivityLogs":
        user = p.get("userId") or p.get("servicePrincipalId") or p.get("appId") or "unknown"
        return [_ev(t, user, "data_access", what="microsoft graph activity", ip=p.get("ipAddress"),
                    uri=p.get("requestUri"))]
    op = p.get("activityDisplayName") or e.get("operationName") or ""
    c = classify(op)
    if not c:
        return []
    ib = _d(p.get("initiatedBy"))
    user = (ib.get("user") or {}).get("userPrincipalName") or (ib.get("user") or {}).get("id") or \
        (ib.get("app") or {}).get("displayName") or (ib.get("app") or {}).get("servicePrincipalId") or "unknown"
    if str(p.get("result", "success")).lower() not in ("success", ""):
        return []
    return [_ev(t, user, c[0], what=c[1], ip=e.get("callerIpAddress"))]


def from_graph_signin(e: dict) -> List[Event]:
    st = e.get("status") or {}
    code = int(st.get("errorCode") or 0)
    geo = ((e.get("location") or {}).get("geoCoordinates") or {})
    ua = e.get("userAgent") or (e.get("deviceDetail") or {}).get("browser")
    return _signin(_t(e["createdDateTime"]), e.get("userPrincipalName"), code == 0, e.get("ipAddress"), ua,
                   geo.get("latitude"), geo.get("longitude"), e.get("correlationId"),
                   mfa_denied=code == 500121 and "denied" in str(st.get("additionalDetails", "")).lower(),
                   risk=e.get("riskLevelDuringSignIn"))


def from_o365(e: dict) -> List[Event]:
    op = e.get("Operation", "")
    t = _t(e["CreationTime"])
    user = e.get("UserId") or "unknown"
    ip = str(e.get("ClientIP") or e.get("ActorIpAddress") or "").rsplit(":", 1)[0] if e.get("ClientIP", "").count(":") == 1 \
        else (e.get("ClientIP") or e.get("ActorIpAddress"))
    ua = next((x.get("Value") for x in e.get("ExtendedProperties") or [] if x.get("Name") == "UserAgent"), None)
    if op in ("UserLoggedIn", "UserLoginFailed"):
        err = str(e.get("LogonError") or "")
        return _signin(t, user, op == "UserLoggedIn", ip, ua, None, None, None,
                       mfa_denied="UserDeclinedAuthentication" in err or "DeniedMfa" in err)
    if op == "Set-Mailbox":
        params = {x.get("Name"): x.get("Value") for x in e.get("Parameters") or []}
        if any(k in params for k in ("ForwardingAddress", "ForwardingSmtpAddress", "DeliverToMailboxAndForward")):
            return [_ev(t, user, "mail_rule", what="set-mailbox forwarding", ip=ip)]
        return []
    c = classify(op)
    if not c:
        return []
    if c[0] == "idp_risk":
        return [_ev(t, user, "idp_risk", severity="high", source=f"Microsoft 365 {op}", ip=ip)]
    if e.get("ResultStatus") in ("Failed", "False", False) and c[0] != "config_change":
        return []
    return [_ev(t, user, c[0], what=c[1], ip=ip, workload=e.get("Workload"), app=e.get("ClientAppId") or e.get("AppId"))]


def from_cloudtrail(e: dict) -> List[Event]:
    ui = e.get("userIdentity") or {}
    user = ui.get("userName") or (ui.get("sessionContext") or {}).get("sessionIssuer", {}).get("userName") or \
        ui.get("arn") or ui.get("principalId") or "unknown"
    t = _t(e["eventTime"])
    op = e.get("eventName", "")
    ip, ua = e.get("sourceIPAddress"), e.get("userAgent")
    if op == "ConsoleLogin":
        ok = ((e.get("responseElements") or {}).get("ConsoleLogin") == "Success")
        mfa = (e.get("additionalEventData") or {}).get("MFAUsed") == "Yes"
        ev = _signin(t, user, ok, ip, ua, None, None, None)
        if ok:
            ev[0].attrs["mfa"] = mfa
        return ev
    c = classify(op)
    if not c:
        return []
    err = e.get("errorCode")
    if err and c[0] != "api_read":
        return [_ev(t, user, "api_read", what=op.lower(), error=err, ip=ip, ua=ua)]
    return [_ev(t, user, c[0], what=c[1], ip=ip, ua=ua, error=err)]


def from_ocsf_cloudtrail(e: dict) -> List[Event]:
    api = e.get("api") or {}
    actor = (e.get("actor") or {}).get("user") or {}
    native = {"eventName": api.get("operation", ""), "eventTime": e.get("time"),
              "userIdentity": {"userName": actor.get("name") or actor.get("uid")},
              "sourceIPAddress": (e.get("src_endpoint") or {}).get("ip"),
              "userAgent": (e.get("http_request") or {}).get("user_agent"),
              "errorCode": (api.get("response") or {}).get("error")}
    return from_cloudtrail(native)


def _code(v) -> int:
    try:
        return int(v or 0)
    except (TypeError, ValueError):
        return -1


def _d(v) -> dict:
    v = _j(v)
    return v if isinstance(v, dict) else {}


def _j(v):
    if isinstance(v, str) and v[:1] in "{[":
        try:
            return json.loads(v)
        except ValueError:
            return {}
    return v if v not in ("", None) else {}


def from_sentinel(e: dict) -> List[Event]:
    """Microsoft Sentinel / Log Analytics tables: SigninLogs and AAD*SignInLogs, AuditLogs, AWSCloudTrail, OfficeActivity.
    Rows are rewritten into the native shape of each source and read by the same adapter."""
    typ = e.get("Type") or ""
    if typ.endswith("SignInLogs") or typ == "SigninLogs" or ("ResultType" in e and "IPAddress" in e):
        st = _d(e.get("Status"))
        loc = _d(e.get("LocationDetails"))
        native = {"time": e.get("TimeGenerated") or e.get("CreatedDateTime"), "category": "SignInLogs",
                  "properties": {"userPrincipalName": e.get("UserPrincipalName") or e.get("ServicePrincipalName")
                                 or e.get("ServicePrincipalId"), "ipAddress": e.get("IPAddress"), "userAgent": e.get("UserAgent"),
                                 "status": {"errorCode": e.get("ResultType") or 0,
                                            "additionalDetails": st.get("additionalDetails", "")},
                                 "location": loc, "sessionId": e.get("SessionId"), "correlationId": e.get("CorrelationId"),
                                 "riskLevelDuringSignIn": e.get("RiskLevelDuringSignIn")}}
        return from_entra(native)
    if typ == "AuditLogs" or "ActivityDisplayName" in e:
        native = {"time": e.get("ActivityDateTime") or e.get("TimeGenerated"), "category": "AuditLogs",
                  "properties": {"activityDisplayName": e.get("ActivityDisplayName") or e.get("OperationName"),
                                 "initiatedBy": _d(e.get("InitiatedBy")), "result": e.get("Result", "success")}}
        return from_entra(native)
    if typ == "AWSCloudTrail" or "EventName" in e and "EventSource" in e:
        native = {"eventName": e.get("EventName", ""), "eventTime": e.get("TimeGenerated"), "eventSource": e.get("EventSource"),
                  "userIdentity": {"userName": e.get("UserIdentityUserName"), "arn": e.get("UserIdentityArn"),
                                   "principalId": e.get("UserIdentityPrincipalid")},
                  "sourceIPAddress": e.get("SourceIpAddress"), "userAgent": e.get("UserAgent"),
                  "errorCode": e.get("ErrorCode") or None, "responseElements": _d(e.get("ResponseElements")),
                  "additionalEventData": _d(e.get("AdditionalEventData"))}
        return from_cloudtrail(native)
    if typ == "OfficeActivity" or ("Operation" in e and "TimeGenerated" in e and "UserId" in e):
        native = {"Operation": e.get("Operation", ""), "CreationTime": e.get("TimeGenerated"), "UserId": e.get("UserId"),
                  "ClientIP": e.get("ClientIP") or e.get("Client_IPAddress") or "", "ResultStatus": e.get("ResultStatus"),
                  "Parameters": _j(e.get("Parameters")) if isinstance(_j(e.get("Parameters")), list) else [], "Workload": e.get("OfficeWorkload")}
        return from_o365(native)
    return []


def convert(e: dict) -> List[Event]:
    if "TimeGenerated" in e and ("Type" in e or "TenantId" in e or "AADTenantId" in e):
        return from_sentinel(e)
    if "preview" in e and isinstance(e.get("result"), dict):
        e = e["result"]
        if isinstance(e.get("_raw"), str):
            try:
                e = json.loads(e["_raw"])
            except ValueError:
                return []
    if "eventSource" in e and "eventName" in e:
        return from_cloudtrail(e)
    if "api" in e and "metadata" in e:
        return from_ocsf_cloudtrail(e)
    if "properties" in e and ("category" in e or "operationName" in e):
        return from_entra(e)
    if "Operation" in e and "CreationTime" in e:
        return from_o365(e)
    if "createdDateTime" in e and "userPrincipalName" in e:
        return from_graph_signin(e)
    return []


def load(paths: Iterable[pathlib.Path]) -> List[Event]:
    evs: List[Event] = []
    for p in paths:
        text = pathlib.Path(p).read_text()
        rows = []
        if text.lstrip()[:1] in "[{" and not text.lstrip().startswith("{\"") or text.lstrip().startswith("["):
            try:                                     # one JSON document (array or object)
                doc = json.loads(text)
                rows = doc if isinstance(doc, list) else [doc]
            except ValueError:
                rows = []
        if not rows:
            for line in text.splitlines():
                if line.strip():
                    try:
                        rows.append(json.loads(line))
                    except ValueError:
                        continue
        for r in rows:
            try:
                evs += [x for x in convert(r) if x.account]
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
    if not evs:
        return []
    evs.sort(key=lambda x: x.t)
    t0 = evs[0].t - 24 * 20                     # start the clock 20 days earlier: past any learning period
    for x in evs:
        x.t -= t0
    return evs
