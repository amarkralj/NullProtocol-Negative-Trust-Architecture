# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Okta System Log adapter (v0.5): Okta events -> engine events.

Okta System Log is the audit log every Okta tenant produces (JSON, one object per event). The mapping uses
eventType, outcome.result, actor, target, client (IP, user agent, location), authenticationContext
(externalSessionId) and debugContext.debugData. Used to test the engine on real recorded attack logs from
splunk/attack_data (see scripts/fetch_splunk_attack_data.py and scripts/run_splunk_okta.py).

    user.session.start, user.authentication.sso, policy.evaluate_sign_on (success) -> login
        (device = Okta device token hash or user agent; session = externalSessionId; 1FA rule -> no MFA)
    user.session.start / user.authentication.* failures, user.account.lock      -> login_failure
    user.authentication.auth_via_mfa failure, user.mfa.okta_verify.deny_push   -> mfa_push deny
    user.authentication.auth_via_mfa success                                     -> mfa_push approve
    system.idp.lifecycle.create / activate                                       -> config_change add_identity_provider
    system.api_token.create                                                      -> config_change add_admin_api_token
    user.mfa.factor.deactivate, user.mfa.factor.reset_all                        -> config_change disable_mfa
    device.enrollment.create, user.mfa.factor.activate                           -> mfa_enroll
    security.threat.detected, user.account.report_suspicious_activity_by_enduser -> idp_risk
    app.generic.unauth_app_access_attempt                                        -> app_denied
"""
from __future__ import annotations

import datetime as dt
import json
import pathlib
from typing import Iterable, List, Optional

from .sim import Event

LOGIN_OK = {"user.session.start", "user.authentication.sso", "policy.evaluate_sign_on"}
AUTH_FAIL = {"user.session.start", "user.authentication.sso", "user.authentication.verify",
             "user.authentication.authenticate", "user.account.lock"}


def _t(ts: str) -> float:
    return dt.datetime.fromisoformat(ts.replace("Z", "+00:00")).timestamp() / 3600


def _actor(e: dict) -> Optional[str]:
    return (e.get("actor") or {}).get("alternateId")


def _target_user(e: dict) -> Optional[str]:
    for t in e.get("target") or []:
        if t.get("type") == "User":
            return t.get("alternateId")
    return None


def to_event(e: dict, t0: float) -> Optional[Event]:
    et = e.get("eventType", "")
    res = (e.get("outcome") or {}).get("result", "")
    user = _actor(e)
    if not user:
        return None
    t = _t(e["published"]) - t0
    c = e.get("client") or {}
    g = c.get("geographicalContext") or {}
    geo = g.get("geolocation") or {}
    ua = (c.get("userAgent") or {}).get("rawUserAgent")
    dbg = (e.get("debugContext") or {}).get("debugData") or {}
    sid = (e.get("authenticationContext") or {}).get("externalSessionId")
    ip = c.get("ipAddress")
    ctx = {"ip": ip, "ip_type": "residential", "country": g.get("country"), "lat": geo.get("lat"), "lon": geo.get("lon"),
           "sid": sid, "sip": ip, "ua": ua, "device": dbg.get("dtHash") or ua, "okta_event": et}
    if et in LOGIN_OK and res in ("SUCCESS", "ALLOW"):
        one_factor = any((tg.get("detailEntry") or {}).get("policyRuleFactorMode") == "1FA" for tg in e.get("target") or [])
        return Event(t, user, "login", attrs=dict(ctx, mfa=not one_factor))
    if et in AUTH_FAIL and res in ("FAILURE", "DENY"):
        return Event(t, user, "login_failure", attrs=ctx)
    if et in ("user.authentication.auth_via_mfa", "user.mfa.okta_verify.deny_push"):
        return Event(t, user, "mfa_push", attrs=dict(ctx, result="approve" if res == "SUCCESS" else "deny"))
    if et in ("system.idp.lifecycle.create", "system.idp.lifecycle.activate"):
        return Event(t, user, "config_change", sensitive=True, attrs=dict(ctx, what="add_identity_provider"))
    if et == "system.api_token.create":
        return Event(t, user, "config_change", sensitive=True, attrs=dict(ctx, what="add_admin_api_token"))
    if et in ("user.mfa.factor.deactivate", "user.mfa.factor.reset_all"):
        return Event(t, user, "config_change", sensitive=True, attrs=dict(ctx, what="disable_mfa", target=_target_user(e)))
    if et in ("device.enrollment.create", "user.mfa.factor.activate"):
        return Event(t, user, "mfa_enroll", attrs=ctx)
    if et == "security.threat.detected":
        return Event(t, user, "idp_risk", attrs=dict(ctx, severity="high", source="Okta ThreatInsight"))
    if et == "user.account.report_suspicious_activity_by_enduser":
        return Event(t, user, "idp_risk", attrs=dict(ctx, severity="high", source="user reported suspicious activity"))
    if et == "app.generic.unauth_app_access_attempt":
        return Event(t, user, "app_denied", attrs=ctx)
    return None


def from_log_analytics(r: dict) -> dict:
    """Okta System Log as stored by Microsoft Sentinel (table Okta_CL: flattened columns with type suffixes)."""
    def g(k):
        v = r.get(k)
        return None if v in ("", "null", None) else v

    def num(k):
        v = g(k)
        try:
            return float(v) if v is not None else None
        except ValueError:
            return None
    targets = g("target_s")
    try:
        targets = json.loads(targets) if targets else []
    except ValueError:
        targets = []
    return {"eventType": g("eventType_s") or "", "published": g("published_t") or g("TimeGenerated"),
            "outcome": {"result": g("outcome_result_s") or ""},
            "actor": {"alternateId": g("actor_alternateId_s"), "type": g("actor_type_s")},
            "client": {"ipAddress": g("client_ipAddress_s"), "userAgent": {"rawUserAgent": g("client_userAgent_rawUserAgent_s")},
                       "geographicalContext": {"country": g("client_geographicalContext_country_s"),
                                               "geolocation": {"lat": num("client_geographicalContext_geolocation_lat_d"),
                                                               "lon": num("client_geographicalContext_geolocation_lon_d")}}},
            "authenticationContext": {"externalSessionId": g("authenticationContext_externalSessionId_s")},
            "debugContext": {"debugData": {"dtHash": g("debugContext_debugData_deviceFingerprint_g")}},
            "target": targets if isinstance(targets, list) else []}


def _read(p) -> list:
    text = pathlib.Path(p).read_text()
    if text.lstrip().startswith("["):                     # JSON array (Sentinel export)
        rows = json.loads(text)
        return [from_log_analytics(r) if "eventType_s" in r else r for r in rows]
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def load(paths: Iterable[pathlib.Path]) -> List[Event]:
    raw = []
    for p in paths:
        raw += [r for r in _read(p) if r.get("published")]
    raw.sort(key=lambda e: e["published"])
    t0 = _t(raw[0]["published"]) - 24 * 20 if raw else 0.0     # start the clock 20 days earlier: past any learning period
    evs = [to_event(e, t0) for e in raw]
    return [e for e in evs if e is not None]
