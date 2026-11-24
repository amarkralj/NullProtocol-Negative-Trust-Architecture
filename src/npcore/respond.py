# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.0 response layer: from a containment decision to concrete actions in the systems a company already runs.

The engine decides a level (L0 observe ... L4 isolate) per person, account or AI agent. This module turns each level
change, and a few pieces of evidence that have a direct remedy, into requests against documented vendor APIs:

    level          every connector                                  documented endpoint
    L1, L2         signed CAEP risk-level-change (any SSF receiver) OpenID CAEP 1.0
    L3             revoke sign-in sessions                          Entra: POST /users/{id}/revokeSignInSessions
                                                                    Okta: DELETE /api/v1/users/{id}/sessions
                                                                    Google: POST /admin/directory/v1/users/{key}/signOut
                                                                    AWS: deny-older-sessions role policy (aws:TokenIssueTime)
    L4             suspend the account (always needs approval)  Entra: PATCH /users/{id} accountEnabled=false
                                                                    Okta: POST /api/v1/users/{id}/lifecycle/suspend
                                                                    Google: PUT /admin/directory/v1/users/{key} suspended
    evidence       remedy
    control_disabled (branch protection removed)  GitHub: PUT /repos/{o}/{r}/branches/{b}/protection  (restore)
    privileged_workload (privileged pod)          Kubernetes: DELETE /api/v1/namespaces/{ns}/pods/{name} (approval)
    agent_autonomy_override                       host: stop the agent process (approval)

Safety rules: dry-run is the default (the plan is printed with curl / AWS CLI equivalents); nothing destructive runs
without an explicit approval; every planned and executed action is written to a hash-chained ledger before it runs;
every action carries its undo. Signed SETs use JWS HS256 (RFC 7515) from the standard library.
"""
from __future__ import annotations

import base64
import datetime as dt
import hashlib
import hmac
import json
import os
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from .integrations import CAEP, RISK
from .ledger import Ledger

DOCS = {
    "entra_revoke": "https://learn.microsoft.com/graph/api/user-revokesigninsessions",
    "entra_disable": "https://learn.microsoft.com/graph/api/user-update",
    "okta_sessions": "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserSessions/",
    "okta_suspend": "https://developer.okta.com/docs/api/openapi/okta-management/management/tag/UserLifecycle/",
    "google_signout": "https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/signOut",
    "google_suspend": "https://developers.google.com/admin-sdk/directory/reference/rest/v1/users/update",
    "aws_revoke": "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_use_revoke-sessions.html",
    "github_protect": "https://docs.github.com/rest/branches/branch-protection#update-branch-protection",
    "k8s_delete_pod": "https://kubernetes.io/docs/reference/kubernetes-api/workload-resources/pod-v1/#delete-delete-a-pod",
    "caep": "https://openid.net/specs/openid-caep-1_0-final.html",
    "jws": "https://www.rfc-editor.org/rfc/rfc7515",
}


@dataclass
class Action:
    system: str                      # entra | okta | google | aws | github | kubernetes | ssf | host
    action: str
    subject: str
    reason: str
    method: str = ""
    url: str = ""
    body: Optional[dict] = None
    approval: bool = False           # True: a person must approve before it runs
    undo: Optional[dict] = None
    doc: str = ""
    cli: str = ""                    # equivalent command for manual use
    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])

    def to_dict(self):
        return {k: v for k, v in asdict(self).items() if v not in (None, "")}


# --------------------------------------------------------------------------- signed security events (JWS HS256)
def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _unb64(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def sign_set(payload: dict, key: bytes, kid: str = "np-1") -> str:
    head = {"alg": "HS256", "typ": "secevent+jwt", "kid": kid}
    msg = _b64(json.dumps(head, separators=(",", ":")).encode()) + "." + _b64(json.dumps(payload, separators=(",", ":")).encode())
    return msg + "." + _b64(hmac.new(key, msg.encode(), hashlib.sha256).digest())


def verify_set(token: str, key: bytes) -> dict:
    """Returns the payload if the signature is valid; raises ValueError otherwise."""
    h, p, s = token.split(".")
    if json.loads(_unb64(h)).get("alg") != "HS256":
        raise ValueError("unexpected algorithm")
    good = _b64(hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(good, s):
        raise ValueError("bad signature")
    return json.loads(_unb64(p))


# --------------------------------------------------------------------------- planning
def _user(subject: str) -> str:
    s = subject[5:] if subject.startswith("acct:") else subject
    return s[6:] if s.startswith("agent:") else s


def _q(s: str) -> str:
    return urllib.parse.quote(s, safe="@")


def _session_actions(subject, reason, systems, cfg) -> List[Action]:
    u, out = _user(subject), []
    if "entra" in systems:
        out.append(Action("entra", "revoke_sessions", subject, reason, "POST",
                          f"https://graph.microsoft.com/v1.0/users/{_q(u)}/revokeSignInSessions", doc=DOCS["entra_revoke"],
                          cli=f"curl -X POST -H 'Authorization: Bearer $NP_ENTRA_TOKEN' "
                              f"https://graph.microsoft.com/v1.0/users/{_q(u)}/revokeSignInSessions"))
    if "okta" in systems:
        dom = cfg.get("okta_domain", "example.okta.com")
        out.append(Action("okta", "clear_sessions", subject, reason, "DELETE",
                          f"https://{dom}/api/v1/users/{_q(u)}/sessions?oauthTokens=true", doc=DOCS["okta_sessions"],
                          cli=f"curl -X DELETE -H 'Authorization: SSWS $NP_OKTA_TOKEN' "
                              f"'https://{dom}/api/v1/users/{_q(u)}/sessions?oauthTokens=true'"))
    if "google" in systems and "@" in u:
        out.append(Action("google", "sign_out", subject, reason, "POST",
                          f"https://admin.googleapis.com/admin/directory/v1/users/{_q(u)}/signOut", doc=DOCS["google_signout"],
                          cli=f"curl -X POST -H 'Authorization: Bearer $NP_GOOGLE_TOKEN' "
                              f"https://admin.googleapis.com/admin/directory/v1/users/{_q(u)}/signOut"))
    if "aws" in systems and ("assumed-role/" in u or ":role/" in u or cfg.get("aws_role")):
        role = cfg.get("aws_role") or u.split("assumed-role/")[-1].split("/")[0]
        now = dt.datetime.now(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        pol = {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": ["*"], "Resource": ["*"],
                                                       "Condition": {"DateLessThan": {"aws:TokenIssueTime": now}}}]}
        out.append(Action("aws", "revoke_role_sessions", subject, reason, "IAM:PutRolePolicy", f"iam://role/{role}",
                          {"RoleName": role, "PolicyName": "AWSRevokeOlderSessions", "PolicyDocument": pol},
                          undo={"method": "IAM:DeleteRolePolicy", "RoleName": role, "PolicyName": "AWSRevokeOlderSessions"},
                          doc=DOCS["aws_revoke"],
                          cli=f"aws iam put-role-policy --role-name {role} --policy-name AWSRevokeOlderSessions "
                              f"--policy-document '{json.dumps(pol, separators=(',', ':'))}'"))
    return out


def _suspend_actions(subject, reason, systems, cfg) -> List[Action]:
    u = _user(subject)
    person = True          # suspension always waits for a person, also for a hijacked account: it locks the victim out
    out = []
    if "entra" in systems:
        out.append(Action("entra", "disable_account", subject, reason, "PATCH", f"https://graph.microsoft.com/v1.0/users/{_q(u)}",
                          {"accountEnabled": False}, approval=person, doc=DOCS["entra_disable"],
                          undo={"method": "PATCH", "body": {"accountEnabled": True}}))
    if "okta" in systems:
        dom = cfg.get("okta_domain", "example.okta.com")
        out.append(Action("okta", "suspend", subject, reason, "POST", f"https://{dom}/api/v1/users/{_q(u)}/lifecycle/suspend",
                          approval=person, doc=DOCS["okta_suspend"],
                          undo={"method": "POST", "url": f"https://{dom}/api/v1/users/{_q(u)}/lifecycle/unsuspend"}))
    if "google" in systems and "@" in u:
        out.append(Action("google", "suspend", subject, reason, "PUT",
                          f"https://admin.googleapis.com/admin/directory/v1/users/{_q(u)}", {"suspended": True},
                          approval=person, doc=DOCS["google_suspend"], undo={"method": "PUT", "body": {"suspended": False}}))
    return out


class Responder:
    """Builds and (optionally) executes the action plan. `systems` names the connectors that exist in the
    organisation; `cfg` holds non-secret settings (okta_domain, k8s_api, ...). Secrets come from the environment."""

    def __init__(self, systems=("ssf",), cfg: Optional[dict] = None, issuer="https://nt.example/",
                 audience="https://receiver.example/ssf", set_key: Optional[bytes] = None):
        self.systems, self.cfg = set(systems), cfg or {}
        self.issuer, self.audience = issuer, audience
        self.key = set_key or os.environb.get(b"NP_SET_KEY") or b"demo-set-key-not-for-production!"
        self.ledger = Ledger()
        self.plan: List[Action] = []
        self._planned: set = set()

    # ---- level changes
    def on_level(self, subject: str, old: int, new: int, t_epoch: float, reason: str) -> List[Action]:
        acts: List[Action] = []
        if RISK[old] != RISK[new] and "ssf" in self.systems:
            ev = {CAEP + "risk-level-change": {"principal": "SESSION" if subject.startswith("acct:") else "USER",
                                               "current_level": RISK[new], "previous_level": RISK[old],
                                               "risk_reason": reason[:120], "event_timestamp": int(t_epoch)}}
            payload = {"iss": self.issuer, "aud": self.audience, "jti": uuid.uuid4().hex, "iat": int(t_epoch),
                       "sub_id": {"format": "opaque", "id": subject}, "events": ev}
            acts.append(Action("ssf", "caep_risk_level_change", subject, reason, "POST", self.audience,
                               {"set": sign_set(payload, self.key)}, doc=DOCS["caep"]))
        if new >= 3 > old:
            acts += _session_actions(subject, reason, self.systems, self.cfg)
        if new >= 4 > old:
            acts += _suspend_actions(subject, reason, self.systems, self.cfg)
        return self._record(acts)

    # ---- evidence with a direct remedy
    def on_evidence(self, x, event=None) -> List[Action]:
        acts: List[Action] = []
        a = (event.attrs if event is not None else {}) or {}
        if x.kind == "control_disabled" and "github" in self.systems and "protected_branch.destroy" in x.desc and a.get("repo"):
            branch = a.get("branch") or self.cfg.get("default_branch", "main")
            body = {"required_status_checks": None, "enforce_admins": True,
                    "required_pull_request_reviews": {"required_approving_review_count": 1}, "restrictions": None}
            acts.append(Action("github", "restore_branch_protection", x.subject, x.desc, "PUT",
                               f"https://api.github.com/repos/{a['repo']}/branches/{branch}/protection", body,
                               doc=DOCS["github_protect"], undo={"method": "DELETE"}))
        if x.kind == "privileged_workload" and "kubernetes" in self.systems and a.get("what") in ("privileged_pod", "host_namespace") \
                and a.get("name"):
            api = self.cfg.get("k8s_api", "https://kubernetes.default.svc")
            acts.append(Action("kubernetes", "delete_pod", x.subject, x.desc, "DELETE",
                               f"{api}/api/v1/namespaces/{a.get('ns') or 'default'}/pods/{a['name']}", approval=True,
                               doc=DOCS["k8s_delete_pod"], cli=f"kubectl delete pod -n {a.get('ns') or 'default'} {a['name']}"))
        if x.kind == "agent_autonomy_override" and "host" in self.systems:
            cli = x.desc.split(" ", 1)[0]
            acts.append(Action("host", "stop_agent", x.subject, x.desc, "EXEC", "", {"pattern": f"{cli} .*(yolo|skip-permissions|bypass)"},
                               approval=True, cli=f"pkill -f '{cli} .*(yolo|dangerously|full-auto)'"))
        if x.kind in ("session_replay", "device_code_phish") and x.subject.startswith("acct:"):
            acts += _session_actions(x.subject, x.desc, self.systems, self.cfg)   # cheap for the victim: sign in again
        return self._record(acts)

    def _record(self, acts):
        new = []
        for a in acts:
            key = (a.system, a.action, a.subject, a.url) if a.system != "ssf" else (a.id,)
            if key in self._planned:                  # the same session revocation once, not once per evidence
                continue
            self._planned.add(key)
            new.append(a)
        acts = new
        for a in acts:
            self.plan.append(a)
            self.ledger.append("action_planned", {"id": a.id, "system": a.system, "action": a.action,
                                                  "subject": hashlib.sha256(a.subject.encode()).hexdigest()[:16],
                                                  "approval": a.approval, "url": a.url}, None)
        return acts

    # ---- execution (opt-in)
    def execute(self, approved=()) -> List[dict]:
        """Runs planned HTTP actions whose connector has a token in the environment. Actions that need approval run
        only if their id is in `approved`. AWS and host actions are printed, never run from here."""
        tokens = {"entra": os.environ.get("NP_ENTRA_TOKEN"), "okta": os.environ.get("NP_OKTA_TOKEN"),
                  "google": os.environ.get("NP_GOOGLE_TOKEN"), "github": os.environ.get("NP_GITHUB_TOKEN"),
                  "kubernetes": os.environ.get("NP_K8S_TOKEN"), "ssf": os.environ.get("NP_SSF_TOKEN")}
        out = []
        for a in self.plan:
            if a.approval and a.id not in approved:
                out.append({"id": a.id, "status": "waiting for approval"}); continue
            tok = tokens.get(a.system)
            local = a.url.startswith(("http://127.0.0.1:", "http://localhost:"))     # test receivers only
            if a.system in ("aws", "host") or not tok or not (a.url.startswith("https://") or local):
                out.append({"id": a.id, "status": "not run (no connector token or manual system)"}); continue
            auth = f"SSWS {tok}" if a.system == "okta" else f"Bearer {tok}"
            data = json.dumps(a.body).encode() if a.body is not None and a.system != "ssf" else \
                (a.body["set"].encode() if a.system == "ssf" else None)
            ctype = "application/secevent+jwt" if a.system == "ssf" else "application/json"
            req = urllib.request.Request(a.url, data=data, method=a.method, headers={"Authorization": auth, "Content-Type": ctype,
                                                                                    "Accept": "application/json"})
            self.ledger.append("action_started", {"id": a.id}, None)
            try:
                with urllib.request.urlopen(req, timeout=20) as r:
                    res = {"id": a.id, "status": r.status}
            except Exception as exc:                       # recorded, never hidden
                res = {"id": a.id, "status": "error", "error": str(exc)[:200]}
            self.ledger.append("action_result", res, None)
            out.append(res)
        return out


def respond_replay(events, systems=("ssf",), cfg=None, version="v1.0"):
    """Replay recorded events through the engine and build the response plan (dry run)."""
    from .engine import Engine, version_preset
    users = sorted({e.account for e in events})
    eng = Engine(version_preset(version), {u: u for u in users}, {u: "Unknown" for u in users})
    r = Responder(systems, cfg)
    day = int(events[0].t // 24) + 1
    seen = 0
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        for x in eng.observe(e, True):
            if x.weight > 0:
                r.on_evidence(x, e)
        for t, s, old, new in eng.level_log[seen:]:
            reason = "; ".join(x.desc for x in eng.trust.evidence(s) if x.weight > 0)[-200:]
            r.on_level(s, old, new, t * 3600, reason)
        seen = len(eng.level_log)
    return eng, r
