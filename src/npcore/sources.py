# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.0 log adapters: GitHub, Google Workspace and Google Cloud, Kubernetes, AWS data-movement services, AI assistants
and AI agents. Everything the v0.5-v0.9 adapters read (Okta, Entra ID, Microsoft 365, CloudTrail) still goes through
them; this module adds new formats and a few fields they dropped. Standard library only.

Every action name is mapped explicitly; unlisted actions are ignored. Event kinds produced here (read by
Engine._v10_check):

    control_change     what=<control>      a security control switched off or removed (branch protection, rulesets,
                                           2FA requirement, IP allow list, security workflow not run)
    audit_change       what=<stream>       audit log streaming removed or changed (same rule as v0.6)
    destructive_change what=<action>       repository or organisation deleted, archived or removed
    protected_push     what=<branch>       a protection rule overridden to push
    config_change      what=...            new_principal (self-hosted runner, app install), disable_mfa, privilege_grant
    external_share     what=<channel>      a document or mail crosses the organisation boundary
    secret_read        what=<object>       Kubernetes secret read
    workload_create    what=privileged_pod | host_namespace | daemonset | node_port | cronjob
    forbidden          what=<verb resource> denied API request (anonymous or authenticated)
    scanner_seen       what=<tool>         a known cluster scanner ran
    data_access        what=<operation>    DataSync tasks, bucket replication, S3 batch jobs, export tasks
    object_read        what=<operation>    one object read (S3 GetObject): judged by volume
    device_code_login                      sign-in with the OAuth device-code flow
    ai_invoke          prompt, tools, in_tok, out_tok, region, inference_region; agent=True for programmatic sessions
    agent_exec         cmdline             a process command line on a host (auditd PROCTITLE / EXECVE)
    agent_tool         what=<tool>         MCP tools/call
    model_request      what=<path>         local model server request (Ollama)
"""
from __future__ import annotations

import csv
import datetime as dt
import json
import pathlib
import re
from collections import defaultdict
from typing import Iterable, List

from . import cloudlogs, okta, opclass
from .sim import Event

_t = cloudlogs._t


def _ev(t, acct, kind, sensitive=False, **attrs) -> Event:
    return Event(t, acct, kind, sensitive=sensitive, attrs=attrs)


# ------------------------------------------------------------------------------------------------ GitHub
# GitHub audit log actions: https://docs.github.com/en/organizations/keeping-your-organization-secure/
#   managing-security-settings-for-your-organization/audit-log-events-for-your-organization
GH_CONTROL = {"protected_branch.destroy", "protected_branch.update_admin_enforced", "repository_ruleset.destroy",
              "org.disable_two_factor_requirement", "business.disable_two_factor_requirement", "ip_allow_list.disable",
              "ip_allow_list_entry.destroy", "business.disable_oidc", "org.disable_saml", "business.disable_saml",
              "repository_secret_scanning_push_protection.disable", "repository_secret_scanning.disable",
              "secret_scanning.disable", "repository_vulnerability_alerts.disable", "dependabot_alerts.disable",
              "code_scanning.disable", "workflows.disable_workflow", "org.disable_member_team_creation_permission"}
GH_AUDIT = {"audit_log_streaming.destroy", "audit_log_streaming.update", "audit_log_streaming.disable"}
GH_DESTROY = {"repo.destroy", "business.remove_organization", "repo.archived", "org.delete", "repo.transfer",
              "business.delete", "repo.access"}
GH_PUSH = {"protected_branch.policy_override", "protected_branch.rejected_ref_update", "git.push.force",
           "repository_ruleset.bypass"}
GH_NEW = {"enterprise.register_self_hosted_runner", "org.register_self_hosted_runner", "repo.register_self_hosted_runner",
          "integration_installation.create", "oauth_application.create", "personal_access_token.access_granted",
          "org.add_member", "business.add_admin", "org.update_member"}


def from_github_audit(e: dict) -> List[Event]:
    a = e.get("action", "")
    t = _t(e.get("@timestamp") or e.get("created_at"))
    user = e.get("actor") or "unknown"
    ctx = {"ip": e.get("actor_ip"), "ua": e.get("user_agent"), "repo": e.get("repo") or e.get("org")}
    if a == "repo.access" and e.get("visibility") != "public":
        return []
    if a in GH_CONTROL:
        return [_ev(t, user, "control_change", True, what=a, **ctx)]
    if a in GH_AUDIT:
        return [_ev(t, user, "audit_change", True, what=a, **ctx)]
    if a in GH_DESTROY:
        return [_ev(t, user, "destructive_change", True, what=a, **ctx)]
    if a in GH_PUSH:
        return [_ev(t, user, "protected_push", True, what=e.get("branch") or e.get("name") or a, **ctx)]
    if a in GH_NEW:
        return [_ev(t, user, "config_change", True, what="new_principal", detail=a, **ctx)]
    return []


SECURITY_WORKFLOW = re.compile(r"secur|codeql|scan|sast|dast|lint|test|valid|check|audit|dependab|trivy|semgrep|snyk|gitleaks", re.I)


def github_workflows(rows: List[dict]) -> List[Event]:
    """GitHub Actions workflow_run webhooks. A security or test workflow requested for a commit but never completed
    while other workflows of the same commit did complete: the check was switched off or cancelled. Emitted at the
    time a timer would fire (one hour after the request), as a streaming deployment would."""
    req, done, actor = defaultdict(dict), defaultdict(set), {}
    for x in rows:
        w = x.get("workflow_run") or {}
        sha, name = w.get("head_sha"), w.get("name")
        if not sha or not name:
            continue
        actor[sha] = (w.get("triggering_actor") or w.get("actor") or {}).get("login", "unknown")
        if x.get("action") == "requested":
            req[sha].setdefault(name, _t(w.get("created_at")))
        elif x.get("action") == "completed":
            done[sha].add(name)
    out = []
    for sha, names in req.items():
        if not done[sha]:
            continue
        for name, t in names.items():
            if name not in done[sha] and SECURITY_WORKFLOW.search(name):
                out.append(_ev(t + 1.0, actor[sha], "control_change", True, what=f"workflow '{name}' requested, never completed"))
    return out


# ------------------------------------------------------------------------------------------------ Google
# Admin SDK Reports API activity records: https://developers.google.com/admin-sdk/reports/v1/appendix/activity/login
GWS_MFA_OFF = {"UNENROLL_USER_FROM_STRONG_AUTH", "UNENROLL_USER_FROM_TITANIUM", "ENFORCE_STRONG_AUTHENTICATION",
               "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT", "CHANGE_ALLOWED_TWO_STEP_VERIFICATION_METHODS"}
GWS_PRIV = {"ASSIGN_ROLE", "GRANT_ADMIN_PRIVILEGE", "ADD_PRIVILEGE", "CREATE_ROLE", "GRANT_DELEGATED_ADMIN_PRIVILEGES",
            "AUTHORIZE_API_CLIENT_ACCESS", "ADD_TO_TRUSTED_OAUTH2_APPS"}
SECOND_FACTORS = {"google_authenticator", "idv_preregistered_phone", "idv_any_phone", "backup_code", "security_key",
                  "internal_two_factor", "totp", "google_prompt", "phone_prompt"}


def _params(e: dict) -> dict:
    out = {}
    for p in (e.get("event") or {}).get("parameters") or []:
        out[p.get("name")] = p.get("value", p.get("multiValue", p.get("boolValue", p.get("intValue"))))
    return out


def from_gws(e: dict) -> List[Event]:
    app = (e.get("id") or {}).get("applicationName")
    t = _t((e.get("id") or {}).get("time"))
    user = (e.get("actor") or {}).get("email") or "unknown"
    ip = e.get("ipAddress")
    name = (e.get("event") or {}).get("name", "")
    p = _params(e)
    ctx = {"ip": ip, "ip_type": "residential", "ua": None, "device": None, "sid": None, "sip": ip}
    if app == "login":
        methods = p.get("login_challenge_method") or []
        methods = [methods] if isinstance(methods, str) else methods
        n2 = sum(1 for m in methods if m in SECOND_FACTORS)
        if name == "login_failure":
            if n2:                                   # password accepted, second factor failed (once per attempt)
                return [_ev(t + i / 3600, user, "mfa_push", result="deny", **ctx) for i in range(n2)]
            return [_ev(t, user, "login_failure", **ctx)]
        if name == "login_success":
            return [_ev(t, user, "login", mfa=n2 > 0, **ctx)]
        return []
    if app == "admin":
        if name in GWS_MFA_OFF and str(p.get("NEW_VALUE", "false")).lower() not in ("true", "enforced"):
            return [_ev(t, user, "config_change", True, what="disable_mfa", target=p.get("USER_EMAIL"), ip=ip)]
        if name in GWS_PRIV:
            return [_ev(t, user, "config_change", True, what="privilege_grant", target=p.get("USER_EMAIL"), ip=ip)]
    return []


def _domain(addr) -> str:
    return str(addr or "").rsplit("@", 1)[-1].lower()


def from_drive(e: dict) -> List[Event]:
    """Drive audit records as exported flat (type, name, parameters, email, timestamp)."""
    p = e.get("parameters") or {}
    t = _t(e.get("timestamp"))
    actor = e.get("email") or "unknown"
    owner, vis = p.get("owner"), p.get("visibility")
    target = p.get("target_user") or p.get("target_domain")
    crosses = vis in ("shared_externally", "public_on_the_web", "people_with_link", "public_in_the_domain_with_link") \
        or (target and owner and _domain(target) != _domain(owner))
    if not crosses or e.get("type") not in ("acl_change", "access"):
        return []
    who = owner if e.get("type") == "access" and owner else actor
    return [_ev(t, who, "external_share", True, what=f"drive {e.get('name')} {vis}", doc=p.get("doc_id"),
                dest=_domain(target) if target else vis, ip=e.get("ip_address"))]


def from_gmail(e: dict) -> List[Event]:
    """Gmail log events (BigQuery export). Outbound mail with an attachment to another domain."""
    src = (e.get("source") or {}).get("address") or (e.get("message_info") or {}).get("source", {}).get("address")
    dests = [d.get("address") for d in e.get("destination") or [] if d.get("service") == "smtp-outbound"]
    ext = [d for d in dests if _domain(d) and _domain(d) != _domain(src)]
    if not src or not ext or not (e.get("num_message_attachments") or 0):
        return []
    t = float(e["timestamp"]) / 3600 if isinstance(e.get("timestamp"), (int, float)) else _t(e.get("timestamp"))
    return [_ev(t, src, "external_share", True, what="mail with attachment", dest=_domain(ext[0]),
                nbytes=e.get("payload_size"))]


# Cloud Audit Logs: permissions that make a new resource run as a service account (iam.serviceAccounts.actAs)
GCP_ACTAS = ("cloudfunctions.functions.create", "cloudfunctions.functions.update", "compute.instances.create",
             "compute.instances.setServiceAccount", "run.services.create", "dataflow.jobs.create",
             "iam.serviceAccountKeys.create", "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.signJwt",
             "iam.serviceAccounts.actAs", "deploymentmanager.deployments.create")
GCP_PRIV = ("setIamPolicy", "resourcemanager.projects.setIamPolicy", "iam.roles.create", "iam.roles.update")


def from_gcp(e: dict) -> List[Event]:
    """Cloud Audit Logs: native LogEntry (protoPayload) or the flat field names of the Splunk add-on."""
    if "protoPayload" in e:
        pp = e["protoPayload"]
        user = (pp.get("authenticationInfo") or {}).get("principalEmail") or "unknown"
        perms = [a.get("permission", "") for a in pp.get("authorizationInfo") or []]
        sa = json.dumps(pp.get("request") or {})
        sa = re.search(r"[\w.-]+@[\w.-]+\.iam\.gserviceaccount\.com", sa)
        sa = sa.group() if sa else None
        t, ip = _t(e.get("timestamp")), (pp.get("requestMetadata") or {}).get("callerIp")
        method = pp.get("methodName", "")
    else:
        user = e.get("src_user") or e.get("data.protoPayload.authenticationInfo.principalEmail") or "unknown"
        perms = [v for k, v in e.items() if k.endswith("authorizationInfo{}.permission")]
        perms = [x for v in perms for x in (v if isinstance(v, list) else [v])]
        sa = next((v for k, v in e.items() if k.endswith("serviceAccountEmail")), None)
        t, ip = _t(e.get("_time") or e.get("timestamp") or 0), e.get("src")
        method = e.get("data.protoPayload.methodName", "")
    out = []
    if sa and sa != user and any(p in GCP_ACTAS for p in perms):
        out.append(_ev(t, user, "config_change", True, what="privilege_grant", detail=f"runs as {sa}", ip=ip))
    elif any(p.endswith(GCP_PRIV) for p in perms) or method.endswith("SetIamPolicy"):
        out.append(_ev(t, user, "config_change", True, what="privilege_grant", detail=method or perms[0], ip=ip))
    elif method:                                           # v1.1: any other method, by verb and object
        req = (e.get("protoPayload") or {}).get("request") if "protoPayload" in e else None
        out += _opclass_event(t, user, method, req, None, ip)
    return out


# ------------------------------------------------------------------------------------------------ Kubernetes
# Kubernetes audit events (audit.k8s.io/v1): https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
SCANNERS = re.compile(r"kube-hunter|kubescape|kube-bench|peirates|kubiscan|kubeletctl|botb|cdk-team|kdigger|kubesploit|"
                      r"\bnuclei\b|\bExpanse\b|\bzgrab|\bmasscan\b|\bcensys", re.I)


def from_k8s_audit(e: dict) -> List[Event]:
    if e.get("stage") not in (None, "ResponseComplete", "Panic"):
        return []
    u = e.get("user") or {}
    user = u.get("username") or "unknown"
    if user.startswith("system:") and user not in ("system:anonymous",) and "system:serviceaccount" not in user:
        return []                                       # control-plane components
    t = _t(e.get("requestReceivedTimestamp") or e.get("stageTimestamp"))
    ip = (e.get("sourceIPs") or [None])[0]
    verb, ref = e.get("verb", ""), e.get("objectRef") or {}
    res, code = ref.get("resource", ""), (e.get("responseStatus") or {}).get("code", 200)
    ua = e.get("userAgent") or ""
    ctx = {"ip": ip, "ua": ua, "ns": ref.get("namespace")}
    acct = user if user != "system:anonymous" else f"anonymous@{ip}"
    out = []
    if SCANNERS.search(ua):
        out.append(_ev(t, acct, "scanner_seen", what=SCANNERS.search(ua).group(), **ctx))
    if code in (401, 403):
        out.append(_ev(t, acct, "forbidden", what=f"{verb} {res or e.get('requestURI', '')}",
                       anonymous=user == "system:anonymous", write=verb in ("create", "update", "patch", "delete"), **ctx))
        return out
    if code >= 300:
        return out
    if res == "secrets" and verb in ("get", "list", "watch"):
        out.append(_ev(t, user, "secret_read", True, what=f"{verb} {ref.get('namespace') or '*'}/{ref.get('name') or '*'}", **ctx))
    if verb == "create":
        obj = e.get("requestObject") or {}
        spec = obj.get("spec") or {}
        pod = ((spec.get("template") or {}).get("spec") or spec) if res != "cronjobs" else \
            (((spec.get("jobTemplate") or {}).get("spec") or {}).get("template") or {}).get("spec") or {}
        priv = any(((c.get("securityContext") or {}).get("privileged") or
                    "SYS_ADMIN" in ((c.get("securityContext") or {}).get("capabilities") or {}).get("add", []))
                   for c in (pod.get("containers") or []) + (pod.get("initContainers") or []))
        hostns = any(pod.get(k) for k in ("hostPID", "hostIPC", "hostNetwork")) or \
            any("hostPath" in v for v in pod.get("volumes") or [])
        what = None
        if priv:
            what = "privileged_pod"
        elif hostns:
            what = "host_namespace"
        elif res == "daemonsets":
            what = "daemonset"
        elif res == "services" and spec.get("type") in ("NodePort", "LoadBalancer"):
            what = "node_port"
        elif res == "cronjobs":
            what = "cronjob"
        if what:
            out.append(_ev(t, user, "workload_create", True, what=what, name=ref.get("name"), **ctx))
    return out


def from_k8s_event(e: dict) -> List[Event]:
    """Core Kubernetes Event objects (kubectl get events -w -o json): a known scanner image or pod name."""
    o = e.get("object") or e
    text = " ".join(str(x) for x in (o.get("message"), (o.get("involvedObject") or {}).get("name")))
    m = SCANNERS.search(text)
    if not m:
        return []
    t = _t(o.get("lastTimestamp") or o.get("firstTimestamp") or (o.get("metadata") or {}).get("creationTimestamp"))
    ns = (o.get("involvedObject") or {}).get("namespace") or "default"
    return [_ev(t, f"cluster:{ns}", "scanner_seen", what=m.group().lower())]


# ------------------------------------------------------------------------------------------------ AWS additions
AWS_MOVE = {"createtask": "DataSync task", "startTaskExecution".lower(): "DataSync run", "putbucketreplication": "bucket replication",
            "createjob": "S3 batch job", "jobcreated": "S3 batch job", "createexporttask": "export task",
            "startexporttask": "export task", "exportsnapshot": "snapshot export", "createreplicationconfiguration": "replication"}


def aws_extra(e: dict) -> List[Event]:
    op = (e.get("eventName") or "").lower()
    if op not in AWS_MOVE and op != "getobject":
        return []
    ui = e.get("userIdentity") or {}
    user = ui.get("userName") or (ui.get("sessionContext") or {}).get("sessionIssuer", {}).get("userName") or \
        ui.get("arn") or ui.get("principalId") or ("aws-service:" + str(e.get("eventSource")))
    if e.get("errorCode"):
        return []
    t = _t(e["eventTime"])
    if op == "getobject":
        return [_ev(t, user, "object_read", what="getobject", ip=e.get("sourceIPAddress"),
                    bucket=(e.get("requestParameters") or {}).get("bucketName"))]
    return [_ev(t, user, "data_access", True, what=AWS_MOVE[op], ip=e.get("sourceIPAddress"))]


# ------------------------------------------------------------------------------------------------ AI
def _text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(_text(c.get("text") or c.get("content") or "") if isinstance(c, dict) else str(c) for c in content)
    return ""


def from_bedrock(e: dict) -> List[Event]:
    """Amazon Bedrock model invocation logs (schemaType ModelInvocationLog). The principal is the role session name;
    a session that is not a person's sign-in name (botocore-session-*, i-*, role-only) is treated as an agent."""
    arn = (e.get("identity") or {}).get("arn", "")
    who = arn.rsplit("/", 1)[-1] or "unknown"
    agent = "@" not in who
    inp, out = e.get("input") or {}, e.get("output") or {}
    body = inp.get("inputBodyJson") or {}
    msgs = body.get("messages") or []
    last_user = next((m for m in reversed(msgs) if m.get("role") == "user"), {})
    prompt = _text(last_user.get("content"))
    tools = []
    ob = out.get("outputBodyJson")
    for b in (ob if isinstance(ob, list) else [ob] if isinstance(ob, dict) else []):
        if not isinstance(b, dict):
            continue
        cb = b.get("content_block") or {}
        if cb.get("type") == "tool_use":
            tools.append((cb.get("toolUse") or cb).get("name") or cb.get("name"))
        for c in b.get("content") or []:
            if isinstance(c, dict) and c.get("type") == "tool_use":
                tools.append(c.get("name"))
    return [_ev(_t(e.get("timestamp")), who, "ai_invoke", prompt=prompt, tools=[x for x in tools if x],
                in_tok=int(inp.get("inputTokenCount") or 0), out_tok=int(out.get("outputTokenCount") or 0),
                region=e.get("region"), inference_region=e.get("inferenceRegion") or e.get("region"),
                agent=agent, app="bedrock", model=e.get("modelId"))]


def copilot_csv(path: pathlib.Path) -> List[Event]:
    """Microsoft Purview eDiscovery export of Copilot interactions (CSV). A prompt row is a Copilot item whose
    sender list starts with the user (responses start with 'Copilot in ...')."""
    out = []
    with open(path, encoding="utf-8-sig", newline="") as f:
        for r in csv.DictReader(f):
            if "Copilot" not in (r.get("Item class") or ""):
                continue
            sender = (r.get("Sender") or r.get("Sender/Author") or "").split(";")[0].strip()
            text = r.get("Subject/Title") or ""
            if "@" not in sender or not text:
                continue
            ts = r.get("Date") or r.get("Created") or r.get("Email date sent")
            try:
                t = _t(ts.replace(" ", "T"))
            except (ValueError, AttributeError):
                continue
            out.append(_ev(t, sender.lower(), "ai_invoke", prompt=text, tools=[], in_tok=0, out_tok=0, region=None,
                           inference_region=None, agent=False, app=(r.get("Item class") or "").rsplit(".", 1)[-1]))
    return out


_AUD = re.compile(r"msg=audit\((?P<ts>[^:)]+(?::\d\d)*(?:\.\d+)?)(?::\d+)?\)")


def _audit_time(s: str) -> float:
    m = _AUD.search(s)
    if not m:
        raise ValueError
    raw = m.group("ts")
    if re.match(r"^\d+(\.\d+)?$", raw):                      # raw auditd: epoch seconds
        return float(raw) / 3600
    head = raw.rsplit(":", 1)[0] if raw.count(":") > 2 else raw   # interpreted: 03/12/2026 13:47:00.893
    d = dt.datetime.strptime(head.split(".")[0], "%m/%d/%Y %H:%M:%S").replace(tzinfo=dt.timezone.utc)
    return d.timestamp() / 3600


def auditd(path: pathlib.Path) -> List[Event]:
    out = []
    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        if "type=PROCTITLE" not in line and "type=EXECVE" not in line:
            continue
        m = re.search(r"proctitle=(.*)$", line)
        cmd = m.group(1).strip() if m else " ".join(re.findall(r'a\d+="?([^" ]+)"?', line))
        if re.fullmatch(r"[0-9A-Fa-f]+", cmd or ""):           # raw auditd hex-encodes arguments with NUL separators
            cmd = bytes.fromhex(cmd).replace(b"\x00", b" ").decode(errors="replace")
        uid = re.search(r"\bauid=(\S+)", line)
        try:
            t = _audit_time(line)
        except ValueError:
            continue
        host = re.search(r"\bnode=(\S+)", line)
        out.append(_ev(t, f"{(uid.group(1) if uid else 'user')}@{host.group(1) if host else 'host'}", "agent_exec", cmdline=cmd))
    return out


def from_mcp(e: dict) -> List[Event]:
    if e.get("method") != "tools/call" or e.get("direction") != "inbound":
        return []
    name = (e.get("params") or {}).get("name")
    return [_ev(_t(e["timestamp"]), f"{e.get('host', 'host')}:{e.get('source', 'mcp')}", "agent_tool", what=name,
                tools=[name])]


_GIN = re.compile(r"\[GIN\] (\d{4}/\d\d/\d\d - \d\d:\d\d:\d\d) \| (\d+) \|[^|]*\|\s*([0-9a-fA-F.:]+) \|\s*(\w+)\s+\"([^\"]+)\"")


def ollama(path: pathlib.Path) -> List[Event]:
    out = []
    for line in pathlib.Path(path).read_text(errors="replace").splitlines():
        m = _GIN.search(line)
        if not m:
            continue
        d = dt.datetime.strptime(m.group(1), "%Y/%m/%d - %H:%M:%S").replace(tzinfo=dt.timezone.utc)
        out.append(_ev(d.timestamp() / 3600, f"client@{m.group(3)}", "model_request", what=f"{m.group(4)} {m.group(5)}",
                       status=int(m.group(2))))
    return out


# ------------------------------------------------------------------------------------------------ v1.1: by verb and object
def _aws_user(e: dict) -> str:
    ui = e.get("userIdentity") or {}
    return ui.get("userName") or (ui.get("sessionContext") or {}).get("sessionIssuer", {}).get("userName") or \
        ui.get("arn") or ui.get("principalId") or "unknown"


def _opclass_event(t, user, op, params, error, ip=None, ua=None) -> List[Event]:
    c = opclass.classify(op, params, error)
    if not c:
        return []
    kind, what = c
    return [_ev(t, user, kind, True, what=what, op=op, ip=ip, ua=ua)]


def aws_by_verb(e: dict) -> List[Event]:
    return _opclass_event(_t(e["eventTime"]), _aws_user(e), e.get("eventName", ""), e.get("requestParameters"),
                          e.get("errorCode"), e.get("sourceIPAddress"), e.get("userAgent"))


def ocsf_by_verb(e: dict) -> List[Event]:
    api = e.get("api") or {}
    actor = (e.get("actor") or {}).get("user") or {}
    req = (api.get("request") or {}).get("data")
    try:
        req = json.loads(req) if isinstance(req, str) else req
    except ValueError:
        pass
    err = (api.get("response") or {}).get("error") or None
    return _opclass_event(_t(e.get("time")), actor.get("name") or actor.get("uid") or "unknown", api.get("operation", ""),
                          req, err, (e.get("src_endpoint") or {}).get("ip"))


def from_azure_activity(e: dict) -> List[Event]:
    """Azure Activity log (subscription level): authorization.action or operationName, caller, status."""
    opn = e.get("operationName")
    op = (e.get("authorization") or {}).get("action") or ((opn or {}).get("value") if isinstance(opn, dict) else opn)
    status = e.get("status")
    status = (status or {}).get("value") if isinstance(status, dict) else status
    if str(status or "Succeeded") not in ("Succeeded", "Started", "Accepted", "Success"):
        return []
    phase = e.get("eventName")
    phase = (phase or {}).get("value") if isinstance(phase, dict) else phase
    if phase and phase not in ("EndRequest", "Write", "Delete", "Action"):
        return []                                          # BeginRequest and EndRequest describe the same call
    t = _t(e.get("eventTimestamp") or e.get("time"))
    return _opclass_event(t, e.get("caller") or "unknown", str(op or ""), e.get("properties"), None,
                          (e.get("httpRequest") or {}).get("clientIpAddress") if isinstance(e.get("httpRequest"), dict) else None)


# ------------------------------------------------------------------------------------------------ dispatch
def _entra_extra(e: dict) -> List[Event]:
    p = e.get("properties") or {}
    if str(p.get("authenticationProtocol", "")).lower() == "devicecode" and \
            int((p.get("status") or {}).get("errorCode") or 0) == 0:
        return [_ev(_t(e.get("time") or p.get("createdDateTime")), p.get("userPrincipalName") or "unknown",
                    "device_code_login", ip=p.get("ipAddress"), app=p.get("appDisplayName"))]
    return []


def convert(e: dict) -> List[Event]:
    if "preview" in e and isinstance(e.get("result"), dict):
        r = e["result"]
        if any(k.startswith("data.protoPayload") for k in r):
            return from_gcp(r)
        e = json.loads(r["_raw"]) if isinstance(r.get("_raw"), str) else r
    if e.get("schemaType") == "ModelInvocationLog":
        return from_bedrock(e)
    if e.get("apiVersion", "").startswith("audit.k8s.io"):
        return from_k8s_audit(e)
    if (e.get("object") or {}).get("kind") == "Event" or (e.get("kind") == "Event" and "involvedObject" in e):
        return from_k8s_event(e)
    if e.get("kind") == "admin#reports#activity":
        return from_gws(e)
    if "protoPayload" in e:
        return from_gcp(e)
    if "action" in e and "actor" in e and ("@timestamp" in e or "_document_id" in e or "business" in e or "org" in e) \
            and isinstance(e.get("actor"), str):
        return from_github_audit(e)
    if "parameters" in e and "email" in e and e.get("type") in ("acl_change", "access"):
        return from_drive(e)
    if "rfc2822_message_id" in e or ("destination" in e and "source" in e and "payload_size" in e):
        return from_gmail(e)
    if e.get("sourcetype") == "mcp:jsonrpc" or ("jsonrpc" in e and "direction" in e):
        return from_mcp(e)
    if "authorization" in e and "caller" in e or (isinstance(e.get("operationName"), dict) and "caller" in e):
        return from_azure_activity(e)
    if e.get("category") in ("UserRiskEvents", "RiskyUsers", "RiskyServicePrincipals") or \
            e.get("operationName") in ("User Risk Detection", "Risky user"):
        p = e.get("properties") or {}
        who = p.get("userPrincipalName") or e.get("identity") or "unknown"
        lvl = str(p.get("riskLevel") or p.get("riskLevelAggregated") or "high").lower()
        return [_ev(_t(e.get("time").replace(" ", "T")) if "/" not in str(e.get("time")) else
                    _t(__import__("datetime").datetime.strptime(e["time"], "%m/%d/%Y %I:%M:%S %p").isoformat()),
                    who, "idp_risk", severity="high" if lvl in ("high", "none", "hidden") else lvl,
                    source=f"Entra ID {p.get('riskEventType') or p.get('riskType') or 'risk detection'}")]
    if "eventType" in e and "actor" in e and isinstance(e.get("actor"), dict):
        x = okta.to_event(e, 0.0)
        return [x] if x else []
    out = []
    if "eventSource" in e and "eventName" in e:
        out += aws_extra(e)
        if (e.get("eventName") or "").lower() in AWS_MOVE or e.get("eventName") == "GetObject":
            return out
        base = cloudlogs.convert(e)
        return base if base else aws_by_verb(e)            # v1.1: unknown operations classified by verb and object
    if "api" in e and "metadata" in e:
        base = cloudlogs.convert(e)
        return base if base else ocsf_by_verb(e)
    if "properties" in e and "category" in e:
        out += _entra_extra(e)
    return out + cloudlogs.convert(e)


def _rows(text: str) -> list:
    s = text.lstrip()
    if s.startswith("["):
        try:
            return json.loads(s)
        except ValueError:
            pass
    rows = []
    for line in text.splitlines():
        if line.strip():
            try:
                rows.append(json.loads(line))
            except ValueError:
                continue
    if not rows and s.startswith("{"):
        try:
            d = json.loads(s)
            rows = d if isinstance(d, list) else [d]
        except ValueError:
            pass
    return rows


def load(paths: Iterable[pathlib.Path], shift: bool = True) -> List[Event]:
    evs: List[Event] = []
    for p in paths:
        p = pathlib.Path(p)
        if p.suffix == ".csv":
            evs += copilot_csv(p)
            continue
        text = p.read_text(errors="replace")
        if "msg=audit(" in text[:2000]:
            evs += auditd(p)
            continue
        if "[GIN]" in text or text.startswith("time=") and "level=" in text[:200]:
            evs += ollama(p)
            continue
        rows = _rows(text)
        if any(isinstance(r, dict) and "workflow_run" in r for r in rows):
            evs += github_workflows(rows)
            continue
        for r in rows:
            if not isinstance(r, dict):
                continue
            try:
                evs += [x for x in convert(r) if x.account]
            except (ValueError, KeyError, TypeError, AttributeError):
                continue
    if not evs:
        return []
    evs.sort(key=lambda x: x.t)
    if shift:
        t0 = evs[0].t - 24 * 20                # start the clock 20 days earlier: past any learning period
        for x in evs:
            x.t -= t0
    return evs
