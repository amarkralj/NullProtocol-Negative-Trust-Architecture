# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.1: classify a cloud control-plane operation by what it does, not by its name.

v1.0 mapped every operation explicitly and dropped the rest; on unseen data that caught 5 of 23 attack datasets,
mostly because the operations were simply not on a list (results/v10_holdout_run.json). Here an operation is split into
a verb and an object, the same way for all three big clouds:

    AWS CloudTrail   eventName   DeleteGuardrail, PutBucketVersioning, AuthorizeSecurityGroupIngress
    Azure Activity   operation   Microsoft.Automation/automationAccounts/runbooks/write
    Google Cloud     methodName  google.iam.admin.v1.DeleteRole, SetIamPolicy

and (verb class, object class) decides the event:

    switch off / delete  + logging or detection object  -> audit_change          (audit tampering)
    switch off / delete  + protective control           -> control_change        (control disabled)
    a setting changed to Suspended / Disabled / false   -> control_change
    open a network rule to the whole internet            -> control_change
    delete / terminate   + data or workload object      -> destructive_change
    create / attach / put + identity or credential       -> config_change (credential_added | privilege_grant |
                                                           mfa_method | new_principal)
    switch off / delete  + MFA                           -> config_change disable_mfa
    create               + automation that runs code     -> config_change new_principal (runbooks, functions, ...)

Read-only verbs and everything else return None (the existing discovery-by-volume rule still sees denied reads).
The vocabulary is fixed in this file and was written from the providers' naming conventions, not from test logs.
"""
from __future__ import annotations

import json
import re
from typing import Optional, Tuple

OFF = {"delete", "disable", "deactivate", "stop", "remove", "detach", "suspend", "unenroll", "unenable", "cancel",
       "terminate", "purge", "destroy", "unset", "disassociate", "deregister"}
MAKE = {"create", "attach", "put", "add", "update", "set", "enable", "register", "associate", "upload", "import",
        "write", "grant", "assign", "modify", "replace", "insert", "patch", "activate", "invite", "generate", "sign",
        "authorize", "allow", "open", "share", "publish", "expose"}
READ = {"get", "list", "describe", "read", "search", "lookup", "batchget", "head", "query", "view", "scan", "select",
        "filter", "check", "validate", "estimate", "preview", "test", "simulate", "download"}

LOGGING = ("trail", "logging", "loggroup", "logstream", "flowlog", "detector", "recorder", "configrule", "invocationlogging",
           "auditlog", "diagnosticsetting", "diagnostic", "monitor", "alarm", "insight", "guardduty", "securityhub",
           "inspector", "macie", "accessanalyzer", "sink", "logbucket", "datacollectionrule", "workspace", "sentinel",
           "eventselector", "auditconfig", "logsink", "logmetric", "alertrule", "activitylogalert")
CONTROL = ("guardrail", "publicaccessblock", "encryption", "webacl", "waf", "firewall", "securitygroup", "networkacl",
           "networksecuritygroup", "securityrule", "conditionalaccess", "versioning", "objectlock", "retention", "backup",
           "replication", "branchprotection", "ruleset", "passwordpolicy", "accountpasswordpolicy", "orgpolicy",
           "organizationpolicy", "servicecontrolpolicy", "permissionboundary", "keypolicy", "keyrotation", "defender",
           "policyassignment", "lock", "vpcserviceperimeter", "serviceperimeter", "accesslevel", "dlp", "safelinks",
           "antiphish", "mfaenforcement", "securitycontact", "securitysetting")
DATA = ("bucket", "knowledgebase", "database", "dbinstance", "dbcluster", "table", "snapshot", "volume", "instance",
        "repository", "secret", "filesystem", "cluster", "storageaccount", "container", "vault", "keyvault", "key",
        "dataset", "datastore", "index", "collection", "disk", "image", "server", "virtualmachine", "agent", "model",
        "project", "subscription", "resourcegroup", "account", "domain")
IDENTITY = ("user", "role", "accesskey", "loginprofile", "group", "policyversion", "rolepolicy", "userpolicy", "grouppolicy",
            "serviceaccount", "serviceaccountkey", "serviceprincipal", "credential", "samlprovider", "openidconnectprovider",
            "oidcprovider", "federation", "identityprovider", "roleassignment", "roledefinition", "iampolicy", "policy",
            "membership", "member", "permission", "apikey", "token", "certificate", "trust", "sshpublickey")
MFA = ("mfadevice", "virtualmfadevice", "mfa", "twofactor", "2sv", "strongauth")
RUNS_CODE = ("runbook", "automationaccount", "function", "lambda", "webhook", "job", "schedule", "trigger", "workflow",
             "logicapp", "pipeline", "cloudbuild", "cloudscheduler", "eventsubscription", "deployment")
WIDE_OPEN = re.compile(r'"(cidrIp|CidrIp|cidrIpv6|sourceAddressPrefix|sourceRanges?)"\s*:\s*\[?\s*"(0\.0\.0\.0/0|::/0|\*|Internet|Any)"')
SWITCHED_OFF = re.compile(r'"(Status|status|state|State|enabled|Enabled|enable|mode)"\s*:\s*"?(Suspended|Disabled|disabled|false|Off|off|None)"?')


def _words(op: str) -> Tuple[str, str]:
    """Verb and object (lower case, no separators) from any provider's operation name."""
    if "/" in op:                                          # Azure: Microsoft.X/resourceA/resourceB/verb
        parts = [p for p in op.split("/") if p]
        verb = parts[-1].lower()
        if verb == "action" and len(parts) >= 2:           # .../listKeys/action -> verb from the last resource name
            m = re.match(r"([a-z]+)([A-Z].*)?", parts[-2])
            return (m.group(1).lower() if m else parts[-2].lower()), (m.group(2) or parts[-3] if m else "").lower()
        obj = parts[-2] if len(parts) >= 2 else ""
        return {"write": "write", "delete": "delete", "read": "read"}.get(verb, verb), obj.lower().rstrip("s")
    name = op.rsplit(".", 1)[-1]                           # GCP: google.iam.admin.v1.DeleteRole -> DeleteRole
    m = re.match(r"([A-Za-z][a-z]+)(.*)", name)
    if not m:
        return "", ""
    verb, rest = m.group(1).lower(), m.group(2)
    rest = re.sub(r"\d{8}(v\d+)?$", "", rest)              # CloudTrail API versions: DeleteGuardrail20230601
    return verb, rest.replace("_", "").lower()


def _has(obj: str, vocab) -> bool:
    return any(v in obj for v in vocab)


def classify(op: str, params=None, error: Optional[str] = None) -> Optional[Tuple[str, str]]:
    """(event kind, what) or None."""
    if not op:
        return None
    if error:                                              # denied: only attempts to tamper, disable or destroy count
        c = classify(op, params, None)
        if c and c[0] in ("audit_change", "control_change", "destructive_change"):
            return "denied_change", f"{c[0]}|{c[1]}"
        return None
    verb, obj = _words(op)
    if verb in READ or not verb:
        return None
    p = json.dumps(params, separators=(",", ":"), default=str) if params not in (None, "", {}) else ""
    if verb in OFF or verb == "unenable":
        if _has(obj, MFA):
            return "config_change", "disable_mfa"
        if _has(obj, LOGGING):
            return "audit_change", f"{verb} {obj}"
        if _has(obj, CONTROL):
            return "control_change", f"{verb} {obj}"
        if _has(obj, DATA) and verb in ("delete", "terminate", "purge", "destroy", "remove"):
            return "destructive_change", f"{verb} {obj}"
        if _has(obj, IDENTITY):                             # removing a user or role is administration, not an attack
            return None
        return None
    if verb in MAKE:
        if p and SWITCHED_OFF.search(p) and (_has(obj, LOGGING) or _has(obj, CONTROL)):
            return ("audit_change" if _has(obj, LOGGING) else "control_change"), f"{verb} {obj} switched off"
        if p and WIDE_OPEN.search(p):
            return "control_change", f"{verb} {obj} open to the internet"
        if _has(obj, CONTROL) or _has(obj, LOGGING):        # a protective setting changed, not switched off: unknown
            return None                                     # direction (tightened or loosened) -> no evidence
        if _has(obj, MFA):
            return "config_change", "mfa_method"
        if _has(obj, ("accesskey", "loginprofile", "serviceaccountkey", "credential", "apikey", "sshpublickey", "token",
                      "certificate", "password")):
            return "config_change", "credential_added"
        if _has(obj, ("samlprovider", "openidconnectprovider", "oidcprovider", "federation", "identityprovider", "trust")):
            return "config_change", "federation"
        if _has(obj, ("policy", "roleassignment", "roledefinition", "permission", "membership", "member", "iampolicy")) \
                and not _has(obj, CONTROL) and not _has(obj, LOGGING):
            return "config_change", "privilege_grant"
        if verb in ("create", "add", "register", "invite") and _has(obj, ("user", "role", "serviceaccount",
                                                                         "serviceprincipal", "group")):
            return "config_change", "new_principal"
        if verb in ("create", "write", "put", "register") and _has(obj, RUNS_CODE):
            return "config_change", "new_principal"
    return None
