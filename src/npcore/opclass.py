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
       "terminate", "purge", "destroy", "unset", "disassociate", "deregister", "leave", "pause"}
MAKE = {"create", "attach", "put", "add", "update", "set", "enable", "register", "associate", "upload", "import",
        "write", "grant", "assign", "modify", "replace", "insert", "patch", "activate", "invite", "generate", "sign", "deploy",
        "authorize", "allow", "open", "share", "publish", "expose", "install", "promote", "change", "toggle"}
READ = {"get", "list", "describe", "read", "search", "lookup", "batchget", "head", "query", "view", "scan", "select",
        "filter", "check", "validate", "estimate", "preview", "test", "simulate", "download"}

LOGGING = ("trail", "logging", "loggroup", "logstream", "flowlog", "detector", "recorder", "configrule", "invocationlogging",
           "auditlog", "diagnosticsetting", "diagnostic", "monitor", "alarm", "insight", "guardduty", "securityhub",
           "inspector", "macie", "accessanalyzer", "sink", "logbucket", "datacollectionrule", "workspace", "sentinel",
           "eventselector", "auditconfig", "logsink", "logmetric", "alertrule", "activitylogalert", "deliverychannel",
           "querylog", "resolverquerylog", "macie", "maciesession", "actiongroup", "metricalert", "eventhub",
           "scheduledqueryrule", "watcher")
CONTROL = ("guardrail", "publicaccessblock", "encryption", "webacl", "waf", "firewall", "securitygroup", "networkacl",
           "networksecuritygroup", "securityrule", "conditionalaccess", "versioning", "objectlock", "retention", "backup",
           "replication", "branchprotection", "ruleset", "passwordpolicy", "accountpasswordpolicy", "orgpolicy",
           "organizationpolicy", "servicecontrolpolicy", "permissionboundary", "keypolicy", "keyrotation", "defender",
           "policyassignment", "lock", "vpcserviceperimeter", "serviceperimeter", "accesslevel", "dlp", "safelinks",
           "antiphish", "mfaenforcement", "securitycontact", "securitysetting", "organization")
DATA = ("managedzone", "dnszone", "bucket", "knowledgebase", "database", "dbinstance", "dbcluster", "table", "snapshot", "volume", "instance",
        "repository", "secret", "filesystem", "cluster", "storageaccount", "container", "vault", "keyvault", "key",
        "dataset", "datastore", "index", "collection", "disk", "image", "server", "virtualmachine", "agent", "model",
        "project", "subscription", "resourcegroup", "account", "domain")
IDENTITY = ("user", "role", "accesskey", "loginprofile", "group", "policyversion", "rolepolicy", "userpolicy", "grouppolicy",
            "serviceaccount", "serviceaccountkey", "serviceprincipal", "credential", "samlprovider", "openidconnectprovider",
            "oidcprovider", "federation", "identityprovider", "roleassignment", "roledefinition", "iampolicy", "policy",
            "membership", "member", "permission", "apikey", "token", "certificate", "trust", "sshpublickey")
MFA = ("mfadevice", "virtualmfadevice", "mfa", "twofactor", "2sv", "strongauth")
RUNS_CODE = ("runbook", "automationaccount", "function", "lambda", "webhook", "job", "schedule", "trigger", "workflow",
             "logicapp", "pipeline", "cloudbuild", "cloudscheduler", "eventsubscription", "deployment", "build",
             "deployifnotexists", "runcommand", "extension")
WIDE_OPEN = re.compile(r'"(cidr_?ip(v6)?|sourceaddressprefix|sourceranges?|ipv6cidrblock)"\s*:\s*\[?\s*"(0\.0\.0\.0/0|::/0|\*|internet|any)"'
                       r'|"(principal|aws)"\s*:\s*"\*"|"(publiclyaccessible|public)"\s*:\s*"?true'
                       r'|"[a-z]*(visibility|acl|grantee|uri)"\s*:\s*"[^"]*(public|allusers|authenticatedusers)', re.I)
SWITCHED_OFF = re.compile(r'"[a-z]*(enabl|status|state|mode|protection|mfadelete|logging|retention|versioning|encrypt|flowlog|'
                          r'audit|monitor|defender|firewall)[a-z]*"\s*:\s*"?(suspended|disabled|false|off|none|paused)"?', re.I)
SWITCHED_ON = re.compile(r'"[a-z]*(enabl|status|state|mode|protection|mfadelete|logging|retention|versioning|encrypt|flowlog|'
                         r'audit|monitor|defender|firewall)[a-z]*"\s*:\s*"?(enabled|true|on|active|enforced)"?', re.I)
CODE_PARAMS = re.compile(r'"(userdata|zipfile|imageuri|s3key|code|runbookcontent|script|commands)"\s*:', re.I)


def _words(op: str) -> Tuple[str, str]:
    """Verb and object (lower case, no separators) from any provider's operation name."""
    if "/" in op:                                          # Azure: Microsoft.X/resourceA/resourceB/verb
        parts = [x for x in op.split("/") if x]
        last = parts[-1].lower()
        res = parts[1:-1]
        obj = "".join(res).lower().replace(".", "")        # the whole resource path, so runbooks/draft keeps "runbook"
        if last == "action" and res:
            m = re.match(r"([a-z]+)([A-Z].*)?$", res[-1])
            low = res[-1].lower()
            verb = m.group(1) if m and m.group(2) else (low if low in OFF | MAKE | READ | {"recover", "restore", "backup"}
                                                        else "invoke")
            return verb.lower(), obj
        return {"write": "write", "delete": "delete", "read": "read"}.get(last, last), obj
    segs = [x for x in op.split(".") if x]
    name = segs[-1] if segs else op
    if re.fullmatch(r"[a-z]+", name) and len(segs) >= 2:   # lower-case dotted: v1.compute.firewalls.insert
        return name, segs[-2].lower()
    m = re.match(r"(.*?)(Created|Updated|Deleted|Enabled|Disabled|Removed|Added)$", name)
    if m and m.group(1):                                   # past tense: inboundSsoProfileCreated
        return ADJ.get(m.group(2).lower(), m.group(2).lower()), m.group(1).lower()
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
    p0 = json.dumps(params, separators=(",", ":"), default=str) if params not in (None, "", {}) else ""
    if ".logging." in op.lower() or op.lower().startswith("logging."):
        obj = "logging" + obj                              # everything inside the logging service is about logs
    pl = p0.lower()
    if verb in ("get", "describe") and ('"withdecryption":true' in pl.replace(" ", "") or
                                         re.search(r'"attribute"\s*:\s*"userdata"', pl)):
        return "data_access", f"{verb} {obj} decrypted / user data"     # secrets in parameters or startup scripts
    if verb in MAKE and re.search(r'"(allusers|allauthenticatedusers)"', pl):
        return "control_change", f"{verb} {obj} public (allUsers)"
    if verb in ("schedule", "disable") and "keydeletion" in obj + verb or op.lower() in ("schedulekeydeletion",):
        return "destructive_change", "schedule key deletion"
    if verb == "download" and _has(obj, ("log", "dump", "backup", "snapshot", "export")):
        return "data_access", f"{verb} {obj}"
    if verb in ("send", "start", "run", "invoke") and _has(obj, ("command", "session", "script")):
        return "workload_create", "remote_exec"
    if _has(obj, ("vault",)) and _has(obj, ("secret", "key", "certificate")) and \
            verb in ("read", "get", "getsecret", "recover", "restore", "backup", "invoke", "list"):
        return "data_access", f"key vault {verb} {obj}"   # secrets, keys and certificates retrieved or restored
    if verb in ("begin", "invoke", "generate") and _has(obj, ("getaccess", "disk", "listkeys", "sas")) and "access" in op.lower() + obj:
        return "data_access", f"{verb} {obj}"             # a download link to a whole disk
    if verb in ("start", "create", "write", "invoke") and _has(obj, ("packetcapture", "trafficmirror")):
        return "data_access", f"{verb} {obj} (network traffic captured)"
    if verb in MAKE and _has(obj, ("suppression",)):
        return "audit_change", f"{verb} {obj}"            # alerts suppressed
    if "listkeys" in obj or "listaccountsas" in obj or "listservicesas" in obj:
        return "data_access", f"{verb} {obj} (storage keys or SAS retrieved)"
    if verb in READ or not verb:
        return None
    p = json.dumps(params, separators=(",", ":"), default=str) if params not in (None, "", {}) else ""
    p = p.replace('\\"', '"').replace("\\\\", "")      # Azure puts the request body in an escaped JSON string
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
        if verb == "put" and "logging" in obj and params is not None and "loggingenabled" not in p0.lower():
            return "audit_change", f"{verb} {obj} emptied"
        m = SWITCHED_OFF.search(p) if p else None
        if m:
            return ("audit_change" if "log" in m.group(0).lower() or _has(obj, LOGGING) else "control_change"), \
                f"{verb} {obj} switched off ({m.group(0)[:60]})"
        if p and re.search(r'"publicaccess"\s*:\s*"(container|blob)"|"(allow[a-z]*public[a-z]*|allowsharedkeyaccess)"\s*:\s*"?true|"publicnetworkaccess"\s*:\s*"enabled"'
                           r'|"supportshttpstrafficonly"\s*:\s*"?false', p, re.I):
            return "control_change", f"{verb} {obj} opened"
        if p and WIDE_OPEN.search(p) and "egress" not in obj:   # open egress is the AWS default, not exposure
            return "control_change", f"{verb} {obj} open to the internet"
        if _has(obj, RUNS_CODE + ("instanceattribute", "functioncode")) and (CODE_PARAMS.search(p) or "code" in obj):
            return "config_change", "new_principal"           # code that will run was replaced (backdoor, startup script)
        if _has(obj, CONTROL) or _has(obj, LOGGING):        # a protective setting changed
            cidrs = re.findall(r'"cidr_?ip(?:v6)?"\s*:\s*"([^"]+)"', p, re.I)
            internal = bool(cidrs) and all(__import__("ipaddress").ip_network(c, strict=False).is_private for c in cidrs
                                           if re.fullmatch(r"[0-9a-fA-F:.]+/\d+", c))
            if "egress" in obj or internal or (p and SWITCHED_ON.search(p)):
                return None                                 # switched ON / outbound default: tightening, not evidence
            return "control_change", f"{verb} {obj} modified (direction unknown)"   # recorded, weak (minor)
        if _has(obj, MFA):
            return "config_change", "mfa_method"
        if _has(obj + op.lower(), ("accesskey", "loginprofile", "serviceaccountkey", "credential", "apikey", "sshpublickey",
                                    "token", "certificate", "password", "jwt", "signblob", "hmac")):
            return "config_change", "credential_added"
        if _has(obj, ("samlprovider", "openidconnectprovider", "oidcprovider", "federation", "identityprovider", "trust",
                      "ssoprofile", "workforcepool", "workloadidentitypool", "identitypool")):
            return "config_change", "federation"
        if _has(obj, ("policy", "roleassignment", "roledefinition", "permission", "membership", "member", "iampolicy",
                      "rolebinding", "ownership", "elevateaccess")) \
                and not _has(obj, CONTROL) and not _has(obj, LOGGING):
            return "config_change", "privilege_grant"
        if verb in ("create", "add", "register", "invite") and _has(obj, ("user", "role", "serviceaccount",
                                                                         "serviceprincipal", "group")):
            return "config_change", "new_principal"
        if verb in ("create", "write", "put", "register", "insert", "publish", "deploy", "invoke") and _has(obj, RUNS_CODE):
            return "config_change", "new_principal"
    return None


# ------------------------------------------------------------------------------------------------ 1.0.2: dotted names
# GitHub audit actions (org.saml_disabled), Okta event types (user.session.impersonation.grant), Google Workspace
# event names (2sv_disable, ADD_TRUSTED_DOMAINS): tokens split on '.', '_' and '-'; adjectives count as verbs.
ADJ_ = None
ADJ = {"elevated": "grant", "set": "set", "updated": "update", "added": "add", "disabled": "disable", "enabled": "enable", "removed": "remove", "deleted": "delete", "created": "create",
       "granted": "grant", "suspended": "suspend", "unenrolled": "unenroll", "dismissed": "dismiss"}
SEC_WORDS = ("saml", "sso", "two", "2sv", "2fa", "mfa", "factor", "oauth_app_restrictions", "app_restrictions", "secret",
             "scanning", "dependabot", "advanced_security", "code_scanning", "allow_list", "allowlist", "ip_allow",
             "protection", "ruleset", "audit", "log", "titanium", "strong", "password_policy", "enforce", "sandbox",
             "predelivery", "trusted_domain", "security", "threat", "policy", "push_protection", "vulnerability")
PRIV_WORDS = ("privilege", "admin", "role", "impersonation", "org.owner", "moderator", "super")
CRED_WORDS = ("token", "public_key", "deploy_key", "ssh_key", "api_key", "secret_key", "credential", "certificate",
              "client_secret", "personal_access_token", "pat")
SHARE_WORDS = ("forwarding_out_of_domain", "external", "public", "people_with_link", "anyone")
RISK_WORDS = ("suspicious", "gov_attack", "password_leak", "leaked", "threat", "attack_warning", "compromise")


def classify_dotted(name: str, params=None) -> Optional[Tuple[str, str]]:
    if not name:
        return None
    n = name.lower()
    toks = [ADJ.get(x, x) for x in re.split(r"[._\-\s]+", n) if x]
    verbs = [x for x in toks if x in OFF or x in MAKE or x in ("dismiss", "show", "reset", "transfer", "takeout")]
    v = verbs[-1] if verbs else ""
    p = json.dumps(params, default=str).lower() if params not in (None, "", {}) else ""
    if any(w in n for w in RISK_WORDS):
        return "idp_risk", n
    if "takeout" in n or "data_export" in n or ("export" in toks and v in ("create", "start")):
        return "data_access", n
    if any(w in n for w in ("forwarding_out_of_domain", "email_forwarding")):
        return "mail_rule", n
    if v in ("show",) and "password" in n:
        return "data_access", "password retrieval: " + n
    if v in OFF or v == "dismiss":
        if any(w in n for w in ("mfa", "factor", "2sv", "two_factor", "strong", "titanium")):
            return "config_change", "disable_mfa"
        if any(w in n for w in ("audit", "log_stream", "audit_log")):
            return "audit_change", n
        if any(w in n for w in SEC_WORDS) and not n.startswith(("hook", "user.")):
            return "control_change", n
        if any(w in n for w in ("repo.destroy", "repository.destroy", "org.delete")):
            return "destructive_change", n
        return None
    if v == "transfer" or "transfer" in n:
        return "destructive_change", n
    if v in MAKE or v in ("reset",):
        if p and SWITCHED_OFF.search(p.replace("'", '"')) and any(w in n + p for w in SEC_WORDS):
            return "control_change", n + " switched off"
        if any(w in p for w in ('"new_value": "false"', '"new_value": "disabled"', '"new_value": "off"', "allow_all",
                                 '"new_value": "true"' if "allow" in p or "reuse" in p else "@@")) and \
                any(w in n + p for w in SEC_WORDS + ("reuse", "allow")):
            return "control_change", n + " weakened"
        if any(w in n for w in ("federation", "identity provider", "identity_provider", "saml", "sso")) and \
                v in ("set", "add", "create", "update", "change", "modify"):
            return "config_change", "federation"
        if n.strip() == "authorize" or n.endswith(".authorize"):
            return "config_change", "new_principal"         # an OAuth app granted access to a user's data
        if "trusted_domain" in n and v == "add":
            return "control_change", n
        if any(w in n for w in ("mfa", "factor", "2sv")) and v in ("reset",):
            return "config_change", "mfa_method"
        if "password" in n and v == "reset":
            return "config_change", "credential_added"
        if any(w in n for w in CRED_WORDS) and v in ("create", "add", "generate", "register", "grant", "upload"):
            return "config_change", "credential_added"
        if any(w in n for w in PRIV_WORDS) or any(w in p for w in ('"role": "admin"', "super_admin", '"permission": "admin"')):
            if v in ("grant", "assign", "add", "create", "update", "set", "invite", "promote", "change", "modify"):
                return "config_change", "privilege_grant"
        if "setting" not in n and any(w in n for w in ("hook", "application", "integration", "oauth", "app")) and \
                v in ("create", "add", "install", "authorize"):
            return "config_change", "new_principal"
        if any(w in n + " " + p for w in SHARE_WORDS) and any(w in n for w in ("access", "visibility", "acl", "share", "owner")):
            return "external_share", n
    return None


# ------------------------------------------------------------------------------------------------ 1.0.2: impact
CRITICAL_DATA = ("backup", "vault", "key", "snapshot", "bucket", "storageaccount", "database", "dbinstance", "dbcluster",
                 "knowledgebase", "repository", "repo.", "filesystem", "table", "recoveryservice", "restorepoint", "secret",
                 "organization", "project", "subscription", "resourcegroup", "logs", "trail")
ADMIN_GRANTS = re.compile(r"administratoraccess|iamfullaccess|poweruseraccess|organizationaccountaccessrole|"
                          r'"action"\s*:\s*\[?\s*"(\*|iam:\*|sts:\*|\*:\*)"|roles/(owner|editor|iam\.|resourcemanager\.|'
                          r'securityadmin|cloudkms\.admin|storage\.admin)|"(owner|contributor|user access administrator)"'
                          r"|cluster-admin|super_?admin", re.I)


def critical(what: str) -> bool:
    """Deleting these loses data or recovery; deleting VMs, disks or routes is routine operations."""
    w = str(what).lower().replace(" ", "")
    return any(c in w for c in CRITICAL_DATA)


def admin_grant(params) -> bool:
    return bool(ADMIN_GRANTS.search(json.dumps(params, default=str))) if params not in (None, "", {}) else False
