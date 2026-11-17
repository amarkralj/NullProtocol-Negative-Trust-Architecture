# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Replay recorded cloud attack logs from splunk/attack_data (Microsoft Entra ID, Microsoft 365, AWS CloudTrail,
Google Workspace) through the engine (v0.5 and v0.6). Writes results/splunk_cloud.json.

The expected detection of each dataset follows from its name with the rules below, written before the first run.
Datasets about e-mail content (phishing), container images, code deployment or vendor-generated risk scores are out
of scope for an insider-threat engine and are listed, not scored.
"""
import json, pathlib
from collections import defaultdict
from npcore import cloudlogs
from npcore.engine import Engine, version_preset
from npcore.anon import pseudonymize

RULES = [  # (name keywords, expected evidence kinds) - first match wins
    (("gsuite", "gdrive", "suspect_email", "ecr_", "risk_dataset", "exfil_risk_events", "updatelambda", "startup_script",
      "copilot", "defender", "various_alerts", "azure_workload_events", "o365_various"), None),
    (("denied_mfa", "failed_mfa", "mfasweep", "mfa_login_failed"), {"mfa_fatigue", "brute_force"}),
    (("spray", "brute", "failed_auth", "failed_console", "login_failure", "lockout", "sso_logon_errors",
      "high_number", "multiple_users_from_ip"), {"password_spray", "brute_force"}),
    (("concurrent_sessions", "different_ips", "multiple_appids", "multiple_city"), {"session_replay", "impossible_travel"}),
    (("cloudtrail", "detector", "log_group", "security_services", "_acl", "bucketlifecycle", "advanced_audit",
      "blockconsent", "safelinks"), {"audit_tamper"}),
    (("forwarding", "inbox_rule", "transport_rule", "mailflow"), {"mail_forwarding"}),
    (("export", "pst", "content_search", "sharepoint_search", "mailbox_access", "mailboxes_accessed", "snapshot",
      "ami_shared", "public_bucket", "secrets", "getpassworddata", "cloudwatch_logs", "sus_file", "s3_file_encryption",
      "kms_key", "graph_mailbox", "ews_mailbox", "mail_read"), {"bulk_data_access"}),
    (("discovery", "excessive_list", "accessdenied", "security_scanner", "brute_force"), {"discovery"}),
    (("alert", "risky"), {"idp_risk"}),
    (("",), {"identity_config_change", "new_principal"}),   # role, consent, credential, federation, MFA method ...
]
ROOT = pathlib.Path("data/splunk_attack_data/attack_techniques")
SIGNAL_KINDS = {"password_spray", "brute_force", "mfa_fatigue", "session_replay", "impossible_travel", "audit_tamper",
                "mail_forwarding", "bulk_data_access", "discovery", "idp_risk", "identity_config_change", "new_principal",
                "account_takeover_reset", "no_mfa_login"}


def expected(name):
    for keys, exp in RULES:
        if any(k in name for k in keys):
            return exp


def family(name):
    if name.startswith(("gsuite", "gdrive")):
        return "Google Workspace"
    if name.startswith("azure"):
        return "Microsoft Entra ID"
    if name.startswith(("o365", "m365")) or any(k in name for k in ("full_access", "rights_delegation", "impersonation",
                                                                     "transport_rule")):
        return "Microsoft 365"
    return "AWS CloudTrail"


def replay(events, version):
    users = sorted({e.account for e in events})
    eng = Engine(version_preset(version), {u: u for u in users}, {u: "Unknown" for u in users})
    kinds = defaultdict(set)
    day = int(events[0].t // 24) + 1
    for e in events:
        while e.t >= day * 24:
            eng.end_of_day(day); day += 1
        for x in eng.observe(e, True):
            if x.weight > 0:
                kinds[x.kind].add(x.subject)
    return kinds, {s: int(l) for s, l in eng.level.items() if int(l) > 0}


rows = {}
dirs = sorted({f.parent for f in ROOT.rglob("*") if f.suffix in (".log", ".json") and not f.parent.name.startswith("okta")})
for d in dirs:
    name = d.name
    exp = expected(name)
    events = cloudlogs.load(sorted(list(d.glob("*.log")) + list(d.glob("*.json"))))
    row = {"technique": d.parent.name, "family": family(name), "events_mapped": len(events),
           "expected": None if exp is None else sorted(exp)}
    if exp is None:
        row["status"] = "out of scope"
    elif not events:
        row["status"] = "not readable"
    else:
        for v in ("v0.5", "v0.6"):
            kinds, levels = replay(events, v)
            row[v] = {"detections": {k: sorted(s) for k, s in kinds.items() if k in SIGNAL_KINDS},
                      "as_expected": bool(exp & set(kinds)), "levels": levels}
        row["status"] = "detected" if row["v0.6"]["as_expected"] else "missed"
    rows[name] = row
    print(f"{name[:52]:52s} {row['family'][:10]:10s} ev {len(events):5d}  {row['status']:12s}"
          + (f" v0.5 {'Y' if row['v0.5']['as_expected'] else '-'}  {sorted(row['v0.6']['detections'])}" if "v0.6" in row else ""))
sc = [r for r in rows.values() if "v0.6" in r]
print(f"\nscored {len(sc)}  v0.5 {sum(r['v0.5']['as_expected'] for r in sc)}  v0.6 {sum(r['v0.6']['as_expected'] for r in sc)}"
      f"  out of scope {sum(r['status'] == 'out of scope' for r in rows.values())}  not readable {sum(r['status'] == 'not readable' for r in rows.values())}")
pathlib.Path("results/splunk_cloud.json").write_text(json.dumps(pseudonymize(rows), indent=1))  # no lab identities in results
