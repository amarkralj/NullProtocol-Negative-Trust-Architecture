# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.1 blind test, step 1: pre-register expectations for the unit-test logs of panther-labs/panther-analysis
(Apache-2.0), written from RULE FILE NAMES ONLY, before any rule file or test log is downloaded.

Writes results/v11_panther_expected.json. The keyword table below is the whole pre-registration: the first matching row
decides the expected evidence kinds of a rule (None = not scored, with the reason).

Metrics, fixed here:
  * detection: a test log marked ExpectedResult: true, replayed alone through the engine, raises at least one expected
    kind (weight > 0). Reported per rule (all of its positive tests detected / some / none) and per test log.
  * false alarm: a test log marked ExpectedResult: false, of ANY in-scope rule, raises evidence of weight >= 1.0 (enough
    to move a principal to L1 on its own). Reported per test log.
  * logs our adapters cannot read count as missed (positives) and as no alarm (negatives); both are also reported.
Caveat fixed in advance: these are hand-written unit-test logs, not recordings of attacks.
"""
import json, pathlib, subprocess

REPO, SHA_FILE = "panther-labs/panther-analysis", "develop"
FAMILIES = ("aws_cloudtrail_rules", "azure_activity_rules", "azure_signin_rules", "gcp_audit_rules", "gcp_k8s_rules",
            "github_rules", "gsuite_activityevent_rules", "gsuite_reports_rules", "kubernetes_rules", "okta_rules",
            "aws_bedrockmodelinvocation_rules", "aws_eks_rules")
SEQ = "needs a sequence or a count of events; each Panther test is one event"
INFO = "informational activity, not misuse by itself"
CONTENT = "content inspection of mail, code or comments; out of scope"
VENDOR = "vendor-generated detection or alert passed through"
CTRL, AUDIT, DESTR = ["control_disabled"], ["audit_tamper", "control_disabled"], ["destructive_change"]
IDCH = ["identity_config_change", "new_principal"]
DATA = ["bulk_data_access", "external_share", "secret_access"]
DISC = ["discovery"]

RULES = [   # (keywords that must all appear in the file name, expected kinds or None, reason if None)
    # sequences and counts
    (("spray",), None, SEQ), (("many",), None, SEQ), (("multiple",), None, SEQ), (("bulk",), None, SEQ),
    (("enumeration",), None, SEQ), (("zscore",), None, SEQ), (("behavioral",), None, SEQ), (("excessive",), None, SEQ),
    (("rate_limits",), None, SEQ), (("unused_region",), None, SEQ), (("unusual",), None, SEQ), (("short_lifecycle",), None, SEQ),
    (("multi_instance",), None, SEQ), (("lockouts",), None, SEQ), (("session_multiple_ips",), None, SEQ),
    (("multiregion",), None, SEQ), (("large_scan",), None, SEQ), (("failed_signins",), None, SEQ),
    # content and vendor alerts
    (("malicious",), None, CONTENT), (("spam",), None, CONTENT), (("spoofed",), None, CONTENT), (("malware",), None, CONTENT),
    (("ransom",), None, CONTENT), (("phishing",), None, CONTENT), (("ioc",), None, CONTENT), (("shai_hulud",), None, CONTENT),
    (("skip_commits",), None, CONTENT), (("checkout",), None, CONTENT), (("trufflehog",), None, CONTENT), (("xz",), None, CONTENT),
    (("guardrailintervened",), None, VENDOR), (("threatinsight",), ["idp_risk"], None), (("high_risk",), ["idp_risk"], None),
    (("risklevel",), ["idp_risk"], None), (("suspicious_activity",), ["idp_risk"], None), (("is_suspicious",), ["idp_risk"], None),
    (("protection_alerts",), None, VENDOR), (("policy_violation",), None, VENDOR), (("advisor",), None, VENDOR),
    (("secret_scanning_alert",), None, VENDOR), (("vulnerability_dismissed",), CTRL, None), (("login_signal",), None, VENDOR),
    (("leaked_password",), ["idp_risk"], None), (("gov_attack",), ["idp_risk"], None), (("device_compromise",), None, VENDOR),
    (("device_suspicious",), None, VENDOR), (("suspicious_logins",), ["idp_risk"], None), (("passthrough",), None, VENDOR),
    (("compromised",), ["idp_risk", "identity_config_change"], None), (("fastpass",), None, VENDOR),
    # logging, detection and audit switched off
    (("logging",), AUDIT, None), (("logs_deleted",), AUDIT, None), (("flow_logs",), AUDIT, None), (("cloudtrail_stopped",), AUDIT, None),
    (("event_selectors",), AUDIT, None), (("diagnostic",), AUDIT, None), (("log_analytics",), AUDIT, None),
    (("log_bucket",), AUDIT, None), (("sink",), AUDIT, None), (("config_service_disabled",), AUDIT, None),
    (("macie",), AUDIT, None), (("securityhub",), AUDIT, None), (("alert_rules_deleted",), AUDIT, None),
    (("alert_suppression",), AUDIT, None), (("action_groups",), AUDIT, None), (("network_watcher",), AUDIT, None),
    (("activity_stream_stopped",), AUDIT, None), (("event_hub_deleted",), AUDIT, None), (("monitoring",), None, INFO),
    # protective controls switched off or opened
    (("guardrail",), CTRL, None), (("encryption_disabled",), CTRL, None), (("delete_bucket_encryption",), CTRL, None),
    (("public_access_block",), CTRL, None), (("versioning",), CTRL, None), (("mfa_delete",), CTRL, None),
    (("replication",), CTRL, None), (("security_control_disabling",), CTRL, None), (("waf",), CTRL, None),
    (("ipset",), CTRL, None), (("deletion_protection",), CTRL, None), (("backup_deleted",), CTRL + DESTR, None),
    (("soft_delete_disabled",), CTRL, None), (("https_only_disabled",), CTRL, None), (("immutability",), CTRL, None),
    (("resource_lock",), CTRL, None), (("firewall",), CTRL, None), (("nsg",), CTRL, None), (("permissive",), CTRL, None),
    (("security_group",), CTRL, None), (("network_acl",), CTRL, None), (("branch_protection",), CTRL, None),
    (("branch_policy_override",), ["protected_push", "control_disabled"], None), (("ruleset",), CTRL, None),
    (("advanced_security",), CTRL, None), (("ip_allowlist",), CTRL, None), (("org_auth",), CTRL, None),
    (("advanced_protection",), CTRL, None), (("sandbox_disabled",), CTRL, None), (("predelivery",), CTRL, None),
    (("enforce_strong_disabled",), CTRL, None), (("password_reuse",), CTRL, None), (("vpc_service_controls",), DISC, None),
    (("finding_evasion",), AUDIT, None), (("security_configuration_change",), CTRL, None),
    # made public / shared outside
    (("public",), ["control_disabled", "external_share"], None), (("anonymous_access",), ["control_disabled", "external_share"], None),
    (("external_share",), ["external_share"], None), (("overly_visible",), ["external_share"], None),
    (("visibility_change",), ["external_share", "control_disabled"], None), (("external_forwarding",), ["mail_forwarding", "external_share"], None),
    (("external_sharing",), ["external_share"], None), (("shared",), ["external_share", "bulk_data_access"], None),
    (("sas",), ["external_share", "bulk_data_access"], None), (("external_account",), DATA, None),
    (("cross_account",), DATA, None), (("cross_region",), DATA, None), (("data_export",), DATA, None),
    (("snapshot_export",), DATA, None), (("exfiltration",), DATA + ["identity_config_change"], None),
    (("ownership_transfer",), ["external_share"], None), (("transfer",), ["destructive_change", "external_share"], None),
    # destructive
    (("deleted",), DESTR, None), (("deletion",), DESTR, None), (("purged",), DESTR, None), (("_purge",), DESTR, None),
    (("erase_key",), DESTR, None), (("cmk_loss",), DESTR, None), (("delete_object",), DESTR, None), (("destructive",), DESTR, None),
    (("repo_archived",), DESTR, None), (("attempt_to_leave_org",), CTRL + DESTR, None), (("bucket_deleted",), DESTR, None),
    (("modified_or_deleted",), DESTR + CTRL, None),
    # secrets and credentials read
    (("secret",), ["secret_access", "bulk_data_access"], None), (("password_accessed",), ["secret_access", "bulk_data_access"], None),
    (("password_extraction",), ["secret_access", "bulk_data_access"], None), (("decrypt_ssm",), ["secret_access", "bulk_data_access"], None),
    (("keys_listed",), ["secret_access", "bulk_data_access"], None), (("key_accessed",), ["secret_access", "bulk_data_access"], None),
    (("certificate_accessed",), ["secret_access", "bulk_data_access"], None), (("user_data",), ["secret_access", "bulk_data_access"], None),
    (("imds",), ["session_replay", "secret_access"], None), (("steal_serviceaccount",), ["secret_access"], None),
    (("passwors_read",), None, SEQ), (("log_file_downloaded",), ["bulk_data_access"], None),
    (("artifact_download",), None, INFO),
    # identity, credentials, privilege
    (("mfa",), IDCH, None), (("two_step",), IDCH, None), (("access_key",), IDCH, None), (("key_created",), IDCH, None),
    (("keys_created",), IDCH, None), (("key_create",), IDCH, None), (("hmac",), IDCH, None), (("apikeys",), IDCH, None),
    (("api_key_created",), IDCH, None), (("token_created",), IDCH, None), (("certificate_created",), IDCH, None),
    (("credentials",), IDCH, None), (("loginprofile",), IDCH, None), (("login_profile",), IDCH, None), (("password_changed",), IDCH, None),
    (("pass_updated",), IDCH, None), (("support_reset",), IDCH, None), (("admin",), IDCH, None), (("privilege",), IDCH, None),
    (("privileged",), IDCH, None), (("elevate",), IDCH, None), (("role",), IDCH, None), (("iam",), IDCH, None),
    (("policy",), IDCH, None), (("idp",), IDCH, None), (("sso_profile",), IDCH, None), (("saml",), IDCH, None),
    (("oidc",), IDCH, None), (("trust",), IDCH, None), (("workforce_pool",), IDCH, None), (("workload_identity",), IDCH, None),
    (("org2org",), IDCH, None), (("invite",), IDCH, None), (("collaborator",), IDCH, None), (("moderators",), IDCH, None),
    (("create_user",), IDCH, None), (("create_role",), IDCH, None), (("entity_created",), IDCH, None),
    (("service_account",), IDCH, None), (("backdoor",), IDCH, None), (("added_to",), IDCH, None),
    (("app_integration",), IDCH, None), (("marketplace",), IDCH, None), (("oauth",), IDCH, None), (("support_access",), IDCH, None),
    (("serviceaccount_token",), IDCH, None), (("client_certificate",), IDCH, None), (("update_credentials",), IDCH, None),
    (("lambda_extension",), IDCH, None), (("lambda_code",), IDCH, None), (("lambda_crud",), None, INFO),
    (("runbook_created",), IDCH, None), (("automation_account",), IDCH, None), (("webhook",), IDCH, None),
    (("automation_schedule",), IDCH, None), (("functions_create",), IDCH, None), (("functions_update",), IDCH, None),
    (("cloud_run",), IDCH, None), (("deployifnotexists",), IDCH, None), (("deployments_create",), IDCH, None),
    (("signjwt",), IDCH, None), (("sign_blob",), IDCH, None), (("get_access_token",), IDCH, None),
    (("runner",), IDCH, None), (("workflow_permission",), CTRL + IDCH, None), (("hook",), IDCH, None),
    (("admission_controller",), IDCH + ["privileged_workload"], None),
    # Kubernetes workloads
    (("privileged_pod",), ["privileged_workload"], None), (("host_network",), ["privileged_workload"], None),
    (("host_pid",), ["privileged_workload"], None), (("host_ipc",), ["privileged_workload"], None),
    (("hostpath",), ["privileged_workload"], None), (("host_path",), ["privileged_workload"], None),
    (("dangerous_capabilities",), ["privileged_workload"], None), (("daemonset",), ["privileged_workload"], None),
    (("node_port",), ["privileged_workload"], None), (("nodeport",), ["privileged_workload"], None),
    (("cron_job",), ["privileged_workload"], None), (("cronjob",), ["privileged_workload"], None),
    (("system_namespace",), ["privileged_workload"], None), (("exec_into_pod",), ["privileged_workload"], None),
    (("kubectl_cp",), ["bulk_data_access"], None), (("ingress_without_tls",), None, INFO),
    (("anonymous",), DISC, None), (("access_denied",), DISC, None), (("recon",), DISC, None), (("discovery",), DISC, None),
    (("unauthorized",), DISC, None), (("403",), None, SEQ),
    # code or traffic redirected on infrastructure (names reviewed once more before download)
    (("startup_script",), IDCH + ["privileged_workload"], None), (("traffic_mirroring",), DATA, None),
    (("distributed_command",), ["privileged_workload", "new_principal"], None), (("command_executed",), ["privileged_workload", "new_principal"], None),
    (("serverless_execution",), ["privileged_workload", "new_principal"], None), (("key_regenerated",), IDCH, None),
    (("key_access_enabled",), CTRL, None), (("permissions_modified",), ["external_share", "control_disabled"], None),
    (("packet_capture",), DATA, None), (("port_mapping",), CTRL, None), (("route_table",), CTRL, None),
    (("gateway_modified",), CTRL, None), (("vpc_modified",), CTRL, None), (("getsessiontoken_misuse",), ["session_replay", "identity_config_change"], None),
    # AI
    (("abnormaltokenusage",), ["ai_usage_spike"], None),
    # sign-ins
    (("device_code",), ["device_code_phish"], None), (("without_mfa",), ["no_mfa_login"], None), (("no_mfa",), ["no_mfa_login"], None),
    (("legacyauth",), ["no_mfa_login"], None), (("stolen_session",), ["session_replay"], None),
    (("token_reuse",), ["session_replay"], None), (("anonymizing_vpn",), None, "needs IP reputation data"),
    (("account_locked",), None, SEQ), (("screen_unlock_fail",), None, SEQ), (("unsuccessful_mfa",), None, SEQ),
    (("root_login_failed",), None, SEQ),
]


def expected(name: str):
    n = name.lower()
    for keys, exp, why in RULES:
        if all(k in n for k in keys):
            return exp, why
    return None, INFO + " (no keyword matched)"


def main():
    tree = json.loads(subprocess.run(["gh", "api", f"repos/{REPO}/git/trees/{SHA_FILE}?recursive=1"], capture_output=True,
                                     text=True, check=True).stdout)
    sha = subprocess.run(["gh", "api", f"repos/{REPO}/commits/{SHA_FILE}", "--jq", ".sha"], capture_output=True, text=True,
                         check=True).stdout.strip()
    paths = sorted(x["path"] for x in tree["tree"] if x["path"].startswith("rules/") and x["path"].endswith(".yml")
                   and x["path"].split("/")[1] in FAMILIES)
    rules = {}
    for p in paths:
        exp, why = expected(p.rsplit("/", 1)[1][:-4])
        rules[p] = exp if exp is not None else {"not_scored": why}
    scored = sum(isinstance(v, list) for v in rules.values())
    doc = {"_about": __doc__.strip(), "_source": f"https://github.com/{REPO} at commit {sha} (Apache-2.0)",
           "_commit": sha, "_written": "2026-11-24, before any rule file or test log was downloaded",
           "_counts": {"rules": len(rules), "scored": scored, "not_scored": len(rules) - scored}, "rules": rules}
    pathlib.Path("results/v11_panther_expected.json").write_text(json.dumps(doc, indent=1) + "\n")
    print(doc["_counts"])


if __name__ == "__main__":
    main()
