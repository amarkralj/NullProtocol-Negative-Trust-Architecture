# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""v1.1: cloud operations classified by verb and object; denied attempts; Azure Activity and Entra risk adapters."""
from npcore import sources
from npcore.engine import Engine, version_preset
from npcore.opclass import classify
from npcore.sim import Event


def test_verb_object_across_clouds():
    assert classify("DeleteGuardrail")[0] == "control_change"
    assert classify("DeleteKnowledgeBase")[0] == "destructive_change"
    assert classify("Microsoft.Insights/diagnosticSettings/delete")[0] == "audit_change"
    assert classify("google.logging.v2.ConfigServiceV2.DeleteSink")[0] == "audit_change"
    assert classify("google.iam.admin.v1.CreateServiceAccountKey") == ("config_change", "credential_added")
    assert classify("DeactivateMFADevice") == ("config_change", "disable_mfa")


def test_parameters_decide_direction():
    assert classify("PutBucketVersioning", {"VersioningConfiguration": {"Status": "Suspended"}})[0] == "control_change"
    assert classify("PutBucketVersioning", {"VersioningConfiguration": {"Status": "Enabled"}}) is None
    assert classify("AuthorizeSecurityGroupIngress", {"items": [{"cidrIp": "0.0.0.0/0"}]})[0] == "control_change"
    assert classify("AuthorizeSecurityGroupIngress", {"items": [{"cidrIp": "10.0.0.0/8"}]}) is None
    assert "direction unknown" in classify("UpdateAccountPasswordPolicy")[1]   # 1.0.2: unknown -> weak evidence (0.3)


def test_reads_and_routine_admin_are_quiet():
    for op in ("ListBuckets", "DescribeInstances", "GetObject", "DeleteUser", "StopInstances",
               "Microsoft.Compute/virtualMachines/read"):
        assert classify(op) is None, op


def test_denied_attempt_counts_less():
    assert classify("DeleteTrail", None, "AccessDenied") == ("denied_change", "audit_change|delete trail")
    assert classify("ListBuckets", None, "AccessDenied") is None
    ev = Event(500, "eve", "denied_change", sensitive=True, attrs={"what": "audit_change|delete trail"})
    for version, expect in (("v1.0", []), ("v1.1", [("audit_tamper", 1.0)])):
        eng = Engine(version_preset(version), {"eve": "eve"}, {"eve": "U"})
        assert [(x.kind, x.weight) for x in eng.observe(ev, True) if x.weight > 0] == expect


def test_azure_activity_and_entra_risk_adapters():
    act = {"authorization": {"action": "Microsoft.Automation/automationAccounts/runbooks/write"}, "caller": "a@x.com",
           "eventName": {"value": "EndRequest"}, "status": {"value": "Succeeded"}, "eventTimestamp": "2024-01-01T00:00:00Z"}
    assert [(e.kind, e.attrs["what"]) for e in sources.convert(act)] == [("config_change", "new_principal")]
    begin = dict(act, eventName={"value": "BeginRequest"})
    assert sources.convert(begin) == []                              # one call, counted once
    risk = {"time": "2024-01-01T00:00:00Z", "category": "UserRiskEvents", "operationName": "User Risk Detection",
            "identity": "ava", "properties": {"userPrincipalName": "ava@x.com", "riskEventType": "anonymizedIPAddress"}}
    assert [e.kind for e in sources.convert(risk)] == ["idp_risk"]


# ---------------------------------------------------------------- 1.0.2
from npcore.opclass import classify_dotted, critical  # noqa: E402


def test_dotted_names_github_okta_workspace():
    assert classify_dotted("org.saml_disabled")[0] == "control_change"
    assert classify_dotted("system.mfa.factor.deactivate") == ("config_change", "disable_mfa")
    assert classify_dotted("user.session.impersonation.grant") == ("config_change", "privilege_grant")
    assert classify_dotted("2sv_disable") == ("config_change", "disable_mfa")
    assert classify_dotted("org.enable_two_factor_requirement") is None      # switching protection ON is not evidence
    assert classify_dotted("repo.create") is None


def test_azure_paths_and_escaped_bodies():
    assert classify("MICROSOFT.AUTOMATION/AUTOMATIONACCOUNTS/RUNBOOKS/DRAFT/WRITE") == ("config_change", "new_principal")
    assert classify("Microsoft.KeyVault/vaults/secrets/getSecret/action")[0] == "data_access"
    assert classify("Microsoft.KeyVault/vaults/read") is None
    body = {"requestbody": '{"properties":{"allowBlobPublicAccess":true}}'}
    assert classify("Microsoft.Storage/storageAccounts/write", body)[0] == "control_change"
    assert classify("Microsoft.Storage/storageAccounts/write", {"requestbody": '{"properties":{"minimumTlsVersion":"TLS1_2"}}'}) is None


def test_egress_and_impact():
    assert classify("AuthorizeSecurityGroupEgress", {"cidrIp": "0.0.0.0/0"}) is None
    assert critical("delete vaults") and critical("delete bucket") and not critical("terminate instances")


def test_gke_kubernetes_translation_and_exclusions():
    gke = {"timestamp": "2024-01-01T00:00:00Z", "protoPayload": {"methodName": "io.k8s.core.v1.pods.exec.create",
           "resourceName": "core/v1/namespaces/default/pods/web/exec", "authenticationInfo": {"principalEmail": "dev@x.com"},
           "requestMetadata": {"callerIp": "8.8.8.8"}}}
    assert [(e.kind, e.attrs["what"]) for e in sources.convert(gke)] == [("workload_create", "exec")]
    probe = {"apiVersion": "audit.k8s.io/v1", "verb": "get", "user": {"username": "system:anonymous"}, "sourceIPs": ["10.0.0.5"],
             "userAgent": "kube-probe/1.29", "objectRef": {"resource": "healthz"}, "responseStatus": {"code": 200}}
    assert sources.convert(probe) == []


def test_aws_service_actions_and_minor_policies():
    base = {"eventSource": "iam.amazonaws.com", "eventTime": "2024-01-01T00:00:00Z", "userIdentity": {"userName": "ana"}}
    attach = dict(base, eventName="AttachUserPolicy", requestParameters={"policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess"})
    admin = dict(base, eventName="AttachUserPolicy", requestParameters={"policyArn": "arn:aws:iam::aws:policy/AdministratorAccess"})
    assert sources.convert(attach)[0].attrs.get("minor") and not sources.convert(admin)[0].attrs.get("minor")
    svc = dict(base, eventSource="ec2.amazonaws.com", eventName="TerminateInstances",
               userIdentity={"type": "AWSService", "invokedBy": "autoscaling.amazonaws.com"})
    assert sources.convert(svc) == []
