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
    assert classify("UpdateAccountPasswordPolicy") is None          # tightened or loosened: unknown, no evidence


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
