# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Cloud log adapters: native formats and Microsoft Sentinel (Log Analytics) tables, with realistic values placed in
the columns of Sentinel's published table samples (data/sentinel/tables, when downloaded)."""
import json
import pathlib

import pytest

from npcore import cloudlogs
from npcore.engine import Engine, version_preset

T = pathlib.Path("data/sentinel/tables")
FILL = {
    "SigninLogs": {"ResultType": "0", "UserPrincipalName": "ana@example.com", "IPAddress": "198.51.100.7",
                   "TimeGenerated": "2026-01-05T09:00:00Z"},
    "AuditLogs": {"ActivityDisplayName": "Add member to role", "Result": "success",
                  "InitiatedBy": json.dumps({"user": {"userPrincipalName": "ana@example.com"}}),
                  "TimeGenerated": "2026-01-05T09:00:00Z", "ActivityDateTime": "2026-01-05T09:00:00Z"},
    "AWSCloudTrail": {"EventName": "StopLogging", "EventSource": "cloudtrail.amazonaws.com", "ErrorCode": "",
                      "UserIdentityUserName": "ops-admin", "TimeGenerated": "2026-01-05T09:00:00Z"},
    "OfficeActivity": {"Operation": "New-InboxRule", "UserId": "ana@example.com", "ResultStatus": "True",
                       "TimeGenerated": "2026-01-05T09:00:00Z", "ClientIP": "198.51.100.7"},
}
WANT = {"SigninLogs": "login", "AuditLogs": "config_change", "AWSCloudTrail": "audit_change", "OfficeActivity": "mail_rule"}


@pytest.mark.parametrize("table", sorted(FILL))
def test_sentinel_table(table):
    f = T / f"{table}.json"
    if not f.exists():
        pytest.skip("Sentinel table samples not downloaded")
    d = json.loads(f.read_text())
    row = dict(d[0] if isinstance(d, list) else d, **FILL[table])
    row["Type"] = table
    assert [e.kind for e in cloudlogs.convert(row)] == [WANT[table]]


def test_classify_examples():
    assert cloudlogs.classify("Add member to role.") == ("config_change", "privilege_grant")
    assert cloudlogs.classify("StopLogging")[0] == "audit_change"
    assert cloudlogs.classify("Set-InboxRule")[0] == "mail_rule"
    assert cloudlogs.classify("GetPasswordData")[0] == "data_access"
    assert cloudlogs.classify("DescribeInstances")[0] == "api_read"
    assert cloudlogs.classify("Disable Strong Authentication.") == ("config_change", "disable_mfa")


def test_v06_rules_and_simulation_untouched():
    rows = [{"eventVersion": "1.08", "eventSource": "cloudtrail.amazonaws.com", "eventName": "StopLogging",
             "eventTime": "2026-01-05T09:00:00Z", "userIdentity": {"userName": "ops"}, "sourceIPAddress": "198.51.100.7"}]
    rows += [{"eventSource": "ec2.amazonaws.com", "eventName": f"Describe{i}", "eventTime": f"2026-01-05T10:{i:02d}:00Z",
              "userIdentity": {"userName": "ops"}} for i in range(25)]
    evs = [x for r in rows for x in cloudlogs.convert(r)]
    eng = Engine(version_preset("v0.6"), {"ops": "ops"}, {"ops": "IT"})
    kinds = {x.kind for e in evs for x in eng.observe(e, True)}
    assert {"audit_tamper", "discovery"} <= kinds
    eng5 = Engine(version_preset("v0.5"), {"ops": "ops"}, {"ops": "IT"})
    assert not {"audit_tamper", "discovery"} & {x.kind for e in evs for x in eng5.observe(e, True)}
