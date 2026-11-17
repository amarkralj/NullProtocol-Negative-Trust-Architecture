# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Windows endpoint adapter: synthetic Sysmon / Security / PowerShell events in OTRF's field layout."""
import json

from npcore import windows


def run(rows, tmp_path):
    f = tmp_path / "w.json"
    f.write_text("\n".join(json.dumps(r) for r in rows))
    return windows.load([f])


def base(eid, ch, ts, **kw):
    return dict({"EventID": eid, "Channel": ch, "Hostname": "WS5.corp.local", "@timestamp": ts}, **kw)


def test_lsass_access_attributed_to_process_owner(tmp_path):
    rows = [base(1, "Microsoft-Windows-Sysmon/Operational", "2026-01-05T09:00:00Z", User="CORP\\ana", ProcessGuid="{P1}",
                 Image="C:\\x\\powershell.exe", CommandLine="powershell"),
            base(10, "Microsoft-Windows-Sysmon/Operational", "2026-01-05T09:01:00Z", SourceProcessGUID="{P1}",
                 SourceImage="C:\\x\\powershell.exe", TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1010"),
            base(10, "Microsoft-Windows-Sysmon/Operational", "2026-01-05T09:02:00Z", SourceProcessGUID="{P2}",
                 SourceImage="C:\\Windows\\system32\\svchost.exe", TargetImage="C:\\Windows\\system32\\lsass.exe", GrantedAccess="0x1000")]
    evs = [e for e in run(rows, tmp_path) if e.kind == "detection"]
    assert [(e.account, e.attrs["severity"]) for e in evs] == [("ana", "high")]


def test_indicators(tmp_path):
    rows = [base(1, "Microsoft-Windows-Sysmon/Operational", "2026-01-05T09:00:00Z", User="CORP\\bo",
                 CommandLine="rundll32 C:\\windows\\system32\\comsvcs.dll, MiniDump 624 out.dmp full"),
            base(1, "Microsoft-Windows-Sysmon/Operational", "2026-01-05T09:10:00Z", User="CORP\\bo",
                 CommandLine="wevtutil cl Security"),
            base(4732, "Security", "2026-01-05T09:20:00Z", SubjectUserName="bo"),
            base(1, "Microsoft-Windows-Sysmon/Operational", "2026-01-05T09:30:00Z", User="CORP\\bo",
                 CommandLine="C:\\Tools\\AnyDesk.exe")]
    kinds = [(e.kind, e.attrs.get("what") or e.attrs.get("name")) for e in run(rows, tmp_path)]
    assert kinds[0][0] == "detection" and "comsvcs" in kinds[0][1].lower()
    assert ("audit_change", "logging disabled or cleared") in kinds
    assert ("config_change", "privilege_grant") in kinds
    assert ("detection", "remote_access_tool") in kinds
