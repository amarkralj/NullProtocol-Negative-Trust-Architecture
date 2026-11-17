# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Pseudonymise identities before results are written to disk.

Public attack datasets (splunk/attack_data, OTRF Security-Datasets, Microsoft Sentinel samples) were recorded in
real lab tenants and contain the researchers' account names, e-mail addresses, cloud account numbers and Windows
security identifiers. The results only need to show *that* an account was detected, not *which* one, so every
identity is replaced by a stable placeholder:

    rod@lab.onmicrosoft.com            -> user-3f9a1c@example.org
    acct:jdoe                          -> acct:principal-<hash>
    arn:aws:sts::123456789012:...      -> arn:aws:sts::000000000000:...
    S-1-5-21-...-1104                  -> S-1-5-21-sid-5b71aa

The same identity always maps to the same placeholder (a short hash), so results stay comparable between runs and
files. Generic system identities (SYSTEM, unknown, ...) are kept because they reveal nothing about anyone.
"""
from __future__ import annotations

import hashlib
import re
from typing import Any, Iterable

GENERIC = {"unknown", "not available", "system", "s-1-5-18", "nt authority\\system", "administrator", "root",
           "certificate", "microsoft app access panel", "azure mfa strongauthenticationservice", "ms-pim",
           "microsoft\\serviceoperator", "nt authority\\system (w3wp)"}
PREFIXES = ("acct:", "person:", "device:", "app:")

R_EMAIL = re.compile(r"[A-Za-z0-9._%+'-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")
R_AWS = re.compile(r"(?<!\d)\d{12}(?!\d)")
R_SID = re.compile(r"(?i)\bs-1-5-21(?:-\d+){3,4}\b")
R_GUID = re.compile(r"(?i)\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b")
R_HEX = re.compile(r"(?i)(?<=_)[0-9a-f]{16}\b")          # e.g. the suffix of AWSReservedSSO_<role>_<hex>


def _h(s: str) -> str:
    return hashlib.sha256(s.lower().encode()).hexdigest()[:6]


def _scrub(s: str) -> str:
    s = R_EMAIL.sub(lambda m: f"user-{_h(m.group(0))}@example.org", s)
    s = R_SID.sub(lambda m: f"S-1-5-21-sid-{_h(m.group(0))}", s)
    s = R_GUID.sub(lambda m: f"id-{_h(m.group(0))}", s)
    s = R_HEX.sub(lambda m: _h(m.group(0)) + "0" * 10, s)
    return R_AWS.sub("000000000000", s)


def _principal(name: str) -> str:
    pre = next((p for p in PREFIXES if name.startswith(p)), "")
    bare = name[len(pre):]
    if bare.lower() in GENERIC or not bare:
        return name
    out = _scrub(bare)
    if out == bare:                                   # a plain user name such as "jdoe"
        out = f"principal-{_h(bare)}"
    return pre + out


PRINCIPAL_KEYS = {"levels", "detections", "account_level", "detected", "principals", "victims", "accounts"}


def principals(obj: Any, found: set | None = None) -> set:
    """Every identity that appears as a principal in a results structure."""
    found = set() if found is None else found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k == "levels" and isinstance(v, dict):
                found.update(map(str, v))
            elif k == "detections" and isinstance(v, dict):
                for lst in v.values():
                    if isinstance(lst, list):
                        found.update(map(str, lst))
            elif k in PRINCIPAL_KEYS and isinstance(v, list):
                found.update(str(x) for x in v if isinstance(x, str))
            principals(v, found)
    elif isinstance(obj, list):
        for v in obj:
            principals(v, found)
    return found


def pseudonymize(obj: Any, extra: Iterable[str] = ()) -> Any:
    """Copy of `obj` (JSON-like) with every identity replaced. Principal names found under PRINCIPAL_KEYS (and in
    `extra`) are also replaced wherever else they occur in a string."""
    names = {n for n in set(principals(obj)) | set(extra)}
    plain = {}
    for n in names:
        bare = next((n[len(p):] for p in PREFIXES if n.startswith(p)), n)
        if bare and bare.lower() not in GENERIC and _scrub(bare) == bare and len(bare) >= 3:
            plain[bare] = _principal(bare)
    rx = re.compile("|".join(rf"(?<![\w.-]){re.escape(b)}(?![\w-])" for b in sorted(plain, key=len, reverse=True))) if plain else None

    def s(x: str) -> str:
        pre = next((p for p in PREFIXES if x.startswith(p)), "")
        if x[len(pre):] in plain:
            return pre + plain[x[len(pre):]]
        x = _scrub(x)
        return rx.sub(lambda m: plain[m.group(0)], x) if rx else x

    def walk(o: Any) -> Any:
        if isinstance(o, dict):
            return {(s(k) if isinstance(k, str) else k): walk(v) for k, v in o.items()}
        if isinstance(o, list):
            return [walk(v) for v in o]
        return s(o) if isinstance(o, str) else o

    return walk(obj)
