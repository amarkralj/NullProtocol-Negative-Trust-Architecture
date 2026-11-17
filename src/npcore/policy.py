# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Graduated, reversible containment.

Trust maps to a containment level. Each level restricts only what is needed at that level of
distrust, and every level can be lifted again (by decaying evidence or by a human review).

    L0 OBSERVE        trust >= -0.5   normal operation, everything logged pseudonymously
    L1 VERIFY         trust <  -0.5   step-up authentication for sensitive reads
    L2 DUAL_CONTROL   trust <  -1.5   egress and bulk actions need a second approver
    L3 READ_ONLY      trust <  -2.5   all egress blocked, sensitive reads blocked
    L4 ISOLATE        trust <  -4.0   session isolated, case opened for human review

Actions are classified into categories so that the policy is independent of any one log source.
Access to sensitive resources is granted as short-lived *leases* bound to a purpose (e.g. a ticket);
a lease never outlives its purpose and is revoked when the level reaches L3.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum
from typing import Dict, Optional, Tuple


class Level(IntEnum):
    L0_OBSERVE = 0
    L1_VERIFY = 1
    L2_DUAL_CONTROL = 2
    L3_READ_ONLY = 3
    L4_ISOLATE = 4


# action categories
READ = "read"                  # normal read
SENSITIVE_READ = "sensitive_read"
BULK = "bulk"                  # bulk copy / archive / mass clone
EGRESS = "egress"              # data leaves the organisation (external mail, USB, personal cloud)
AUTH = "auth"
ADMIN = "admin"                # permission grants, config changes
OTHER = "other"

ALLOW = "allow"
STEP_UP = "step_up"
DUAL_CONTROL = "dual_control"
DENY = "deny"


@dataclass
class PolicyConfig:
    thresholds: Tuple[float, float, float, float] = (-0.5, -1.5, -2.5, -4.0)  # L1..L4 entry
    lease_hours: float = 8.0


def level_for(trust: float, cfg: PolicyConfig) -> Level:
    l1, l2, l3, l4 = cfg.thresholds
    if trust < l4:
        return Level.L4_ISOLATE
    if trust < l3:
        return Level.L3_READ_ONLY
    if trust < l2:
        return Level.L2_DUAL_CONTROL
    if trust < l1:
        return Level.L1_VERIFY
    return Level.L0_OBSERVE


def decide(level: Level, category: str) -> str:
    """Decision matrix: what a principal at `level` may do in `category`."""
    if level >= Level.L4_ISOLATE:
        return DENY
    if level >= Level.L3_READ_ONLY:
        return DENY if category in (EGRESS, BULK, ADMIN, SENSITIVE_READ) else ALLOW
    if level >= Level.L2_DUAL_CONTROL:
        if category in (EGRESS, BULK, ADMIN):
            return DUAL_CONTROL
        if category == SENSITIVE_READ:
            return STEP_UP
        return ALLOW
    if level >= Level.L1_VERIFY:
        return STEP_UP if category in (SENSITIVE_READ, ADMIN) else ALLOW
    return ALLOW


@dataclass
class Lease:
    subject: str
    resource: str
    purpose: str
    granted_t: float
    expires_t: float


@dataclass
class LeaseBook:
    """Purpose-bound, time-limited access grants (just-in-time access)."""
    cfg: PolicyConfig = field(default_factory=PolicyConfig)
    leases: Dict[Tuple[str, str], Lease] = field(default_factory=dict)

    def grant(self, subject: str, resource: str, purpose: str, t: float) -> Lease:
        lease = Lease(subject, resource, purpose, t, t + self.cfg.lease_hours)
        self.leases[(subject, resource)] = lease
        return lease

    def active(self, subject: str, resource: str, t: float) -> Optional[Lease]:
        lease = self.leases.get((subject, resource))
        return lease if lease and lease.expires_t >= t else None

    def revoke_all(self, subject: str) -> int:
        keys = [k for k in self.leases if k[0] == subject]
        for k in keys:
            del self.leases[k]
        return len(keys)
