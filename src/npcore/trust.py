# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Asymmetric trust model.

NullProtocol Negative Trust (NT) treats trust as a signed quantity:

    trust(s, t) = T0  +  min(P_cap, sum_pos w_i * 2^(-(t - t_i)/h_pos))
                      -        sum_neg w_j * 2^(-(t - t_j)/h_neg)

* T0 is the starting point. NT uses T0 <= 0: a principal is never trusted by default.
* Negative evidence (distrust) decays slowly (h_neg long); positive evidence decays fast (h_pos
  short) and is capped (P_cap). A long clean history therefore cannot "bank" enough trust to hide
  one strong negative signal. This is the evidence asymmetry principle.
* The symmetric variant (h_pos == h_neg, no cap) reproduces a classic risk score and is used as
  an ablation and as the zero-trust/UEBA baseline.
"""
from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List

from .evidence import Evidence


# Evidence close to proof (deception contact, multi-step chains, data leaving to personal
# destinations, account compromise) persists. Weak statistical anomalies fade quickly.
STRONG_KINDS = {
    "exfil_chain", "account_compromise", "social_engineering", "collusion_link", "multi_signal",
    "egress_removable", "egress_personal_cloud", "email_personal", "bulk_copy", "blocked_attempt",
    "cross_account_login", "lookalike_repeat", "leak_site_contact", "spyware_download", "session_replay",
    "dormant_reuse", "mfa_fatigue", "identity_config_change", "record_volume_spike", "post_termination_activity",
    "edr_high", "secret_search", "workload_volume_spike", "account_takeover_reset",
    "impossible_travel", "idp_risk", "audit_tamper", "mail_forwarding", "bulk_data_access", "brute_force", "channel_burst",
}


def is_strong(e: Evidence) -> bool:
    return e.source == "deception" or e.kind in STRONG_KINDS


@dataclass
class TrustConfig:
    t0: float = 0.0            # no earned trust at start (never positive by default)
    h_neg: float = 24 * 30     # half-life of strong negative evidence (hours) -> 30 days
    h_neg_weak: float = 24 * 4  # half-life of weak/statistical negative evidence -> 4 days
    h_pos: float = 24 * 3      # half-life of positive evidence (hours) -> 3 days
    pos_cap: float = 0.6       # maximum earned trust: a clean history cannot bank trust
    asymmetric: bool = True

    @classmethod
    def symmetric(cls, half_life_h: float = 24 * 7) -> "TrustConfig":
        return cls(t0=0.0, h_neg=half_life_h, h_neg_weak=half_life_h, h_pos=half_life_h, pos_cap=math.inf, asymmetric=False)


class TrustModel:
    def __init__(self, cfg: TrustConfig | None = None):
        self.cfg = cfg or TrustConfig()
        self._ev: Dict[str, List[Evidence]] = defaultdict(list)

    def add(self, ev: Evidence) -> None:
        self._ev[ev.subject].append(ev)

    def evidence(self, subject: str) -> List[Evidence]:
        return list(self._ev.get(subject, []))

    def subjects(self):
        return list(self._ev.keys())

    def components(self, subject: str, t: float) -> tuple[float, float]:
        """Return (earned_trust, distrust) at time t, using only evidence up to t."""
        c = self.cfg
        pos = neg = 0.0
        lst = self._ev.get(subject, [])
        if len(lst) > 400:
            self._compact(subject, t)
        for e in self._ev.get(subject, []):
            if e.t > t:
                continue
            age = t - e.t
            if e.weight < 0:
                pos += -e.weight * 2 ** (-age / c.h_pos)
            else:
                h = c.h_neg if (not c.asymmetric or is_strong(e)) else c.h_neg_weak
                neg += e.weight * 2 ** (-age / h)
        return min(pos, c.pos_cap), neg

    def _compact(self, subject: str, t: float) -> None:
        """Drop evidence whose remaining effect on trust is below 1e-6 (it stays in the ledger)."""
        c = self.cfg
        keep = []
        for e in self._ev[subject]:
            if e.t > t:
                keep.append(e); continue
            age = t - e.t
            h = c.h_pos if e.weight < 0 else (c.h_neg if (not c.asymmetric or is_strong(e)) else c.h_neg_weak)
            if abs(e.weight) * 2 ** (-age / h) >= 1e-6:
                keep.append(e)
        self._ev[subject] = keep

    def trust(self, subject: str, t: float) -> float:
        pos, neg = self.components(subject, t)
        return self.cfg.t0 + pos - neg

    def reset_negative(self, subject: str, t: float, factor: float = 0.0) -> None:
        """After a human review clears a principal, scale down earlier negative evidence.
        The original evidence stays in the ledger; only its effect on trust is reduced."""
        kept = []
        for e in self._ev.get(subject, []):
            if e.weight > 0 and e.t <= t:
                if factor > 0:
                    kept.append(Evidence(e.t, e.subject, e.kind, e.weight * factor, e.desc,
                                         e.subject_kind, e.behavior, e.refs, e.source))
            else:
                kept.append(e)
        self._ev[subject] = kept
