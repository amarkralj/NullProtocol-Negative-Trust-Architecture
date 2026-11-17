# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Correlation: evidence that only exists across steps or across people.

* Exfiltration chains: staging -> archive -> egress on the same account within days. Each step
  alone is common; the sequence is not.
* Social-engineering links: a call or pretext message aimed at employee V followed shortly by a
  login on V's account from an unknown context. The *account* is distrusted (it is compromised),
  the *person* V is not (they are the victim). If the caller is an internal account, the caller
  person receives the distrust.
* Collusion propagation: when B misbehaves on data that A gave B access to (grant or internal
  forward), a damped share of B's distrust flows to A.
* Multi-signal campaigns: three or more different kinds of negative evidence within a week.
"""
from __future__ import annotations

from collections import defaultdict, deque
from typing import Dict, List

from .evidence import Evidence, ACCOUNT

CHAIN_WINDOW_H = 7 * 24
SE_WINDOW_H = 1.0
COLLUSION_WINDOW_H = 14 * 24
COLLUSION_DAMPING = 0.5
MISUSE_KINDS = {"egress_removable", "egress_personal_cloud", "egress_cloud", "email_personal", "bulk_copy",
                "exfil_chain", "cross_dept_sensitive_read", "archive"}


class Correlator:
    def __init__(self, owners: Dict[str, str], strong_only_campaigns: bool = False):
        self.owners = owners                     # account -> owning person
        self.strong_only = strong_only_campaigns
        self.recent_strong: Dict[str, deque] = defaultdict(deque)
        self.staged: Dict[str, deque] = defaultdict(deque)
        self.archived: Dict[str, deque] = defaultdict(deque)
        self.calls: List[tuple] = []             # (t, caller_account, target_person)
        self.links: Dict[str, List[tuple]] = defaultdict(list)   # receiver -> [(t, giver, resource_dept)]
        self.recent: Dict[str, deque] = defaultdict(deque)
        self.campaign_flag: Dict[str, float] = {}

    def observe(self, e, new_ev: List[Evidence]) -> List[Evidence]:
        out: List[Evidence] = []
        t, acct = e.t, e.account
        if e.kind == "copy":
            self.staged[acct].append(t)
        elif e.kind == "archive":
            if any(t - s <= CHAIN_WINDOW_H for s in self.staged[acct]):
                self.archived[acct].append(t)
        elif e.kind in ("egress_usb", "egress_cloud") or (e.kind == "email" and e.attrs.get("external") and e.attrs.get("attachment")):
            if any(t - s <= CHAIN_WINDOW_H for s in self.archived[acct]) or any(t - s <= CHAIN_WINDOW_H for s in self.staged[acct]):
                out.append(Evidence(t, acct, "exfil_chain", 1.5,
                                    "staging -> archive -> egress sequence on the same account (bulk copy, compression, transfer)",
                                    behavior="host_data_hoarding", source="correlation"))
                self.staged[acct].clear(); self.archived[acct].clear()
        elif e.kind == "call" or (e.kind == "msg" and e.attrs.get("pattern")):
            tgt = e.attrs.get("target")
            if tgt:
                self.calls.append((t, acct, tgt))
        elif e.kind == "grant":
            g = e.attrs.get("grantee")
            if g:
                self.links[g].append((t, self.owners.get(acct, acct), e.rdept))
        if e.kind == "email" and not e.attrs.get("external") and e.attrs.get("attachment") and e.sensitive:
            rcv = str(e.attrs.get("to", "")).split("@")[0]
            if rcv in self.owners.values():
                self.links[rcv].append((t, self.owners.get(acct, acct), e.rdept))

        # social engineering: login on the target's account soon after a call aimed at them
        if e.kind == "login":
            unknown = any(x.kind in ("new_device", "foreign_ip", "impossible_context") for x in new_ev)
            for (tc, caller, tgt) in self.calls:
                if tgt == self.owners.get(acct) and 0 <= t - tc <= SE_WINDOW_H and unknown:
                    out.append(Evidence(t, "acct:" + acct, "account_compromise", 3.0,
                                        f"login from unknown context {60*(t-tc):.0f} min after a call/pretext aimed at the account owner (vishing pattern)",
                                        subject_kind=ACCOUNT, behavior="social_engineering", source="correlation"))
                    if caller in self.owners:
                        out.append(Evidence(t, self.owners[caller], "social_engineering", 2.0,
                                            f"placed a call/pretext to {tgt}; {60*(t-tc):.0f} min later {tgt}'s account authenticated from an unknown device/IP",
                                            behavior="social_engineering", source="correlation"))

        # collusion: damped propagation from receiver to giver
        person = self.owners.get(acct)
        # only evidence of data misuse in the shared scope propagates (not mood, not login anomalies)
        neg = [x for x in new_ev + out if x.weight > 0 and x.subject_kind != ACCOUNT
               and (x.source == "deception" or x.kind in MISUSE_KINDS)]
        if person and neg and person in self.links:
            for (tg, giver, rdept) in self.links[person]:
                if 0 <= t - tg <= COLLUSION_WINDOW_H and giver != person and e.rdept == rdept:
                    w = COLLUSION_DAMPING * sum(x.weight for x in neg)
                    out.append(Evidence(t, giver, "collusion_link", w,
                                        f"{person} misused {rdept} data after {giver} granted or forwarded access",
                                        behavior="collusion", source="correlation"))

        return out

    def campaign(self, t: float, evs: List[Evidence]) -> List[Evidence]:
        """Multi-signal campaign, evaluated after evidence has been attributed to person or account."""
        out: List[Evidence] = []
        for x in evs:
            if x.weight > 0 and x.kind != "multi_signal":
                dq = self.recent[x.subject]
                dq.append((x.t, x.kind))
                while dq and t - dq[0][0] > 7 * 24:
                    dq.popleft()
                kinds = {k for _, k in dq}
                if self.strong_only:
                    from .trust import is_strong
                    if is_strong(x):
                        self.recent_strong[x.subject].append(x.t)
                    rs = self.recent_strong[x.subject]
                    while rs and t - rs[0] > 7 * 24:
                        rs.popleft()
                    if not rs:
                        continue
                if len(kinds) >= 3 and t - self.campaign_flag.get(x.subject, -1e9) > 7 * 24:
                    self.campaign_flag[x.subject] = t
                    out.append(Evidence(t, x.subject, "multi_signal", 0.6,
                                        f"{len(kinds)} different kinds of negative evidence within 7 days: {', '.join(sorted(kinds))}",
                                        subject_kind=x.subject_kind, source="correlation"))
        return out
