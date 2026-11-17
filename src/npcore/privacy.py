# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Privacy by design: keyed pseudonymisation and four-eyes re-identification.

Analysts and the trust engine only ever see pseudonyms (HMAC-SHA256 of the identity under a
secret key held by a separate role, e.g. the data protection officer). Re-identifying a person
requires two distinct authorised approvers and a documented reason, and is written to the ledger.
This implements data minimisation and pseudonymisation (GDPR Art. 5(1)(c), Art. 25, Art. 32) and
gives the works council a technical guarantee to agree on (BetrVG section 87(1) no. 6).
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from .ledger import Ledger


class ReidentificationDenied(PermissionError):
    pass


@dataclass
class Pseudonymizer:
    key: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    prefix: str = "P-"
    _reverse: Dict[str, str] = field(default_factory=dict, repr=False)

    def pseudonym(self, identity: str) -> str:
        tag = hmac.new(self.key, identity.encode(), hashlib.sha256).hexdigest()[:16]
        p = self.prefix + tag
        self._reverse[p] = identity
        return p

    def reidentify(self, pseudonym: str, approvers: Set[str], reason: str,
                   authorised: Set[str], ledger: Optional[Ledger] = None, t: Optional[float] = None) -> str:
        """Reveal the identity behind a pseudonym. Needs >= 2 distinct authorised approvers
        and a non-empty reason; every attempt (granted or denied) is logged."""
        ok = len(approvers) >= 2 and approvers <= authorised and bool(reason.strip())
        if ledger is not None:
            ledger.append("reidentification", {"pseudonym": pseudonym, "approvers": sorted(approvers),
                                               "reason": reason, "granted": ok}, t)
        if not ok:
            raise ReidentificationDenied("four-eyes rule: two distinct authorised approvers and a reason are required")
        if pseudonym not in self._reverse:
            raise KeyError(pseudonym)
        return self._reverse[pseudonym]
