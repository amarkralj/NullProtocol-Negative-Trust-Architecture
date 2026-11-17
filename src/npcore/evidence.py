# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Evidence: the single currency of the NullProtocol Negative Trust model.

Every observation that should change how much the organisation trusts a principal is turned
into an Evidence record. Positive weight = distrust (negative evidence about the principal),
negative weight = earned trust (positive evidence). Keeping one explicit record per observation
is what makes every containment decision explainable and auditable.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Optional


# Subject kinds. A *person* is a human insider; an *account* is a credential/session that can be
# used by someone else (e.g. after vishing). NullProtocol Negative Trust keeps them apart so that a victim
# whose account was hijacked is not blamed as a person.
PERSON = "person"
ACCOUNT = "account"


@dataclass(frozen=True)
class Evidence:
    t: float                    # time in hours since simulation/telemetry start
    subject: str                # person or account identifier (pseudonymised in production)
    kind: str                   # signal type, e.g. "decoy_credential_use", "exfil_chain"
    weight: float               # > 0 distrust, < 0 earned trust
    desc: str                   # human-readable explanation (shown to reviewers)
    subject_kind: str = PERSON
    behavior: Optional[str] = None     # mapped behaviour taxonomy label (optional)
    refs: tuple = field(default_factory=tuple)  # ids of underlying events / decoys
    source: str = "signal"      # signal | deception | correlation | review

    def to_dict(self) -> dict:
        d = asdict(self)
        d["refs"] = list(self.refs)
        return d
