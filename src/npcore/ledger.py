# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Tamper-evident evidence ledger.

Every evidence record, containment change, review and re-identification is appended to a
hash chain: entry_hash = SHA-256(prev_hash || canonical_json(entry)). Altering, deleting or
reordering any past entry breaks verification. This supports the chain of custody that labour
courts and data protection authorities expect when monitoring results are used, and it lets
works councils audit what the system did.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Iterable, List, Optional

GENESIS = "0" * 64


def _canon(obj) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


@dataclass
class Ledger:
    entries: List[dict] = field(default_factory=list)

    @property
    def head(self) -> str:
        return self.entries[-1]["hash"] if self.entries else GENESIS

    def append(self, kind: str, payload: dict, t: Optional[float] = None) -> dict:
        body = {"seq": len(self.entries), "t": t, "kind": kind, "payload": payload, "prev": self.head}
        h = hashlib.sha256((body["prev"] + _canon(body)).encode()).hexdigest()
        entry = dict(body, hash=h)
        self.entries.append(entry)
        return entry

    def verify(self) -> tuple[bool, Optional[int]]:
        """Return (ok, index_of_first_bad_entry)."""
        prev = GENESIS
        for i, e in enumerate(self.entries):
            body = {k: e[k] for k in ("seq", "t", "kind", "payload", "prev")}
            if e["prev"] != prev or e["seq"] != i:
                return False, i
            h = hashlib.sha256((prev + _canon(body)).encode()).hexdigest()
            if h != e["hash"]:
                return False, i
            prev = h
        return True, None

    def filter(self, kind: str) -> Iterable[dict]:
        return (e for e in self.entries if e["kind"] == kind)

    def dump_jsonl(self, path) -> None:
        with open(path, "w", encoding="utf-8") as f:
            for e in self.entries:
                f.write(_canon(e) + "\n")

    @classmethod
    def load_jsonl(cls, path) -> "Ledger":
        with open(path, encoding="utf-8") as f:
            return cls([json.loads(line) for line in f if line.strip()])
