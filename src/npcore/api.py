# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Embedding API: the smallest way to put NullProtocol Negative Trust into an existing system.

    from npcore.api import NegativeTrust
    nt = NegativeTrust("directory.json")            # or a dict / Directory
    for out in nt.process(ocsf_record):              # one OCSF event in ...
        ...                                          # ... decisions, level changes, CAEP SETs out
    nt.status("u001")                                # level, trust and the evidence behind it
    nt.review("u001", confirmed=False)               # human decision on an L4 case
    nt.verify_ledger()

Input is OCSF (see docs/integration.md); output records are plain dicts that can be sent to a policy
enforcement point, a SOC queue or, for type "caep", signed and delivered to an identity provider.
"""
from __future__ import annotations

import threading
from typing import Iterable, Iterator, List, Optional, Union

from . import policy as P
from .engine import Engine, EngineConfig, version_preset
from .integrations import Directory, from_ocsf, caep_set


class NegativeTrust:
    def __init__(self, directory: Union[str, dict, Directory], version: str = "v0.9", cfg: Optional[EngineConfig] = None,
                 decoys=None, issuer: str = "https://nt.example/", audience: str = "https://idp.example/caep",
                 assume_stepup_passes: bool = True):
        if isinstance(directory, str):
            directory = Directory.load(directory)
        elif isinstance(directory, dict):
            directory = Directory(**{k: (tuple(v) if isinstance(v, list) else v) for k, v in directory.items()})
        self.d = directory
        self.cfg = cfg or version_preset(version)
        self.engine = Engine(self.cfg, {u: u for u in self.d.departments}, self.d.departments, decoys,
                             partner_domains=self.d.partner_domains, support_staff=self.d.support_staff,
                             workloads=self.d.workloads)
        self.issuer, self.audience = issuer, audience
        self.assume_stepup = assume_stepup_passes
        self._day: Optional[int] = None
        self._lock = threading.Lock()
        self.pending_caep: List[dict] = []

    # ------------------------------------------------------------------ events
    def process(self, record: dict) -> List[dict]:
        """Process one OCSF record. Returns the outputs it caused (possibly none)."""
        with self._lock:
            e = from_ocsf(record, self.d)
            if e is None:
                return []
            eng = self.engine
            if self._day is None:
                self._day = int(e.t // 24) + 1
            while e.t >= self._day * 24:
                eng.end_of_day(self._day)
                self._day += 1
            n_lv = len(eng.level_log)
            dec = eng.decide(e)
            allowed = dec == P.ALLOW
            if dec == P.STEP_UP and self.assume_stepup:
                eng.confirm_stepup(e.account, e.t)
                allowed = True
            ev = eng.observe(e, allowed)
            out: List[dict] = []
            if dec != P.ALLOW or ev:
                out.append({"type": "decision", "time": record["time"], "account": e.account, "kind": e.kind, "decision": dec,
                            "evidence": [{"subject": x.subject, "kind": x.kind, "weight": round(x.weight, 3), "why": x.desc} for x in ev]})
            for (t, s, old, new) in eng.level_log[n_lv:]:
                out += self._level_outputs(t, s, old, new)
            return out

    def process_many(self, records: Iterable[dict]) -> Iterator[dict]:
        for r in records:
            yield from self.process(r)

    def _level_outputs(self, t, s, old, new) -> List[dict]:
        reason = next((x.kind for x in reversed(self.engine.trust.evidence(s)) if x.weight > 0), "evidence")
        t_epoch = (self.d.epoch_ms + t * 3_600_000) / 1000
        out = [{"type": "level", "time": int(t_epoch * 1000), "subject": s, "from": old, "to": new,
                "trust": round(self.engine.trust.trust(s, t), 3)}]
        for sset in caep_set(s, old, new, t_epoch, self.issuer, self.audience, reason):
            out.append({"type": "caep", "set": sset})
            self.pending_caep.append(sset)
        return out

    # ------------------------------------------------------------------ queries and human decisions
    def status(self, subject: str) -> dict:
        eng = self.engine
        t = max([x.t for x in eng.trust.evidence(subject)] or [0.0])
        if self._day is not None:
            t = max(t, (self._day - 1) * 24)
        return {"subject": subject, "level": int(eng.subject_level(subject)), "computed_level": int(eng.level[subject]),
                "trust": round(eng.trust.trust(subject, t), 3), "open_case": eng.cases.get(subject),
                "evidence": [{"t": round(x.t, 3), "kind": x.kind, "weight": round(x.weight, 3), "why": x.desc}
                             for x in eng.trust.evidence(subject) if x.weight > 0][-20:]}

    def review(self, subject: str, confirmed: bool, reviewer: str = "reviewer") -> dict:
        with self._lock:
            eng = self.engine
            if subject not in eng.cases:
                return {"ok": False, "error": "no open case"}
            t = eng.cases[subject]["opened"]
            n_lv = len(eng.level_log)
            eng.review(subject, confirmed, t, reviewer)
            outs = []
            for (tt, s, old, new) in eng.level_log[n_lv:]:
                outs += self._level_outputs(tt, s, old, new)
            return {"ok": True, "outputs": outs}

    def take_caep(self, max_events: int = 100) -> List[dict]:
        """Poll pending CAEP SETs (removes them), in the spirit of SSF poll delivery."""
        with self._lock:
            out, self.pending_caep = self.pending_caep[:max_events], self.pending_caep[max_events:]
            return out

    def verify_ledger(self) -> dict:
        ok, bad = self.engine.ledger.verify()
        return {"ok": ok, "entries": len(self.engine.ledger.entries), "first_bad": bad}
