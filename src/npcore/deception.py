# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Deception layer: active falsification of the insider hypothesis.

Decoys are assets that no legitimate workflow needs: a payroll export no process reads, a cloud
key nobody was issued, an admin account nobody owns, a customer record that exists only in the
database. Touching one is strong evidence because the base rate of legitimate contact is near
zero. Different contacts carry different strength: *using* a decoy credential is close to proof,
*viewing* a decoy file in one's own share can be curiosity.

Decoy names are generated from the organisation's own vocabulary (departments, projects,
naming patterns) so they are not trivially recognisable as templates, a weakness of template
honeytokens noted in the literature (e.g. PHANTOM, arXiv 2605.02992).
"""
from __future__ import annotations

import random
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .evidence import Evidence

FILE = "file"
CREDENTIAL = "credential"
ACCOUNT = "account"
RECORD = "record"

# evidential weight per (decoy class, interaction)
WEIGHTS = {
    (FILE, "view"): 0.8,
    (FILE, "copy"): 2.5,
    (FILE, "egress"): 4.0,
    (RECORD, "view"): 1.5,
    (RECORD, "export"): 3.0,
    (CREDENTIAL, "use"): 4.5,
    (ACCOUNT, "login"): 4.5,
}


@dataclass
class Decoy:
    id: str
    cls: str
    name: str
    location: str        # share, repo, wiki page, directory
    dept: Optional[str] = None


@dataclass
class DecoyRegistry:
    decoys: Dict[str, Decoy] = field(default_factory=dict)
    seed: int = 7

    def add(self, decoy: Decoy) -> Decoy:
        self.decoys[decoy.id] = decoy
        return decoy

    def deploy_for_org(self, departments: Dict[str, List[str]], per_dept: int = 3, org: str = "acme") -> List[Decoy]:
        """Create organisation-mimicking decoys. `departments` maps dept -> example real file names,
        which are used to imitate naming conventions."""
        rng = random.Random(self.seed)
        out = []
        topics = {
            "Finance": ["Payroll_export", "Bonus_allocation", "Bank_mandates"],
            "HR": ["Salary_bands", "Performance_reviews", "Termination_list"],
            "Legal": ["Settlement_terms", "MA_target_shortlist", "Litigation_hold"],
            "Sales": ["Key_account_pricing", "Pipeline_master", "Discount_approvals"],
            "Engineering": ["prod_db_credentials", "signing_keys_backup", "infra_secrets"],
            "Product": ["Roadmap_confidential", "Pricing_strategy", "Launch_plan_board"],
        }
        n = 0
        for dept, _examples in departments.items():
            year = 2026
            for _k in range(per_dept):
                base = rng.choice(topics.get(dept, ["Confidential_export"]))
                suffix = rng.choice(["FINAL", "v3", "Q2", "draft", "signed"])
                ext = rng.choice([".xlsx", ".pdf", ".docx", ".csv"])
                d = Decoy(f"dcy-{n:04d}", FILE, f"{base}_{year}_{suffix}{ext}", f"//fs/{dept}/restricted", dept)
                out.append(self.add(d)); n += 1
            if dept == "Engineering":
                out.append(self.add(Decoy(f"dcy-{n:04d}", CREDENTIAL, "AKIA-svc-backup (wiki: runbook-restore)", "wiki/runbooks", dept))); n += 1
            out.append(self.add(Decoy(f"dcy-{n:04d}", RECORD, f"{dept} customer/employee record #9{n:03d}", f"db/{dept.lower()}", dept))); n += 1
        out.append(self.add(Decoy(f"dcy-{n:04d}", ACCOUNT, f"adm-{org}-legacy", "directory", None)))
        return out

    def by_location(self, location: str) -> List[Decoy]:
        return [d for d in self.decoys.values() if d.location == location]

    def check(self, t: float, subject: str, decoy_id: str, interaction: str, subject_kind: str = "person",
              subject_dept: Optional[str] = None) -> Optional[Evidence]:
        """Contextual deception evidence. Viewing a decoy file inside one's own department is
        ambiguous (curiosity, misclick): it is recorded but treated as weak, fading evidence.
        Contact outside one's scope, any credential/account use and any copy/egress of a decoy
        are strong evidence that persists."""
        d = self.decoys.get(decoy_id)
        if d is None:
            return None
        w = WEIGHTS.get((d.cls, interaction), 1.0)
        in_scope = d.cls == FILE and interaction == "view" and subject_dept is not None and d.dept == subject_dept
        if in_scope:
            return Evidence(t, subject, "decoy_file_view_in_scope", 0.5,
                            f"viewed decoy file '{d.name}' in own department share {d.location} (ambiguous: could be curiosity)",
                            subject_kind=subject_kind, behavior="decoy_contact", refs=(d.id,), source="deception_weak")
        return Evidence(t, subject, f"decoy_{d.cls}_{interaction}", w,
                        f"{interaction} of decoy {d.cls} '{d.name}' at {d.location} (no legitimate workflow uses it)",
                        subject_kind=subject_kind, behavior="decoy_contact", refs=(d.id,), source="deception")
