# Metrics

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

NullProtocol Negative Trust needs its own metrics that show measurable benefit against insider threats. Detection rates alone are
misleading for insider threats (extreme class imbalance; see the 2026 CERT-dataset review), so NullProtocol Negative Trust Architecture
measures **harm**, **speed**, **fairness** and **cost**, always side by side.

## 1. Effectiveness

| Metric | Definition | Why |
|---|---|---|
| **Harm prevented (HP)** | `1 − realised / planned` bytes of hostile egress, summed over hostile scenarios | What the organisation actually cares about; rewards early containment, not alerts |
| **Containment rate** | Share of hostile scenarios in which a responsible subject reaches ≥ L3 (or a confirmed case) | Did the system stop the actor at all? |
| **Time to containment (TTC)** | Hours from scenario onset to the first ≥ L3 of a responsible subject; median over scenarios | Insider damage grows with dwell time |
| **Flag rate** | Share of scenarios where the responsible subject reached ≥ L1 or had a case | Early visibility, even if containment was not justified |

## 2. Fairness and proportionality

| Metric | Definition | Why |
|---|---|---|
| **Victim blamed** | Share of hijacked-account and impersonation scenarios in which the *owner* (person) reached ≥ L3 | Measures attribution (P4); blaming victims is both unfair and a legal risk |
| **Negligent over-containment** | Share of negligent scenarios in which the employee reached ≥ L3 | A negligent employee needs guard rails, not isolation (P6) |
| **Innocents contained per 1000 user-days** | Innocent persons who reached ≥ L3 at any time, normalised | The most important cost metric for employees and works councils |
| **Innocent cases per 1000 user-days** | Cases opened (alerts or L4) on innocent persons | Reviewer workload and stress for employees |
| **Case precision** | Share of cases that concern a real attacker | Whether reviewers' time is spent on real incidents |

## 3. Friction

| Metric | Definition |
|---|---|
| **Innocent step-ups per 1000 user-days** | Step-up authentications demanded from innocent employees (max one per account and day) |
| **Innocent dual-control requests per 1000 user-days** | Egress/bulk/admin actions of innocent employees that needed a second approver |
| **Innocent denied actions** | Actions of innocent employees that were blocked (by policy or by a wrong approver decision) |

## 4. Accountability

| Metric | Definition |
|---|---|
| **Ledger integrity** | `Ledger.verify()` succeeds for every run (any tampering is detected and located) |
| **Explanation coverage** | Every evidence item carries a human-readable description; every case lists its evidence (100 % by construction) |
| **Re-identification events** | Number of four-eyes re-identifications (granted / denied), all ledgered |

## 5. Benchmark metrics (OrgForge-IT)

Triage precision/recall/F1, verdict F1, baseline false-positive rate (innocents escalated), vishing detection and
host-trail reconstruction, computed with a re-implementation of the official scoring code. We additionally report
escalations decided before the onset day, because the official "onset sensitivity" counts any escalated subject who
has pre-onset records, which is not what its documentation describes.

## 6. Replay metrics (CERT r4.2)

| Metric | Definition |
|---|---|
| **Incident detected** | A case was opened for the insider (person or account) no later than 7 days after the labelled end of the incident |
| **Innocent users ever restricted** | Users without any incident who reached L3 (read-only) at some point, per 1,000 users |
| **Would-be prevented** | Share of an incident's logged events that happened after the insider would have reached L3 |

## 7. Proposed composite: NullProtocol Negative Trust Efficiency (NTE)

For comparing configurations on one number (secondary to the full table):

```
NTE = HP × (1 − victim_blamed) / (1 + innocents_contained_per_1000_user_days + 0.01 × innocent_stepups_per_1000_user_days)
```

It rewards prevented harm, punishes blaming victims and charges for friction. The weighting is a policy
choice and should be agreed with employee representatives. The cross-organisation tuning uses a linear objective
with the same ingredients, documented in `src/npcore/tune.py`.
