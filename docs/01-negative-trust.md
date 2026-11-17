# NullProtocol Negative Trust: definition, principles and a formal model

*NullProtocol Negative Trust Architecture, working paper v0.3, 17 November 2026. Author: [github.com/amarkralj](https://github.com/amarkralj). Status: draft for discussion.*

## Abstract

Zero trust verifies every access request with a trust algorithm inside the policy engine (NIST SP 800-207). We
define **NullProtocol Negative Trust (NT)**, an extension of that trust algorithm for insider threats: trust is a signed, evidence-driven quantity that starts at zero
and can become negative; misuse is remembered longer than normal behaviour; the organisation tests the insider
hypothesis with decoys; evidence is attributed to the principal it proves something about (a hijacked account, not
its owner); and containment is graduated, proportional and reversible, with humans deciding about people. We give a
formal model, a reference architecture that extends NIST SP 800-207, and an open-source implementation, and evaluate
it on top of zero-trust baselines in simulation, on unseen organisation types and on the CERT r4.2 dataset
([04-evaluation.md](04-evaluation.md)).

## 1. Scope: insider threats in a zero-trust architecture

NIST SP 800-207 defines zero trust around a policy decision point (PDP) that evaluates every access request with a
*trust algorithm* using identity, device, context and history, and leaves the choice of algorithm open. NullProtocol
Negative Trust is such an algorithm, extended for insider threats: harm caused by people and accounts that hold
legitimate access, including attackers acting through a stolen account.

Four insider classes need to be covered: **malicious**, **negligent**,
**colluding** and **compromised** insiders. They differ in intent, so a good architecture must also differ
in response: a negligent employee needs a guard rail and training, not isolation; the owner of a hijacked
account is a victim, not a suspect.

## 2. Definition

> **NullProtocol Negative Trust** is a security paradigm in which the trust an organisation places in a principal
> (person, account, device, workload) is a signed quantity derived only from evidence. It is never positive by
> default, it can fall below zero, and it is lowered faster and for longer by evidence of misuse than it is
> raised by evidence of normal behaviour. The organisation actively creates evidence by deploying assets that
> no legitimate workflow needs, responds to distrust with graduated and reversible restrictions, and
> attributes evidence to the principal it actually proves something about.

### 2.1 Principles

| # | Principle | What it means in practice |
|---|---|---|
| P1 | **No default trust, signed trust** | Trust starts at 0 and has no positive default. It can become negative; "distrust" is a state, not just the absence of trust (cf. Marsh & Dibben 2005, *untrust/distrust/mistrust*). |
| P2 | **Evidence asymmetry, against a personal baseline** | Strong negative evidence decays slowly (half-life 30 days); weak statistical anomalies fade fast (4 days); earned trust fades fast (3 days) and is capped, so a long clean history cannot "bank" trust. Strength is judged against the person's own routine: a channel someone uses every week is weak evidence for non-sensitive data. |
| P3 | **Active falsification (deception)** | Plant decoys (files, credentials, accounts, records) that no legitimate process needs. Contact turns a statistical suspicion into a near-certain test. Contact strength depends on context: a curiosity click in one's own share is weak; using a decoy credential is close to proof. |
| P4 | **Attribution to the proven principal** | Evidence from a session whose context is unproven (unknown device and foreign network, a login right after a pretext call to the owner, a session used from two networks at once) is attributed to the *account*, not to the *person*: hijacked accounts are contained, their owners are not blamed. A colleague's account used from one's own device is attributed to the device owner. |
| P5 | **Correlation across steps and people** | Staging → compression → egress chains, call → login links and grant → misuse links produce evidence that single events never show. Distrust propagates along collusion links, damped (factor 0.5) and only for data misuse in the shared scope. |
| P6 | **Graduated, reversible, proportional containment** | L0 observe → L1 step-up → L2 dual control on egress → L3 read-only → L4 isolate with human review. Every level can be lifted. Levels above L2 need evidence of intent (for example repeated transfers to the same destination, staging, decoy contact); careless mistakes get guard rails, not read-only access. |
| P7 | **Human decision for consequences** | Machines restrict access; only humans decide about people. L4 opens a case with an SLA; a dismissal scales the evidence down and lifts containment. |
| P8 | **Privacy and accountability by design** | Pseudonyms everywhere; re-identification only with four-eyes approval and a documented reason; every evidence item, decision and review in a hash-chained ledger. |
| P9 | **Measurable and calibrated** | Every claim comes with a metric, including the cost to innocent employees. Thresholds are set per organisation from a shadow-mode period to a case budget the organisation can review. |

### 2.2 What the extension adds to a zero-trust trust algorithm

| | Zero-trust trust algorithm (NIST SP 800-207) | Extended with NullProtocol Negative Trust |
|---|---|---|
| Adversary model | Outsider or compromised device trying to reach resources | Authenticated insider acting (mostly) within entitlements, plus hijacked accounts |
| Trust default | No implicit trust from network location; access granted when policy is satisfied | Trust 0, never positive by default; can become negative |
| Evidence | Identity, device posture, context per request | Same, plus behavioural history with asymmetric memory, deception, cross-actor correlation |
| Decision | Allow/deny per request (PDP/PEP) | Continuous containment level per principal; per-request decisions derive from it |
| Response | Deny or step-up | Five graduated, reversible levels, human review for isolation |
| Attribution | Usually the user identity | Person vs account (session context decides) |
| Proof | Policy compliance | Falsification via decoys plus a tamper-evident ledger |

NT is an *extension* of zero trust, not a replacement: it runs inside the PDP as a contextual, score-based trust
algorithm (in the terms of SP 800-207) and uses the same enforcement points.

## 3. Formal model

For principal *s* at time *t*, with evidence items *(tᵢ, wᵢ)*:

```
trust(s,t) = T0 + min( P_cap , Σ_{wᵢ<0} |wᵢ| · 2^(−(t−tᵢ)/h_pos) )
                −       Σ_{wᵢ>0}  wᵢ  · 2^(−(t−tᵢ)/h(i))

h(i) = h_strong  if item i is strong (deception, chain, egress to personal destinations, compromise, collusion)
       h_weak    otherwise
```

Defaults: `T0 = 0`, `P_cap = 0.6`, `h_pos = 3 d`, `h_weak = 4 d`, `h_strong = 30 d`. The symmetric model
(`h_pos = h_weak = h_strong = 7 d`, `P_cap = ∞`) is a classic UEBA risk score and serves as the baseline.

Containment level: `L1 < −0.5`, `L2 < −1.5`, `L3 < −2.5`, `L4 < −4.0`.

Decision matrix (`category × level`):

| | L0 | L1 | L2 | L3 | L4 |
|---|---|---|---|---|---|
| read | allow | allow | allow | allow | deny |
| sensitive read | allow | step-up | step-up | deny | deny |
| bulk (copy/archive/mass clone) | allow | allow | dual control | deny | deny |
| egress (external mail with attachment, USB, personal cloud) | allow | allow | dual control | deny | deny |
| admin (grants) | allow | step-up | dual control | deny | deny |

The session level is `max(level(person), level(account))`, but account-level containment only applies to
sessions from unproven contexts (P4). A person is not taken above L2 without evidence of intent (P6). Evidence
weights are listed in `src/npcore/signals.py` and `src/npcore/deception.py`; they are hand-set and readable.
Tuning them on several organisation types and testing on unseen ones changed the results only marginally
([04-evaluation.md](04-evaluation.md)), so the hand-set values are kept.

## 4. Threat model and scope

In scope: malicious data theft (sweep, staging, exfiltration), disgruntled snooping and leaks, negligent leaks,
hijacked accounts (pretext calls, stolen session tokens), a colleague using another employee's account, collusion,
low-and-slow exfiltration, and insiders who know the defences. Out of scope: insiders who avoid every monitored
channel; physical exfiltration (photos of screens); administrators who can disable the system itself (mitigation:
separation of duties and an external ledger anchor); sabotage without data movement.

## 5. Results

See [04-evaluation.md](04-evaluation.md).

## 6. Limitations

The simulator is ours and embodies our assumptions about insiders; the CERT r4.2 dataset is independent but
synthetic. Neither replaces a field trial. NT asks innocent employees for step-up authentication more often than zero
trust and contains more of them, each released by human review; the right operating point is a decision for each
organisation.

## References

* NIST SP 800-207, *Zero Trust Architecture*, 2020. doi:10.6028/NIST.SP.800-207
* S. Marsh, M. R. Dibben, "Trust, Untrust, Distrust and Mistrust – An Exploration of the Dark(er) Side", iTrust 2005, LNCS 3477, pp. 17–33. doi:10.1007/11429760_2
* B. Lindauer, *Insider Threat Test Dataset*, Carnegie Mellon University, 2020. doi:10.1184/R1/12841247
* F. T. Liu, K. M. Ting, Z.-H. Zhou, "Isolation Forest", ICDM 2008. doi:10.1109/ICDM.2008.17
* OpenID Foundation, *Continuous Access Evaluation Profile 1.0*, 29 Aug 2025.
* S. Curry, "The deception game: negative trust in cybersecurity", Zscaler, 21 Jun 2023.
* J. Flynt, *OrgForge-IT: A Verifiable Synthetic Benchmark for LLM-Based Insider Threat Detection*, arXiv:2603.22499, 2026.
* Jurišić & Tomičić, *The CERT Dataset Decade: A Systematic Review of Methodological Evolution and Performance Bias*, 2026 (performance inflation in insider-threat studies).
