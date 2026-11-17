# Prior art and positioning

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

*Checked 16 November 2026, updated 17 November 2026. The aim was to make sure "NullProtocol Negative Trust" as defined here is new, and to build on
what exists instead of repeating it.*

## 1. The term "negative trust"

* In security practice the term was used by Sam Curry (then CISO of Zscaler) in June 2023 for "minimizing the
  available trust to exploit by attackers": using deception, lures and decoys so that *external attackers* cannot
  trust what they see ([Zscaler](https://www.zscaler.com/blogs/cxo-insights/deception-game-negative-trust-cybersecurity)).
  It is a principle, not a model: there is no numeric trust value, no insider focus and no architecture. Other uses
  likewise mean "extend zero trust with deception technology".
* NullProtocol Negative Trust Architecture uses the term in a different and stricter sense: the organisation's trust *in its own actors*
  is a signed quantity that can fall below zero. Deception is one evidence source among several, not the definition.
* In trust research, Marsh & Dibben (2005) separate *untrust*, *distrust* and *mistrust* and argue that distrust is
  not merely low trust ([Springer](https://www.springerprofessional.de/doi/10.1007/11429760_2)). Later work models
  distrust as negative trust values propagating in agent networks. These are social/agent models, not security
  architectures.

**Conclusion:** the phrase exists (deception-oriented, against external attackers), but no published formal model,
reference architecture or open implementation of negative trust *in insiders* as a signed, evidence-driven quantity was
found. This repository provides them.

## 2. Zero trust

NIST SP 800-207 places a *trust algorithm* inside the policy engine of the PDP and distinguishes criteria-based vs
score-based and singular vs contextual algorithms; it does not prescribe the algorithm
([NIST](https://doi.org/10.6028/NIST.SP.800-207)). NT is a concrete contextual, score-based trust algorithm for this slot, extended
with signed trust, asymmetric memory, deception, person/account attribution,
graduated containment. Session revocation can be propagated with the OpenID **Shared Signals Framework / CAEP 1.0**
(Final Specification, 2025), whose `session-revoked` and `risk-level-change` events fit NT's containment levels
([CAEP 1.0](https://openid.net/specs/openid-caep-1_0-final.html)).

## 3. Insider threat detection (UEBA)

* Commercial user and entity behaviour analytics (UEBA) and insider-risk products are a mature market. NT does not
  compete as "another detector"; its contribution is the architecture around detection.
* Academic work is dominated by the synthetic CERT r4.2/r6.2 datasets. A 2026 systematic review of 131 studies
  finds performance inflation from dataset-version bias and inconsistent evaluation and recommends hybrid methods
  tested under extreme imbalance ([review](https://fvv.um.si/rV/arhiv/2026/2026-02-Jurisic-Tomicic-E.html)).
* **OrgForge-IT** (March 2026) is a newer synthetic benchmark with deterministic ground truth, cross-surface
  scenarios (ghost logins, vishing, three-phase hoarding) and a public leaderboard of LLM pipelines
  ([arXiv:2603.22499](https://arxiv.org/abs/2603.22499), [dataset](https://huggingface.co/datasets/aeriesec/orgforge-insider-threat)).
  We use it as the external benchmark.

## 4. Deception

* Honeytokens and decoys are well established; vendors claim high-fidelity alerts but independent field
  measurements of detection and false-positive rates are scarce. A 2025 simulation study combining honeytokens with
  Isolation Forest reports high recall on synthetic data only
  ([ResearchGate](https://www.researchgate.net/publication/406985865_HONEYTOKEN-AUGMENTED_AI_MODEL_FOR_INSIDER_THREAT_DETECTION_USING_CYBER_DECEPTION_AND_ISOLATION_FOREST)).
* **PHANTOM** (2026) shows that template honeytokens can be recognised statistically and proposes organisation-mimicking
  tokens ([arXiv:2605.02992](https://arxiv.org/pdf/2605.02992)). NT's decoy generator follows that advice
  (organisational vocabulary and naming patterns).
* Game-theoretic deception design for insider mitigation exists ("duplicity games", [arXiv:2006.07942](https://arxiv.org/pdf/2006.07942)).

**What NT adds:** deception as one evidence source among others, with *context-dependent* strength (curiosity in
one's own share ≠ using a decoy credential), inside a trust model that decides proportionate containment.

## 5. Positioning

| Capability | UEBA/insider-risk tools | Deception platforms | **NullProtocol Negative Trust (on a zero-trust architecture)** |
|---|---|---|---|
| Behavioural anomaly scores | yes | partly | no | yes (explainable, robust statistics) |
| Signed trust with asymmetric memory | no | no | no | **yes** |
| Deception as graded evidence | no | no | alerts only | **yes** |
| Person vs account attribution | rarely | no | no | **yes** |
| Graduated, reversible containment | partly | allow/deny | no | **yes (L0–L4)** |
| Collusion propagation | rarely | no | no | **yes (damped)** |
| Tamper-evident ledger, four-eyes re-identification | varies | no | no | **yes** |
| Open source reference + public evaluation | no | no | no | **yes** |
