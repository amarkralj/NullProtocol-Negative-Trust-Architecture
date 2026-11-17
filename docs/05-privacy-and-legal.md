# Privacy and legal considerations

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

> **Not legal advice.** This document lists the privacy and legal questions that an organisation deploying an
> insider-risk system like NullProtocol Negative Trust Architecture has to answer, shows how the architecture addresses each one, and names
> what stays open. It covers the European Union (with Germany as the most demanding member state for employee
> monitoring) and the United States (federal law and the state laws that apply most directly). Laws change; every row
> was checked on 17 November 2026 and links to its source. Other jurisdictions are not yet covered.

## 1. What applies everywhere

Whatever the jurisdiction, the same design choices keep an insider-risk system defensible, and NullProtocol Negative Trust Architecture
implements all of them by default:

* **Tell employees.** Monitoring and the existence of decoys are disclosed in general terms (not where decoys are).
* **Collect metadata, not content.** Logins, file operations, egress volumes and grants; no reading of messages.
  The message-tone signal is optional and off in the recommended configuration (`nt_no_sentiment`).
* **Pseudonymise.** The engine and analysts see pseudonyms; re-identification needs two people.
* **Machines restrict access; humans decide about people.** Containment is graduated and reversible; any employment
  consequence is a human decision after review, and the person can respond.
* **Keep an audit trail.** Every piece of evidence and every decision is in a tamper-evident ledger.
* **Protect whistleblowers.** Reporting channels and regulators are allow-listed and never scored as exfiltration.
* **Measure fairness.** False containment, friction for innocent staff and victim blaming are reported metrics.

## 2. Summary table (EU and US)

| Jurisdiction | Law or rule | Main question for NT | How NullProtocol Negative Trust Architecture addresses it | Residual risk |
|---|---|---|---|---|
| EU | GDPR Art. 6, 88 (legal basis) | Which basis allows monitoring employees for insider threats? | Purpose limited to security; Art. 6(1)(c)/(f) with documented balancing test; collective agreement under Art. 88 where available | Medium; in Germany § 26 BDSG is no longer a safe sole basis after CJEU C-34/21 |
| EU | GDPR Art. 5, 25, 32 (minimisation, pseudonymisation) | Is the processing proportionate? | Metadata only by default; pseudonyms; four-eyes re-identification; fast decay of weak evidence | Low–medium |
| EU | GDPR Art. 35 (DPIA) | Is an impact assessment needed? | Yes; metrics and evaluation provide the risk inputs | Low if done |
| EU | GDPR Art. 22 (automated decisions) | Is automatic containment a decision with significant effect? | L1–L3 restrict access reversibly; L4 opens a case with a review deadline; humans decide about the person | Medium: L4 needs staffed review |
| EU | AI Act Art. 3(1), Annex III 4(b), Art. 5(1)(f) | Is NT an AI system? High-risk? Prohibited emotion recognition? | v0.1 is rule-based with hand-set weights; tone signal optional and off by default | Medium: learned components would likely be high-risk (obligations from 2 Dec 2027) |
| EU | NIS2 Art. 21 | Does NT help meet security obligations? | Supports HR security, access control and incident handling; produces audit evidence | Positive |
| EU | Whistleblower Directive 2019/1937 | Could NT punish a protected report? | Reporting channels and authorities allow-listed | Must be configured |
| DE | BetrVG § 87(1) no. 6 (works council) | Is co-determination required? | Yes; technical guarantees can be written into a works agreement (template in [05a](05a-works-agreement-outline.md)) | Low if agreed |
| DE | TDDDG § 3 (telecommunications secrecy) | Does permitted private use of e-mail bind the employer? | No content inspection; metadata only | Depends on private-use policy |
| US (federal) | ECPA: Wiretap Act, 18 U.S.C. § 2511; Stored Communications Act, § 2701 | May an employer intercept or access employee communications? | NT does not intercept content; it consumes logs from the employer's own systems (provider and consent exceptions); disclosure via notice | Low |
| US (federal) | NLRA § 7 | Could monitoring chill protected concerted activity (e.g. organising)? | Security purpose only; no content analysis; no tone signal by default; works-agreement-style policy forbidding use for other purposes | Low–medium; the NLRB General Counsel's 2022 surveillance memo (GC 23-02) was rescinded in Feb 2025, the statute is unchanged |
| US (federal) | Title VII, ADA, ADEA (disparate impact) | Could scores fall harder on a protected group? | Fairness metrics; only security behaviour signals, no demographic data; human review | Medium: needs monitoring per group in deployment |
| US (federal) | FCRA | Is a third-party monitoring report a "consumer report"? | NT runs in-house; no third-party dossiers | Low; CFPB Circular 2024-06 (which said such reports can be) was withdrawn in May 2025, the statute is unchanged |
| US (federal) | Defend Trade Secrets Act, 18 U.S.C. § 1836, § 1833(b) | Does protecting trade secrets justify monitoring? Whistleblower immunity? | Reasonable secrecy measures are a precondition for protection; disclosures to government/attorneys are allow-listed | Positive |
| US (federal) | 32 CFR Part 117 (NISPOM) § 117.7(d), § 117.18 | Are cleared defence contractors required to run an insider-threat program? | Yes, including user activity monitoring on classified systems; NT's ledger and case workflow fit the program | Positive (for cleared contractors) |
| US (NY) | Civil Rights Law § 52-c | Notice before monitoring e-mail, phone, internet use? | Written notice at hire, acknowledged, and posted; NT is targeted at individuals, so the systems-administration exception does not cover it | Low if notice given |
| US (CT) | Gen. Stat. § 31-48d, expanded from 1 Oct 2026 | Notice of electronic monitoring? | Prior written notice and posting; new hires get a list of prohibited activities that may be monitored without notice | Low if notice given |
| US (DE) | 19 Del. C. § 705 | Notice of monitoring? | Daily electronic notice or one-time acknowledged notice | Low if notice given |
| US (ME) | LD 61 (2025–26 session), in force since July 2026 | Notice and limits on monitoring? | Notice before monitoring and posted policy; NT does not monitor homes or personal devices | Low if notice given |
| US (CA) | CCPA/CPRA (employee data since 2023); CPPA rules on automated decision-making technology and risk assessments, compliance from 1 Jan 2027 | Notice, access/deletion rights, opt-out and appeal for automated "significant decisions", risk assessment | Notice at collection; ledger supports access requests; humans make employment decisions (human-involvement path); risk assessment from metrics | Medium for large California employers |
| US (CO) | SB 26-189 (replaced the 2024 Colorado AI Act), effective 1 Jan 2027 if rules are in place | Does an automated system make consequential employment decisions? | NT does not make employment decisions; containment is an access control | Low; enforcement currently subject to a federal court stay |
| US (IL) | Human Rights Act as amended by HB 3773 (P.A. 103-0804), since 1 Jan 2026 | Is AI used in employment decisions with discriminatory effect or without notice? | No employment decisions by the system; notice if a learned component is added | Low; notice rules from IDHR still pending |

## 3. United States in more detail

**No general employee-privacy law, but notice everywhere.** US federal law allows monitoring of employer systems
when there is a business purpose or consent; the practical rule is notice. New York requires an acknowledged written
notice at hire and a posted notice for monitoring of phone, e-mail and internet use
([Morrison Foerster](https://www.mofo.com/resources/insights/211115-new-york-enacts-employee-monitoring-notification-law));
Connecticut expanded its notice law from 1 October 2026, including a statement to new hires
([Day Pitney](https://daypitney.com/expanded-connecticut-electronic-monitoring-law-takes-effect)); Delaware
offers a daily reminder or a one-time acknowledged notice; Maine's LD 61 added notice and limits in July 2026
([Fisher Phillips](https://www.fisherphillips.com/en/news-insights/maine-sets-new-restrictions-on-workplace-monitoring-and-surveillance.html)).
Connecticut and Maine allow monitoring without prior notice when there are reasonable grounds to believe an
employee is breaking the law or violating the employer's rights, which matches NT's case-based escalation.

**Automated decisions.** California's CPPA rules on automated decision-making technology apply from
1 January 2027 to "significant decisions" about employees made without meaningful human involvement, and require
risk assessments for systematic observation of employees
([Littler](https://littler.com/news-analysis/asap/californias-long-awaited-final-regulations-automated-decisionmaking-create-new)).
Colorado replaced its 2024 AI Act with the narrower SB 26-189, effective 1 January 2027
([Skadden](https://www.skadden.com/insights/publications/2026/06/colorado-repeals-and-replaces-its-ai-act)).
Illinois prohibits discriminatory use of AI in employment decisions and requires notice
([Epstein Becker Green](https://www.ebglaw.com/workforce-bulletin/illinois-prohibits-discriminatory-artificial-intelligence-in-employment-decisions)).
NT keeps employment decisions with humans and records the evidence each decision rests on, which is the strongest
position under all three.

**Federal guidance that was withdrawn.** The NLRB General Counsel memo GC 23-02 on electronic surveillance was
rescinded on 14 February 2025 ([SHRM](https://www.shrm.org/mena/topics-tools/employment-law-compliance/nlrb-general-counsel-memos-from-biden-administration-revoked)),
and CFPB Circular 2024-06 on worker-surveillance reports under the FCRA was withdrawn on 12 May 2025
([Digital Policy Alert](https://digitalpolicyalert.org/event/29976-consumer-financial-protection-bureau-withdrew-guidance-on-protecting-workers-from-unchecked-digital-tracking-and-opaque-decision-making-systems-circular-2024-06)).
The underlying statutes are unchanged and the guidance may return; designing as if it applied costs little.

**Required programs.** Cleared defence contractors must run an insider-threat program under 32 CFR Part 117
(NISPOM), including user activity monitoring on classified systems
([eCFR § 117.7](https://www.ecfr.gov/current/title-32/subtitle-A/chapter-I/subchapter-D/part-117/section-117.7)).

## 4. European Union in more detail

### 4.1 Data protection (GDPR, BDSG)

**Legal basis.** In its judgment of 30 March 2023 (C-34/21) the CJEU held that a national clause that merely
repeats the GDPR is not a "more specific rule" under Art. 88 GDPR. The provision examined (§ 23 HDSIG) is almost
identical to § 26(1) sentence 1 BDSG, so the prevailing view is that § 26(1) BDSG can no longer be relied on as the
sole legal basis; processing must be justified directly under Art. 6 GDPR, and its documentation should say so
([dr-datenschutz](https://www.dr-datenschutz.de/eugh-kritik-am-deutschen-beschaeftigtendatenschutz/),
[bitkom-consult](https://bitkom-consult.de/news/europaeischer-gerichtshof-stellt-deutsche-regeln-zum-beschaeftigtendatenschutz-frage)).
A dedicated employee data protection act (Beschäftigtendatengesetz) was presented as a draft in October 2024 and is
reportedly being prepared again in 2026; it is not in force.

Practical basis for NT:
* **Art. 6(1)(c)** where security measures are legally required (e.g. risk-management obligations of NIS2 entities),
  and **Art. 6(1)(f)** (legitimate interest in protecting data and systems), with a documented balancing test. The
  Trade Secrets Act (GeschGehG) supports the legitimate interest: information is only protected as a trade secret if
  "appropriate secrecy measures" are in place (§ 2 no. 1 lit. b GeschGehG); it is a precondition, not an obligation.
* A **works agreement** (Betriebsvereinbarung) under Art. 88 GDPR that contains the safeguards of Art. 88(2): this is
  where the technical guarantees of NT (pseudonymisation, four-eyes re-identification, retention, no content
  analysis by default, human review) become binding.
* Consent is not suitable as the main basis in employment relationships (imbalance of power).

**Principles (Art. 5, 25, 32).** NT supports them technically:
* *Data minimisation:* only metadata events (login, file, egress, grant). Content inspection is not needed. The
  optional message-tone signal processes content-derived data and is **off in the recommended configuration**
  (preset `nt_no_sentiment`); the evaluation reports what that costs.
* *Pseudonymisation:* analysts and the engine see only HMAC pseudonyms; the key is held by a separate role.
* *Storage limitation:* weak evidence decays in days; evidence on persons cleared by review should be deleted after
  a short period. Tension with an immutable ledger is solved by storing only pseudonyms and hashes in the chain and
  using per-subject encryption keys for payloads ("crypto-shredding"; roadmap).
* *Transparency (Art. 13/14):* employees are informed that insider-risk monitoring and decoys exist, what categories
  of data are processed and how review works. They are not told where decoys are.

**DPIA (Art. 35).** Systematic monitoring of employees with new technology is very likely to require a DPIA.
`docs/03-metrics.md` and the evaluation give the risk inputs (false containment rates, friction, victim blaming).

**Automated decision-making (Art. 22).** Graduated containment (step-up, dual control, read-only) is a security
control on access, reversible and not a decision about the employment relationship. Isolation (L4) can
significantly affect a person's work; NT therefore opens a case with a review SLA, and any employment consequence
(warning, dismissal, criminal complaint) is taken only by humans on the basis of the ledgered evidence. The person
must be able to present their view.

**Telecommunications secrecy.** Whether employers that permit private use of e-mail/internet are bound by
telecommunications secrecy (§ 3 TDDDG) is disputed. NT avoids the issue by design: it does not inspect content and
works on metadata; the position depends on the specific company policy on private use.

### 4.2 Co-determination in Germany (BetrVG)

Technical systems that are *suitable* to monitor employee behaviour or performance require the works council's
agreement (§ 87(1) no. 6 BetrVG); actual intent to monitor is not required. NT clearly falls under this.
Proposed content of the works agreement (template in [05a-works-agreement-outline.md](05a-works-agreement-outline.md)):
purpose limitation, list of signals, decoy policy, containment levels and SLAs, re-identification rule, retention,
evaluation metrics reported to the works council quarterly, prohibition of performance evaluation with NT data.

### 4.3 EU AI Act

* **Is NT an "AI system"?** Recital 12 excludes systems "based on the rules defined solely by natural persons to
  automatically execute operations"; the Commission guidelines on the AI system definition (2025, non-binding)
  confirm that classical heuristic and simple rule-based systems are excluded, to be assessed case by case
  ([Commission](https://digital-strategy.ec.europa.eu/en/library/commission-publishes-guidelines-ai-system-definition-facilitate-first-ai-acts-rules-application)).
  NT v0.1 uses hand-set weights and robust statistics; there is a reasonable argument that it is not an AI system.
  Any learned component (e.g. learned weights, anomaly models) would change this.
* **High-risk:** Annex III point 4(b) covers AI systems intended "to monitor and evaluate the performance and
  behaviour of persons" in work relationships ([text](https://artificialintelligenceact.eu/annex/3/)). A learned NT
  variant would very likely be high-risk. After the Digital Omnibus (Regulation (EU) 2026/1744), obligations for
  Annex III systems apply from **2 December 2027**
  ([Gibson Dunn](https://www.gibsondunn.com/eu-ai-act-omnibus-agreement-postponed-high-risk-deadlines-and-other-key-changes/)).
  NT's ledger, explanations, human oversight and metrics map well onto the high-risk requirements (logging,
  transparency, human oversight, accuracy reporting).
* **Prohibitions (Art. 5, applicable since 2 February 2025):** Art. 5(1)(f) prohibits AI systems that infer emotions
  of natural persons in the workplace (except medical or safety reasons). The AI Act defines emotion recognition
  systems by reference to biometric data, so text tone analysis is arguably outside, but this is contested and a
  reputational risk; hence the message-tone signal is optional and off in the recommended configuration.
  Art. 5(1)(c) (social scoring) does not apply to a security-scoped, context-bound trust value that is not used for
  unrelated detrimental treatment, but the works agreement should prohibit any reuse of trust values outside security.

### 4.4 NIS2

NIS2 Art. 21(2) lists risk-management measures including "human resources security, access control policies and
asset management" and incident handling. NT supports these measures and produces evidence (ledger, metrics) for
audits. It does not by itself make an entity compliant.

## 5. Deception (all jurisdictions)

* Planting decoys in the employer's own systems (files, accounts, records) is a security measure on the employer's
  property. Unlike state agents, employers are not subject to the criminal-procedure doctrine on entrapment, but
  decoys must not *induce* misconduct: they are placed where no legitimate workflow leads and are not advertised to
  any individual.
* Decoys must not contain real personal data. NT's generator creates synthetic content.
* **Usability as evidence:** German labour courts decide case by case whether evidence from monitoring can be
  used, weighing the employee's personality rights against the employer's interests. A documented, proportionate,
  works-council-agreed process with a tamper-evident ledger strongly improves the position. The outcome
  depends on the concrete scenario.
* Contextual strength (P3) is also a fairness safeguard: a curiosity click inside one's own department is weak,
  fading evidence and cannot by itself lead to containment above L1.

## 6. Whistleblower protection

In the EU, the Whistleblower Directive (in Germany the HinSchG) protects reporting; in the US, the DTSA immunity (18 U.S.C. § 1833(b)) and sector statutes such as SOX protect disclosures to authorities. These laws protect reporting through internal and external channels and, under conditions,
disclosure. An insider-risk system must not treat a protected report as exfiltration. Configuration requirements:
the internal reporting channel and the federal and state external reporting offices are allow-listed destinations;
evidence from reports to them is not generated; any case touching a possible report is routed to the reporting
office, not to line management.

## 7. Open legal questions

1. Is the legal basis set (Art. 6(1)(c)/(f) GDPR + works agreement under Art. 88) sufficient for the target company type?
2. Is graduated containment L1–L3 outside Art. 22 GDPR, and under which conditions is L4?
3. Is NT v0.1 an AI system under Art. 3(1) AI Act, and which changes would make it one?
4. Can decoy evidence and ledger records be used in labour-court proceedings (Beweisverwertung)?
5. What is the telecommunications-secrecy position for companies permitting private use?
6. Are the works agreement outline and the whistleblower configuration sufficient?
7. (US) Which state notice laws apply to a remote workforce spread across states, and does one notice satisfy all?
8. (US, California) Is L4 isolation a "significant decision" under the CPPA rules, or an access control outside them?
9. (US) How should disparate-impact monitoring be done without collecting demographic data in the security system?
