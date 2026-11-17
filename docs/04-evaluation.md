# Evaluation

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

All numbers are produced by `scripts/evaluate_release.py` and `scripts/run_tuning.py` and collected by `npcore report`
in `results/RESULTS.md`. Every architecture uses the same signal library, so differences come from the architecture.

## 1. Setup

**Configurations.** Three zero-trust baselines, re-implemented by us inside the same engine (they are not commercial
products): a risk score with SOC alerts (24 h triage); the same score with automatic containment; and automatic
containment plus sequence correlation and decoys. Then the same zero-trust setup extended with NullProtocol Negative
Trust v0.1, v0.2 and v0.3 (message-tone signal off in all three). The comparison shows what the extension adds.

**Simulated organisations.** 150 employees, 60 days, about 190,000 events each, with deliberate benign noise (travel,
new laptops, night work, routine USB and personal-cloud use, IT-support sessions, network handovers). Two attack sets:

* *standard*: data theft, a disgruntled employee, a careless employee, a hijacked account (pretext call), collusion,
  low-and-slow theft;
* *adaptive*: attackers who know the defences: quiet theft to a lookalike domain, a stolen session token, a
  colleague's account used from one's own laptop, a sweep that avoids decoys, collusion without access grants, and a
  careless employee who makes several mistakes.

Simulated people answer step-up prompts, approve or deny dual-control requests and review cases with the same
imperfect rates for every architecture. The results below use seeds never used during development, and two
organisation types (remote-first, night-shift) never used for development or tuning.

**CERT r4.2** (Carnegie Mellon / ExactData; 1,000 users, 17 months, 70 labelled incidents) is replayed in shadow mode
after the same calibration for every architecture: a 60-day learning period, partner domains and shared machines
learned from the logs, and thresholds set to at most five cases per week. Job-search browsing and psychometric data
are not used.

## 2. Simulation: standard attacks

Office organisation, seeds 301–320:

| Architecture | Harm prevented | Attacks contained | Median h to containment | Victim blamed | Careless employee over-contained | Innocents contained / 1,000 user-days | Innocent step-ups / 1,000 user-days |
|---|---|---|---|---|---|---|---|
| Zero-trust baseline, SOC alerts | 65.7 % | 80.0 % | 138.9 | 0 % | 0 % | 0.00 | 8.59 |
| Zero-trust baseline, automatic containment | 90.6 % | 80.0 % | 114.3 | 100 % | 0 % | 0.01 | 11.82 |
| Zero-trust baseline + correlation + decoys | 89.8 % | 80.0 % | 75.4 | 100 % | 0 % | 0.02 | 13.12 |
| Zero trust + NullProtocol Negative Trust v0.1 | 95.6 % | 100 % | 41.8 | 0 % | 0 % | 0.05 | 24.44 |
| Zero trust + NullProtocol Negative Trust v0.2 | 95.5 % | 100 % | 42.0 | 0 % | 5.0 % | 0.04 | 20.95 |
| **Zero trust + NullProtocol Negative Trust v0.3–v0.9** | 95.2 % | 100 % | 42.0 | 0 % | 5.0 % | 0.04 | 20.45 |

Unseen organisation types:

| Architecture | Harm prevented | Attacks contained | Median h to containment | Victim blamed | Careless employee over-contained | Innocents contained / 1,000 user-days | Innocent step-ups / 1,000 user-days |
|---|---|---|---|---|---|---|---|
| Zero-trust baseline, SOC alerts | 65.6 % | 80.0 % | 139.0 | 0 % | 0 % | 0.00 | 18.45 |
| Zero-trust baseline, automatic containment | 88.6 % | 80.0 % | 114.2 | 100 % | 0 % | 0.00 | 25.36 |
| Zero-trust baseline + correlation + decoys | 87.5 % | 80.0 % | 68.0 | 100 % | 10.0 % | 0.02 | 28.44 |
| Zero trust + NullProtocol Negative Trust v0.1 | 96.1 % | 100 % | 41.9 | 10.0 % | 0 % | 0.09 | 50.81 |
| Zero trust + NullProtocol Negative Trust v0.2 | 96.1 % | 100 % | 42.0 | 5.0 % | 10.0 % | 0.08 | 44.29 |
| **Zero trust + NullProtocol Negative Trust v0.3–v0.9** | 96.2 % | 100 % | 42.2 | 5.0 % | 10.0 % | 0.05 | 42.66 |

With the extension, every attack is contained (baselines: four of five, as they do not separate a hijacked account
from its owner), about 2.7 times faster than with the automatic baseline, and the owner of a hijacked account is almost never blamed.
Innocent staff are asked for step-up authentication about 1.7 times as often. On these attacks the gain in harm prevented
is moderate (95–96 % against 88–91 %).

## 3. Simulation: attackers who know the defences

Office organisation, seeds 301–320:

| Architecture | Harm prevented | Attacks contained | Median h to containment | Victim blamed | Careless employee over-contained | Innocents contained / 1,000 user-days | Innocent step-ups / 1,000 user-days |
|---|---|---|---|---|---|---|---|
| Zero-trust baseline, SOC alerts | 8.0 % | 40.0 % | 231.0 | 0 % | 0 % | 0.00 | 14.06 |
| Zero-trust baseline, automatic containment | 10.5 % | 43.0 % | 231.3 | 57.5 % | 25.0 % | 0.02 | 25.56 |
| Zero-trust baseline + correlation + decoys | 13.1 % | 47.0 % | 180.6 | 62.5 % | 95.0 % | 0.13 | 29.69 |
| Zero trust + NullProtocol Negative Trust v0.1 | 39.4 % | 43.0 % | 231.6 | 72.5 % | 75.0 % | 1.93 | 81.36 |
| Zero trust + NullProtocol Negative Trust v0.2 | 40.9 % | 80.0 % | 156.2 | 25.0 % | 100 % | 0.49 | 55.62 |
| **Zero trust + NullProtocol Negative Trust v0.3–v0.9** | 73.2 % | 100 % | 111.7 | 2.5 % | 15.0 % | 0.27 | 55.7 |

Unseen organisation types:

| Architecture | Harm prevented | Attacks contained | Median h to containment | Victim blamed | Careless employee over-contained | Innocents contained / 1,000 user-days | Innocent step-ups / 1,000 user-days |
|---|---|---|---|---|---|---|---|
| Zero-trust baseline, SOC alerts | 8.4 % | 46.0 % | 278.9 | 0 % | 0 % | 0.00 | 25.02 |
| Zero-trust baseline, automatic containment | 14.8 % | 46.0 % | 254.0 | 65.0 % | 30.0 % | 0.11 | 43.69 |
| Zero-trust baseline + correlation + decoys | 20.2 % | 50.0 % | 182.3 | 70.0 % | 95.0 % | 0.22 | 49.12 |
| Zero trust + NullProtocol Negative Trust v0.1 | 50.6 % | 51.0 % | 203.5 | 90.0 % | 85.0 % | 2.24 | 115.18 |
| Zero trust + NullProtocol Negative Trust v0.2 | 51.1 % | 80.0 % | 133.6 | 37.5 % | 100 % | 0.67 | 81.16 |
| **Zero trust + NullProtocol Negative Trust v0.3–v0.9** | 72.9 % | 100 % | 96.8 | 7.5 % | 20.0 % | 0.46 | 79.81 |

With v0.3, 73.2 % of harm is prevented against 13.1 % for the baseline with correlation and decoys, and every
attack is contained. Compared with v0.2 it contains stolen session tokens (v0.2: never), blames victims far less often (25 % →
2.5 %), treats careless employees proportionately (over-contained 100 % → 15 %), and wrongly contains fewer innocent
people (45 % fewer in the office organisation, 31 % fewer on unseen types). The price, against the baselines, is about
twice as many step-ups and about twice as many innocents contained, each released by review.

## 3a. Reconstructions of eight documented attacks (v0.4)

Scenario set `cases` ([08-real-world-cases.md](08-real-world-cases.md)); office organisation, seeds 301–320:

| Configuration | Data stopped | Attacks contained | Victim blamed | Case precision | Innocents contained / 1,000 user-days |
|---|---|---|---|---|---|
| Zero-trust baseline, automatic containment* | 95.3 % | 50.0 % | 80.0 % | 54.1 % | 0.09 |
| Zero-trust baseline + correlation + decoys* | 97.1 % | 50.0 % | 80.0 % | 47.4 % | 0.22 |
| Zero trust + NullProtocol Negative Trust v0.3 | 75.7 % | 51.2 % | 38.0 % | 65.6 % | 0.23 |
| **Zero trust + NullProtocol Negative Trust v0.4–v0.9** | 99.4 % | 100 % | 7.0 % | 91.8 % | 0.32 |

On organisation types never used for development (seeds 601–610), v0.4 stops 99.4 %,
contains 100 %, blames the victim in 3.0 % and has a case precision of
85.7 %. With the same new signals, the zero-trust baselines stop about as much data but contain only
half of the attacks and restrict the employee whose account was taken over in about 80 % of the account-takeover runs.

## 3b. Recorded Okta attack logs (v0.5)

Fifteen recorded Okta System Log attack datasets from [splunk/attack_data](https://github.com/splunk/attack_data)
(Apache-2.0, anonymised by Splunk), read with the Okta adapter. The expected detection for each dataset was written
down before running, from its title and MITRE technique. v0.4 detected 10 of 15. v0.5 adds password-spraying,
impossible-travel, identity-provider-risk and denied-access rules, written after reviewing these logs, and detects
15 of 15; it is therefore not a blind test for v0.5. The datasets contain the attack only, so they show detection,
not false-alarm rates. Per-dataset results: `results/RESULTS.md`.

## 3c. Recorded cloud attack logs (v0.6)

105 recorded attack datasets for Microsoft Entra ID, Microsoft 365 and AWS CloudTrail from
[splunk/attack_data](https://github.com/splunk/attack_data), read with `npcore.cloudlogs`. The expected detection of
each dataset follows from its name by fixed rules (`scripts/run_splunk_cloud.py`), written before the first run; the
numbers below are that first run, and no rule was changed after seeing them.

| Source | Scored | v0.5 | v0.6 | Not readable | Out of scope |
|---|---|---|---|---|---|
| Microsoft Entra ID | 32 | 2 | 26 | 0 | 0 |
| Microsoft 365 | 45 | 6 | 37 | 3 | 3 |
| AWS CloudTrail | 28 | 1 | 26 | 6 | 4 |
| Google Workspace | 0 | | | 0 | 4 |
| **Total** | **105** | **9** | **89** | **9** | **11** |

Out of scope: e-mail content (phishing), container images, code deployment and vendor risk scores. Not readable:
Splunk search exports with flattened fields. Missed (16): password spraying spread over many addresses, concurrent
sessions without a session identifier, sign-ins with many application identifiers, declined consent requests, AWS
role-assumption guessing, and four datasets where v0.6 fired a different signal than the one expected.

## 3d. Golden SAML (OTRF, v0.6)

[OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets) `compound/GoldenSAMLADFSMailAccess`: a forged
SAML token impersonates a privileged user, adds credentials and a delegated permission to an application, and reads
mail through Microsoft Graph. v0.5 detects nothing; v0.6 detects the credential change and the mail access. With a
forged token there is no sign-in to examine, so the evidence is attributed to the impersonated administrator, who is
the victim. Recognising forged tokens (for example a token used without a matching sign-in at the identity provider)
is an open item.

## 3e. Microsoft Sentinel samples (format tests)

Microsoft's published samples for the Sentinel tables `SigninLogs`, `AADNonInteractiveUserSignInLogs`,
`AADServicePrincipalSignInLogs`, `AADManagedIdentitySignInLogs`, `AuditLogs`, `AWSCloudTrail`, `OfficeActivity` and
`Okta_CL` are read by the adapters (`tests/test_cloudlogs.py`). They are schema examples (placeholder values) or
anonymised to a single user, so they test formats, not detection or false alarms.

## 3f. Windows endpoint logs (OTRF, v0.7)

The 113 readable Windows host datasets of [OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets),
read with `npcore.windows` (Windows Security, Sysmon, PowerShell). Expected detection per dataset follows from its
OTRF tactic, fixed before the first run (`scripts/run_otrf_windows.py`).

| Tactic | Datasets | Detected |
|---|---|---|
| Credential theft | 23 | 20 |
| Defence evasion | 38 | 12 |
| Lateral movement | 29 | 9 |
| Discovery | 9 | 1 |
| Persistence | 7 | 3 |
| Execution | 4 | 0 |
| Privilege escalation | 2 | 0 |
| Collection | 1 | 0 |
| **Total** | **113** | **45** |

Credential theft is what the adapter is for: 20 of 23 detected (missed: a protected-mode LSASS patch, a fake
password prompt, Windows Vault reads). Most other datasets record outside-attacker techniques (moving between
machines, code injection) that are the job of an endpoint detection product, and the adapter does not try to
replicate one. OTRF clears the event logs right before each recording; the first run counted that as log tampering
(65 of 113). Those setup events are now removed, which gives the numbers above. These datasets contain attacks only,
so they show detection, not false-alarm rates.

## 4. CERT r4.2

| Architecture | Incidents detected | Scenario 1 | Scenario 2 | Scenario 3 | Innocent users ever restricted / 1,000 | Case precision |
|---|---|---|---|---|---|---|
| Zero-trust baseline, SOC alerts | 24.3 % | 40.0 % | 0 % | 50.0 % | alerts only | 78.7 % |
| Zero-trust baseline, automatic containment | 50.0 % | 96.7 % | 0 % | 60.0 % | 136.6 | 88.1 % |
| Zero-trust baseline + correlation + decoys | 50.0 % | 96.7 % | 0 % | 60.0 % | 140.9 | 82.2 % |
| Zero trust + NullProtocol Negative Trust v0.1 | 25.7 % | 3.3 % | 56.7 % | 0 % | 190.3 | 0.6 % |
| Zero trust + NullProtocol Negative Trust v0.2 | 51.4 % | 96.7 % | 3.3 % | 60.0 % | 46.2 | 90.0 % |
| **Zero trust + NullProtocol Negative Trust v0.3–v0.9** | 50.0 % | 96.7 % | 0 % | 60.0 % | 24.7 | 97.2 % |
| Zero trust + NullProtocol Negative Trust v0.3, tuned weights | 50.0 % | 96.7 % | 0 % | 60.0 % | 7.5 | 100.0 % |

After calibration, v0.2 and v0.3 detect as many incidents as the baselines, and restrict far fewer innocent users. v0.1
has no personal baselines for routine channels; calibration cannot bring its case rate into budget, and it fails.
Scenario 2 (job hunter who steals data before leaving) is missed by design, because job-search browsing is not used.
v0.3's proportionality rule delays read-only containment until there is evidence of intent: the share of incident
activity that falls after the would-be containment is 40.1 % (automatic baseline: 46.0 %).

## 4b. CERT r6.2 and v0.8

r6.2 (4,000 users, about 17 months, 5 labelled insiders, one per scenario), same protocol as r4.2: 60-day learning
period, calibration in days 60–150 to 5 cases per week per 1,000 users, labels used only for scoring
(`scripts/run_cert_r62.py`). r6.2 marks web uploads, so uploads are read as cloud transfers. Every architecture
receives the same HR notice periods (below).

v0.7 detected only scenario 1. Diagnosis: the other insiders exfiltrate over channels they use routinely, and
routine use was weak evidence. v0.8 adds two signals, designed after that diagnosis: HR notice periods (routine
egress by someone who has resigned counts as evidence again) and a burst rule against the person's own weekly rate.
CERT has no resignation dates; a departure is taken from the monthly LDAP snapshots and assumed to be known 30 days
before the last month. The weights were trained on r4.2 only (`scripts/train_v08.py`), with the constraint that
r4.2 detection and false alarms stay at least as good as v0.7:

| r4.2 (training) | Detected | Prevented | Innocent users restricted (L3+) / 1,000 |
|---|---|---|---|
| v0.7 | 50.0 % | 40.1 % | 24.7 |
| **v0.8** (notice 0.5, burst off) | **50.0 %** | **46.7 %** | **24.7** |
| notice 1.2 (rejected: more false alarms) | 62.9 % | 49.0 % | 25.8 |

The burst rule raised r4.2 false alarms at every weight tried and is off (weight 0). r6.2, held out, run once:

| Architecture | Insiders detected | Innocent users restricted (L3+) / 1,000 | Innocent users with a case / 1,000 | Case precision |
|---|---|---|---|---|
| Zero-trust baseline, alerts only* | 0 of 5 | 16.0 | 16.0 | 0.9 % |
| Zero-trust baseline, automatic containment* | 1 of 5 | 100.9 | 35.5 | 0.3 % |
| Zero-trust baseline + correlation + decoys* | 1 of 5 | 44.3 | 7.3 | 2.4 % |
| Zero trust + NullProtocol Negative Trust v0.2 | 1 of 5 | 97.4 | 28.3 | 0.4 % |
| Zero trust + NullProtocol Negative Trust v0.3–v0.7 | 1 of 5 | 81.9 | 33.5 | 0.6 % |
| **Zero trust + NullProtocol Negative Trust v0.8** | 2 of 5 | 82.6 | 34.0 | 0.9 % |

v0.8 detects scenarios 1 and 3; the rejected notice-1.2 variant also detects scenario 2 (3 of 5) at
84.9 innocent users restricted per 1,000. NullProtocol Negative Trust still restricts more innocent users
on r6.2 than the strongest baseline. Simulation, Okta, cloud and Windows results are identical for v0.7 and v0.8.
With five insiders the r6.2 result says little about rates.

## 4c. CERT under a restriction budget (v0.9 protocol)

The protocols in 4 and 4b limit only the number of cases, so a configuration that opens few cases is calibrated to
its most sensitive setting and may restrict many people at L3 without opening a case. From v0.9 every architecture is
also limited to 1 user restricted (L3+) per week per 1,000 users in the calibration window (days 60–150, no labels).
The budget was fixed before the runs (`scripts/run_cert_budget.py`). v0.9 also judges upload routine by breadth
(the main source of false restrictions on r6.2 was uploads to many different ordinary websites); the baselines are
shown with their own signals and with the v0.9 signals.

| Architecture | r4.2 (1,000 users, 70 incidents) | r6.2 (4,000 users, 5 insiders) | r6.1 (4,000 users, 5 insiders, untouched test) |
|---|---|---|---|
| Zero-trust baseline + correlation + decoys* | 36 % / 44.8 % / 14.0 | 0 of 5 / 0.0 % / 1.8 | 0 of 5 / 0.0 % / 1.0 |
| same, with the v0.9 signals* | 26 % / 50.0 % / 12.9 | 1 of 5 / 58.1 % / 24.8 | 1 of 5 / 44.3 % / 16.5 |
| Zero-trust baseline, automatic containment, v0.9 signals* | 19 % / 48.2 % / 12.9 | 1 of 5 / 58.1 % / 20.8 | 1 of 5 / 44.3 % / 15.3 |
| Zero trust + NullProtocol Negative Trust v0.7 | 50 % / 39.7 % / 10.8 | 1 of 5 / 12.7 % / 4.0 | 1 of 5 / 10.9 % / 15.0 |
| **Zero trust + NullProtocol Negative Trust v0.9** | 50 % / 40.4 % / 10.8 | 1 of 5 / 32.2 % / 11.0 | 1 of 5 / 36.4 % / 11.8 |

Each cell: insiders detected / incident activity prevented / innocent users restricted (L3+) per 1,000. Every
architecture is calibrated without labels to at most 5 cases and 1 restricted user per week per 1,000 users, and
receives the same HR notice periods. r6.1 was not used in any development.

Case precision on r6.1: NullProtocol Negative Trust v0.9 50.0 %, baselines with v0.9 signals
1.6–10.0 %. With the v0.4 signals, the baselines detect no insider on r6.2 and r6.1.
The baselines prevent more of each incident because they contain without requiring evidence of intent; Negative
Trust trades that for fewer innocent users restricted. With five insiders per r6 release, the r6 results say little
about rates.

## 5. Scale

1,000 employees, 90 days, three instances of each of the twelve attack types per organisation (1,897,664 events), seeds 201–203:

| Architecture | Harm prevented | Attacks contained | Median h to containment | Victim blamed | Careless employee over-contained | Innocents contained / 1,000 user-days | Innocent step-ups / 1,000 user-days |
|---|---|---|---|---|---|---|---|
| Zero-trust baseline + correlation + decoys | 70.4 % | 63.3 % | 154.7 | 70.4 % | 38.9 % | 0.10 | 41.08 |
| Zero trust + NullProtocol Negative Trust v0.2 | 85.1 % | 90.0 % | 86.2 | 25.9 % | 50.0 % | 0.44 | 84.51 |
| **Zero trust + NullProtocol Negative Trust v0.3–v0.9** | 90.9 % | 100 % | 57.9 | 3.7 % | 11.1 % | 0.23 | 84.1 |

Throughput: about 59,735 events per second per core (pure Python, six runs in parallel on one laptop).

## 6. Learning on some organisations, applying to unseen ones

Weights (in five groups), memory half-lives, the cap on earned trust and the threshold scale were tuned on office,
USB-culture and finance-heavy organisations, with one objective for every architecture (harm prevented minus penalties
for innocents contained, step-ups, victims blamed and over-contained careless employees). The tuned settings were then
applied to organisation types and a dataset never used for tuning:

| | Objective on unseen organisation types, default | tuned | CERT innocent users restricted / 1,000, default | tuned |
|---|---|---|---|---|
| Zero trust + NullProtocol Negative Trust v0.3 | 67.1 | 67.6 | 24.7 | 7.5 |
| Zero-trust baseline + correlation + decoys | 25.0 | 25.4 | – | – |

On unseen simulated organisations the gain is marginal: the hand-set defaults already transfer. On CERT the tuned
weights restrict fewer innocent users at the same detection rate. The release keeps the hand-set weights, which stay
readable and are not learned from employee data; the tuned weights are in `results/tuning.json`.

## 7. Public benchmark: OrgForge-IT

| System | Triage F1 | Verdict F1 | False-positive rate |
|---|---|---|---|
| NullProtocol Negative Trust Architecture (deterministic) | 1.000 | 1.000 | 0.000 |
| NullProtocol Negative Trust Architecture without person/account attribution | 0.800 | 0.800 | 0.021 |
| Best published LLM pipelines (leaderboard snapshot 2026-03-22) | 0.800 | 1.000 | 0.021 |

Without attribution, the engine makes exactly the error of the best LLM pipelines: the victim of a vishing call is
reported as the insider. The benchmark is small (two threat actors among 50 employees) and was not evaluated blind.

## 8. Limits

* The simulator is ours. CERT r4.2 is independent but synthetic. A shadow-mode pilot in a real organisation is the
  next test.
* Settings do not transfer between organisations without the calibration phase.
* A stolen session is detected only when the owner is active at the same time, or when the attacker triggers other
  evidence; an attacker who replays a token while the owner is offline is caught only by behaviour.
* Rates for rare outcomes (victims blamed, careless employees over-contained) rest on 20–40 instances per cell.
