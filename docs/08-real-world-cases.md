# Real-world cases (v0.4)

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

Each case below reproduces the attack path of a publicly documented incident in the simulator
(`src/npcore/sim_cases.py`, scenario set `cases`), next to benign look-alikes that a naive rule would flag:
verified and unverified password resets followed by a new laptop, single mistaken push denials, a return from
parental leave, support agents' rare look-ups without a ticket, integration traffic with peaks, adware findings,
a ticketed MFA policy change by IT, and leavers who simply stop working.

| Case | Source | Attack path in the simulator | Detection (v0.4) | Principal |
|---|---|---|---|---|
| Help desk MFA reset | MGM Resorts 2023 ([Bloomberg](https://www.bloomberg.com/news/articles/2023-09-16/mgm-resorts-hackers-broke-in-after-tricking-it-service-desk)) | Unverified reset of a privileged user, sign-in from a new device, new identity provider, data out | Reset → new-device sign-in within 24 h; identity configuration change | Account |
| MFA fatigue | Uber 2022 ([InfoQ](https://www.infoq.com/news/2022/09/Uber-breach-mfa-fatigue)) | 9–16 denied pushes at night, one approval, new-device sign-in | Push bombing, then new-device sign-in | Account |
| Session token from a support file | Okta 2023 ([BleepingComputer](https://www.bleepingcomputer.com/news/security/okta-breach-134-customers-exposed-in-october-support-system-hack/)) | Admin session replayed by another client while the owner is offline; admin API token created | Session presented by a different client | Account |
| Old password, no MFA | Snowflake 2024 ([TechCrunch](https://techcrunch.com/2024/06/05/snowflake-customer-passwords-found-online-Infostealing-malware/)) | Account unused for weeks, sign-in without MFA from abroad, bulk export | Dormant reuse from a new device or without MFA | Account |
| Integration OAuth token | Salesloft Drift 2025 ([Security Affairs](https://securityaffairs.com/?p=181632)) | Integration token used from a new network, bulk exports, searches for keys and passwords | New network, export volume, secret search | Integration |
| Bribed support agents | Coinbase 2024/25 ([The Register](https://www.theregister.com/2025/05/21/coinbase_confirms_insider_breach_affects/)) | Two agents look up customer records without tickets for weeks | Purpose binding, look-up spikes | Person |
| Former employee | Cash App 2022 ([UpGuard](https://www.upguard.com/blog/how-did-the-cash-app-data-breach-happen)) | Access continues after the end date; reports copied | Activity after termination | Person |
| Fake remote worker | KnowBe4 2024 ([CyberScoop](https://cyberscoop.com/cyber-firm-knowbe4-hired-a-fake-it-worker-from-north-korea/)) | New hire's laptop: infostealer and remote-access tool, repositories copied | Endpoint findings | Person |

## Results (held-out seeds 301–320; unseen organisation types 601–610)

Every architecture uses the same v0.4 signals, so the difference is the architecture.

| | Data stopped | Attacks contained | Victim blamed | Case precision | Innocents restricted / 1,000 user-days |
|---|---|---|---|---|---|
| Zero-trust baseline, automatic | 95.3 % | 50 % | 80 % | 54 % | 0.09 |
| Zero-trust baseline + correlation + decoys | 97.1 % | 50 % | 80 % | 47 % | 0.22 |
| Zero trust + NullProtocol Negative Trust v0.3 | 75.7 % | 51 % | 38 % | 66 % | 0.24 |
| **Zero trust + NullProtocol Negative Trust v0.4** | **99.4 %** | **100 %** | **7 %** | **92 %** | 0.32 |

Unseen organisation types: v0.4 stops 99.4 %, contains 100 %, blames the victim in 3 %, precision 86 %.

What this shows:
* **The new signals do most of the harm prevention**, and any zero-trust stack could use them. The extension's
  contribution is attribution: in five of the eight cases the attacker acts through someone else's account, and
  without attribution the employee whose account was taken is the one restricted (80 %).
* **The stolen support-file session** is contained only with the extension (session presented by another client).
* **Cost:** about 1.5 to 1.7 times as many step-ups and three to four times as many innocents restricted as the
  automatic baseline, each released by review.
* Standard and adaptive attack sets: v0.4 gives the same results as v0.3 (no regression).
* The baselines are our own re-implementations, and the attack paths are reconstructions from public reporting,
  not the original logs.
