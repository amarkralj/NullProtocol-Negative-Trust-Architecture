# Changelog

## 1.0.0

* New log sources (`npcore.sources`): GitHub audit log and Actions workflow runs, Google Workspace (login, admin,
  Drive, Gmail), Google Cloud audit logs, Kubernetes audit and events, AWS DataSync / replication / S3 object reads,
  Amazon Bedrock model-invocation logs, Microsoft 365 Copilot (Purview export), Linux audit (AI coding CLIs), MCP
  JSON-RPC and Ollama server logs; Okta and Entra device-code sign-ins through the same loader.
* New evidence (`signals_v10`): security control disabled, destructive change, protected push, external share, secret
  access, privileged workload, denied-request and scanner discovery, object-read volume, device-code phishing,
  distributed spraying, concurrent networks used by different clients, a session cookie that jumps, prompt injection,
  credentials in prompts, high-risk agent tools, AI usage spikes, AI CLIs with every approval off (`npcore.aiguard`).
  What an AI agent does is evidence about the agent's own account (`acct:agent:<id>`), not about the person.
* Response layer (`npcore.respond`, `npcore respond`): signed CAEP events (JWS HS256), session revocation in Entra,
  Okta, Google and AWS, suspension (always with approval), GitHub branch-protection restore, Kubernetes pod deletion
  (approval), dry run by default, every action in the hash-chained ledger before it runs, undo for every action.
* Evaluation (`docs/09-v1.0.md`): 44 / 45 on the 55 pre-registered development datasets (first run 43; v0.9: 11).
  **Blind hold-out, rules frozen before download: 5 / 23, the same as v0.9.** No detection lost on 118 earlier
  datasets; simulator identical to v0.9. Proof bundle with commits and SHA-256 of every input: `results/v10_proof.json`.
* Fixed after the freeze (no recorded result changes): card numbers with only two distinct digits were ignored.

## 0.9.0

* Upload routine judged by breadth: someone who routinely uploads to many different sites is not flagged for one more
  (personal cloud storage, sensitive data and bursts keep their weight).
* Calibration protocol with a restriction budget: every architecture is calibrated, without labels, to at most 5 cases
  and at most 1 user restricted (L3+) per week per 1,000 users (`scripts/run_cert_budget.py`, `results/cert_budget.json`).
* CERT r6.1 added as an untouched test set (`scripts/fetch_cert_r61.sh`).
* Simulation, Okta, cloud and Windows results identical to 0.7.0.
* Results from public attack datasets are pseudonymised before they are written (`npcore.anon`): lab account names,
  e-mail addresses, AWS account numbers, Windows SIDs and object IDs become stable placeholders. Detections unchanged.
* `scripts/run_otrf_golden_saml.py` reproduces `results/otrf_golden_saml.json` (previously produced by a one-off run).
* CI runs lint, tests and the self-test on every push to main.

## 0.8.0

* HR notice periods: routine USB copies, uploads and e-mails home count as evidence again while a resignation is
  pending (`lifecycle` event with status `notice`; for CERT derived from the monthly LDAP snapshots).
* Burst rule for egress channels against the person's own weekly rate (implemented; weight 0 after training).
* Weights trained on CERT r4.2 only (`scripts/train_v08.py`, `results/train_v08.json`) under the constraint that
  r4.2 detection and false alarms are no worse than v0.7. CERT r6.2 held out: 2 of 5 insiders (v0.7: 1 of 5).
* All earlier results are unchanged: simulation, Okta, cloud and Windows logs give identical results to v0.7.

## 0.7.0

* Windows endpoint adapter (`npcore.windows`): Windows Security, Sysmon and PowerShell logs. Public indicators for
  credential theft (LSASS memory access, dumping tools, DCSync), log tampering, remote execution, remote-access tools,
  account and group changes and archiving, attributed to the user behind the process.
* Evaluated on the 113 readable Windows host datasets of OTRF Security-Datasets (`scripts/run_otrf_windows.py`):
  20 of 23 credential-theft datasets detected, 45 of 113 overall.
* CERT r6.2 replay (`scripts/run_cert_r62.py`, `scripts/fetch_cert_r62.sh`): r5+ formats, web uploads read as cloud
  transfers; 1 of 5 insiders detected by every architecture.
* Simulation results are identical to 0.4.0.

## 0.6.0

* Cloud log adapters (`npcore.cloudlogs`): Microsoft Entra ID sign-in and audit logs, Microsoft Graph sign-ins,
  Microsoft 365 audit log, AWS CloudTrail (native and OCSF), and the same sources as Microsoft Sentinel tables.
  The Okta adapter also reads Sentinel's `Okta_CL` table.
* Cloud audit rules: privilege and credential changes, new principals, logging or protection switched off, mail
  forwarding rules, sensitive data access, repeated failed sign-ins on one account, discovery bursts.
* Evaluated on 105 recorded cloud attack datasets from splunk/attack_data (89 detected on the first run) and on the
  OTRF Golden SAML dataset (`scripts/run_splunk_cloud.py`, `results/splunk_cloud.json`, `results/otrf_golden_saml.json`).
* Simulation results are identical to 0.4.0 (the new rules react only to the new event types).

## 0.5.0

* Okta System Log adapter (`npcore.okta`) and a replay of the recorded Okta attack logs from
  [splunk/attack_data](https://github.com/splunk/attack_data) (`scripts/fetch_splunk_attack_data.py`,
  `scripts/run_splunk_okta.py`).
* Identity-provider rules: password spraying across accounts, impossible travel, identity-provider risk alerts
  (Okta ThreatInsight, user-reported suspicious activity), denied application access, factor enrolment.
* Authenticator push answers are part of their session and no longer count towards session replay.
* Simulation results are identical to 0.4.0 (the new rules react only to identity-provider events).

## 0.4.0

* Reconstructions of eight documented incidents (MGM Resorts 2023, Uber 2022, Okta support 2023, Snowflake 2024,
  Salesloft Drift 2025, Coinbase 2024/25, Cash App 2022, KnowBe4 2024) with benign look-alikes (scenario set `cases`).
* Detections: help-desk reset or push bombing followed by a new-device sign-in (account takeover), identity
  configuration changes, a session presented by a different client, dormant accounts reused without MFA,
  integrations as principals (new network, export volume, secret searches), purpose binding for customer records,
  activity after termination, endpoint security findings.
* OCSF mappings for Account Change (3001), Detection Finding (2004) and API Activity (6003).
* The zero-trust baselines explicitly have no person/account attribution.

## 0.3.0

* Stolen session tokens: a session used from two networks at once is treated as replayed; the account session is
  contained and its owner is not blamed.
* Proportional containment: levels above dual control require evidence of intent.
* Multi-signal campaigns require at least one strong signal.
* Embedding API (`npcore.api.NegativeTrust`), HTTP service (`npcore serve`), Dockerfile, `npcore selftest`,
  `npcore check-ocsf`.
* Organisation profiles in the simulator and cross-organisation tuning (`npcore.tune`).
* Earlier releases remain reproducible: `version_preset("v0.1")`, `("v0.2")`.

## 0.2.0

* Personal baselines for egress channels; attribution between colleagues (device owner); lookalike destinations;
  removable-media rate spikes; web-gateway categories.
* CERT r4.2 shadow-mode replay with calibration; Isolation Forest baseline; adaptive attack scenarios.
* OCSF input and OpenID CAEP output.

## 0.1.0

* Definition, formal model, reference architecture, engine, simulator, OrgForge-IT adapter.
