# Roadmap

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

The roadmap is driven by documented incidents: each item closes a gap that a real attack used.
[08-real-world-cases.md](08-real-world-cases.md) maps the incidents to the detections.

## Released

* **v0.1**: definition, formal model, reference architecture, engine, simulator, OrgForge-IT adapter.
* **v0.2**: personal baselines for egress channels, attribution between colleagues, lookalike destinations,
  CERT r4.2 replay, OCSF input and CAEP output.
* **v0.3**: detection of stolen session tokens, proportional containment, embedding API, HTTP service, Docker,
  self-test, cross-organisation tuning.

## v0.4: real-world cases

Detections for eight documented incidents, evaluated on held-out seeds (see [08](08-real-world-cases.md)):

| Incident | Detection added |
|---|---|
| MGM Resorts 2023 (help desk MFA reset) | Reset followed by a sign-in from a new device = account takeover; identity configuration changes are high risk |
| Uber 2022 (MFA fatigue) | Burst of denied pushes, then a new-device sign-in = account takeover |
| Okta support 2023 (session token in a support file) | Session presented by a different client than it was issued to = replay, even when the owner is offline |
| Snowflake 2024 (old password, no MFA) | Dormant account used from a new device or without MFA |
| Salesloft Drift 2025 (integration OAuth token) | Integrations as principals: new network, export volume, searches for stored secrets |
| Coinbase 2024/25 (bribed support agents) | Purpose binding: customer records without an assigned ticket, volume spikes |
| Cash App 2022 (former employee) | Any activity after the HR end date |
| KnowBe4 2024 (fake remote worker) | Endpoint security findings and remote-access tools as evidence |

All eight are also readable from OCSF (Account Change 3001, Authentication 3002, Detection Finding 2004,
API Activity 6003).

## v0.5: identity-provider logs

* Okta System Log adapter; tested on 15 recorded Okta attack datasets from splunk/attack_data (15 of 15 detected;
  rules written after reviewing the logs, see the evaluation).
* Password spraying, impossible travel, identity-provider risk alerts, denied application access.

## v0.6: cloud audit logs

* Adapters for Microsoft Entra ID, Microsoft 365, AWS CloudTrail (native, OCSF and Microsoft Sentinel tables).
* Rules for privilege and credential changes, logging switched off, mail forwarding, sensitive data access,
  repeated failed sign-ins and discovery bursts.
* 89 of 105 recorded cloud attack datasets detected on the first run; OTRF Golden SAML detected.

## v0.7: endpoint logs

* Windows Security, Sysmon and PowerShell adapter: credential theft, log tampering, remote execution, remote-access
  tools, account changes, archiving; findings attributed to the user behind the process.
* CERT r6.2 replay.

## v0.8: habits and leavers

* HR notice periods: routine egress by someone who has resigned counts as evidence again.
* Burst rule on egress channels (off after training: too many false alarms on r4.2).
* Trained on CERT r4.2 without making it worse; CERT r6.2 1 → 2 of 5.

## v0.9: fewer innocents restricted

* Upload routine judged by breadth; calibration with a restriction budget for every architecture.
* CERT r4.2, r6.2 and the untouched r6.1: at least as many insiders detected as every baseline, fewer innocent
  users restricted; the baselines still prevent more of each incident.

## Next: data

| Source | Status | Safe on a laptop |
|---|---|---|
| splunk/attack_data: Okta, Entra ID, Microsoft 365, AWS | Done (v0.5, v0.6) | Text logs only; `malware` folder never downloaded |
| OTRF Security-Datasets: Golden SAML and 113 Windows host datasets | Done (v0.6, v0.7): credential theft 20 of 23 | JSON inside zip, checked before reading |
| Microsoft Sentinel samples | Done as format tests | Yes |
| CERT r6.2 and r6.1 (4,000 users, 5 insiders each) | Done (v0.9, restriction-budget protocol) | Read as a stream; never fully unpacked |
| [LANL cyber-security events](https://csr.lanl.gov/data/cyber1/) | Next: real sign-ins with labelled red-team activity, the first false-alarm test on real data | Yes, streamed |
| Atomic Red Team, Stratus Red Team | Later | **No**: only in a disposable VM or test cloud account |

Detection gaps found on recorded data: spraying spread over many addresses, forged federation tokens (Golden SAML),
concurrent sessions without session identifiers; on CERT r6.2, insiders whose exfiltration matches their own habits
(USB copies, uploads), and false alarms from habitual USB and upload use at 4,000-user scale.

## Next: product

1. **v0.8 Deployability:** persistent engine state, signed CAEP delivery over an SSF stream, `npcore calibrate`
   (baselines, partner domains, shared machines and a case budget from a shadow-mode period).
2. **v0.8 Receiving shared signals:** use identity-provider events (credential change, device compliance, token
   binding) as evidence instead of inferring them.
3. **v0.9 AI agents as principals:** agents acting with delegated access (prompt-injected agents exfiltrating data)
   get their own trust, separate from the human who delegated.
4. **v0.9 Privacy:** crypto-shredding of evidence about cleared employees; external anchoring of the ledger.
5. **Validation:** a shadow-mode pilot in a real organisation.

## Open questions

* Can thresholds be defined without calibration, for example as quantiles of each organisation's own trust
  distribution?
* How should decoys be placed to maximise detection without raising curiosity contacts?
* How should trust propagate in large organisations without creating guilt by association?
