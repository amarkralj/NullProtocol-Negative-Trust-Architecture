# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""NullProtocol Negative Trust Architecture: a reference implementation of NullProtocol Negative Trust (NT) architectures
for detecting and containing insider threats.

Modules
-------
evidence    Evidence records (the only input the trust model sees)
trust       Asymmetric trust model: trust can fall below zero (distrust)
deception   Decoy registry: assets no legitimate workflow needs
policy      Graduated, reversible containment levels L0-L4 and leases
correlate   Multi-stage chains, cross-actor links, collusion propagation
signals     Behaviour signals (personal and peer baselines)
ledger      Tamper-evident, hash-chained evidence ledger
privacy     Keyed pseudonymisation with four-eyes re-identification
engine      Streaming orchestrator that ties everything together
sim         Synthetic company simulator with labelled insider scenarios
evaluate    Experiment runner, baselines, ablations and metrics
orgforge    Adapter and scorer for the public OrgForge-IT benchmark
cert        Shadow-mode replay of the CERT r4.2 insider-threat dataset, with calibration
baselines   Independent ML baseline (Isolation Forest UEBA)
integrations OCSF input and OpenID CAEP output for existing security stacks
api         Embedding API (NegativeTrust class) for putting NT into an existing system
serve       Minimal HTTP service around the API
tune        Cross-organisation tuning: learn on some organisation types, test on unseen ones
sim_cases   Reconstructions of eight documented incidents (scenario set "cases")
okta        Okta System Log adapter (native and Microsoft Sentinel table)
windows     Windows Security, Sysmon and PowerShell event log adapter
cloudlogs   Microsoft Entra ID, Microsoft 365, AWS CloudTrail adapters (native, OCSF, Microsoft Sentinel tables)
"""

__version__ = "0.9.0"
