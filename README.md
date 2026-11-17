# NullProtocol Negative Trust Architecture

*Author: [github.com/amarkralj](https://github.com/amarkralj) · [Xevoris Labs](https://xevorislabs.com)*

**An extension of zero trust for insider threats.**

Zero trust (NIST SP 800-207) checks every request, but it leaves open how much a person or an account should be
trusted once they are inside. NullProtocol Negative Trust fills that gap with a trust algorithm built for insider
threats:

* **Trust is a signed value.** It starts at zero, rises slowly with normal behaviour, falls quickly with evidence of
  misuse, and can become negative. The more negative, the more access is restricted.
* **Misuse is remembered longer than good behaviour,** and decoys test suspicion actively.
* **Evidence is attributed to whoever it is about.** A hijacked *account* is contained without blaming its *owner*.
* **Restrictions are graduated and reversible:** L0 observe, L1 verify, L2 dual control, L3 read-only, L4 isolate.
  People review every serious case; nothing decides about an employee on its own.
* **Pseudonymous by default,** with a tamper-evident ledger of every decision.

It plugs into what organisations already run: OCSF events in, OpenID CAEP signals out to the identity provider, and
adapters for Okta, Microsoft Entra ID, Microsoft 365, AWS CloudTrail and Windows endpoint logs.

## Status

**v0.9, research prototype.** Tested in simulation, on recorded attack logs from public security datasets and on three
CERT insider threat datasets. Not yet deployed in a real organisation.

| Stage | |
|---|---|
| Research: model, simulator, baselines | done |
| **Prototype: engine, log adapters, evaluation (v0.9)** | **current** |
| Pilot: shadow mode in a real organisation | next |

## Results so far

| Test | Result |
|---|---|
| Eight documented attacks (MGM Resorts, Uber, Okta, Snowflake, Salesloft Drift, Coinbase, Cash App, KnowBe4), reconstructed in simulation | contained in every run, 20 organisations not used in development |
| Okta attack logs ([splunk/attack_data](https://github.com/splunk/attack_data)) | 15 of 15 attack types detected |
| Microsoft Entra ID, Microsoft 365 and AWS attack logs (splunk/attack_data) | 89 of 105 detected on the first run |
| Windows credential theft ([OTRF Security-Datasets](https://github.com/OTRF/Security-Datasets)) | 20 of 23 detected |
| Golden SAML, forged federation token (OTRF) | detected, evidence on the impersonated administrator |

CERT insider threat datasets (Carnegie Mellon University), replayed in shadow mode. Each cell: insiders detected /
share of incident activity prevented / innocent users restricted (read-only or more) per 1,000:

| | r4.2 (1,000 users) | r6.2 (4,000 users) | r6.1 (4,000 users, held out) |
|---|---|---|---|
| Zero-trust baseline + correlation + decoys* | 36 % / 44.8 % / 14.0 | 0 of 5 / 0 % / 1.8 | 0 of 5 / 0 % / 1.0 |
| same, with our v0.9 signals* | 26 % / 50.0 % / 12.9 | 1 of 5 / 58.1 % / 24.8 | 1 of 5 / 44.3 % / 16.5 |
| **Zero trust + NullProtocol Negative Trust v0.9** | **50 % / 40.4 % / 10.8** | **1 of 5 / 32.2 % / 11.0** | **1 of 5 / 36.4 % / 11.8** |

On all three it detects at least as many insiders as our strongest zero-trust baseline and restricts fewer innocent
users. The baseline restricts earlier and so stops more of each incident. Every architecture was calibrated without
labels to the same restriction budget, fixed before testing; r6.1 was not used until the final test.

\* Baselines are our own re-implementations of zero-trust and UEBA designs in the same engine, with the same
enforcement points, tested with their own signals and with ours. They are not commercial products.

Full method, every version, the limits and the misses: [docs/04-evaluation.md](docs/04-evaluation.md).
Raw numbers: [results/](results/) ([summary](results/RESULTS.md)). Identities from public datasets are pseudonymised.
Every result can be regenerated with the scripts in [scripts/](scripts/); the datasets are downloaded by the fetch scripts
(CERT must be requested from Carnegie Mellon University).

## Documents

| | |
|---|---|
| [00 Prior art](docs/00-prior-art.md) | What exists and what is new |
| [01 NullProtocol Negative Trust](docs/01-negative-trust.md) | Definition, principles, formal model, threat model |
| [02 Reference architecture](docs/02-reference-architecture.md) | Extension of NIST SP 800-207: components, sequences, deployment |
| [03 Metrics](docs/03-metrics.md) | Harm, speed, fairness, friction, accountability |
| [04 Evaluation](docs/04-evaluation.md) | Method, results, version comparison, limits |
| [05 Privacy and legal considerations](docs/05-privacy-and-legal.md) | EU and US law |
| [05a Works agreement outline](docs/05a-works-agreement-outline.md) | Template for employee representatives |
| [06 Integration](docs/06-integration.md) | OCSF in, CAEP out, Python API, HTTP service, Docker |
| [07 Roadmap](docs/07-roadmap.md) | What comes next |
| [08 Real-world cases](docs/08-real-world-cases.md) | Eight documented incidents, reproduced and detected |
| [Changelog](CHANGELOG.md) | Every version since v0.1 |

## Quick start

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
npcore selftest                                  # end-to-end check, prints PASS/FAIL
npcore demo --scenario compromised               # a hijacked account being contained, step by step
pytest -q
```

Plug it into a system ([docs/06-integration.md](docs/06-integration.md)):

```bash
npcore check-ocsf events.jsonl --directory directory.json     # how much of your data it can use
npcore serve --directory directory.json                       # HTTP service: POST /v1/events, GET /v1/caep
docker build -t npcore . && docker run -p 8080:8080 -v $PWD/directory.json:/config/directory.json npcore
```

```python
from npcore.api import NegativeTrust
nt = NegativeTrust("directory.json")
outputs = nt.process(ocsf_record)      # decisions, containment changes, CAEP events
```

Reproduce the results: `python scripts/evaluate_release.py sim` (also `cert`, `scale`; CERT needs
`sh scripts/fetch_cert.sh`), then `npcore report`.

## Contact, contributing and security

* Questions, ideas, pilots: contact@xevorislabs.com, or open an issue. See [CONTRIBUTING.md](CONTRIBUTING.md).
* Security issues: please report privately, see [SECURITY.md](SECURITY.md).

## Licence

Everything in this repository, code, documents and results, is licensed under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0-only).

* **Free to use:** you may use, study, change and share it, including inside a company.
* **Share alike:** if you distribute it, or offer it to others over a network as part of a product or service, you
  must publish your complete source code under the same licence.
* **Commercial licence:** to build NullProtocol Negative Trust into a closed product or service without the AGPL
  obligations, contact **contact@xevorislabs.com**.

Third-party datasets are credited in [NOTICE](NOTICE) and are not redistributed. To cite this work, see
[CITATION.cff](CITATION.cff).

Deploying anything like this requires informing employees and, depending on the jurisdiction, an impact assessment and
an agreement with employee representatives ([doc 05](docs/05-privacy-and-legal.md)).
