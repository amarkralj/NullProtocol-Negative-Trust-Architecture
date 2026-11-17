# Integration: running NullProtocol Negative Trust Architecture in an existing security stack

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

NullProtocol Negative Trust Architecture does not need its own agents. It reads events in the **Open Cybersecurity Schema Framework (OCSF)**
and emits **OpenID Shared Signals / CAEP** events that identity providers and SaaS applications already understand.
Everything in between (signals, deception, correlation, attribution, trust, containment, ledger) is the same engine
that runs in the simulator and on the CERT dataset.

```
 IdP sign-in logs ─┐                                        ┌─> IdP / SSO: step-up, session revoke   (CAEP)
 EDR / DLP events ─┤   OCSF JSONL   ┌───────────────────┐   ├─> DLP / proxy: dual control, block     (decision records)
 Mail gateway     ─┼──────────────> │ npcore stream     │ ──┤
 Web gateway      ─┤                │ (NullProtocol Negative Trust)  │   ├─> SOC / case tool: L4 cases           (level records)
 File audit       ─┘                └───────────────────┘   └─> tamper-evident ledger
```

## 1. Five ways in

| Way | Command / code | Use it for |
|---|---|---|
| Self-test | `npcore selftest` | Prove an installation works: synthetic attacks go through OCSF → engine → CAEP, six checks print PASS/FAIL |
| Check your data | `npcore check-ocsf events.jsonl --directory directory.json` | See which of your OCSF records the engine can use and what is missing (users not in the directory, logins without a device or session id) |
| Batch / pipe | `npcore stream --directory directory.json events.jsonl` | Shadow mode on exported logs; prints decisions, level changes and CAEP SETs as JSON Lines |
| Python | `from npcore.api import NegativeTrust` | Embed in an existing pipeline (see below) |
| HTTP service | `npcore serve --directory directory.json` or the Docker image | Let a SIEM, SOAR or log shipper post events and poll CAEP signals |

```python
from npcore.api import NegativeTrust
nt = NegativeTrust("directory.json")          # version="v0.3" by default
for out in nt.process(ocsf_record):           # decisions, level changes, CAEP SETs
    send_somewhere(out)
nt.status("acct:u001")                        # level, trust and the evidence behind it
nt.review("u001", confirmed=False)            # a human decision on an L4 case
```

HTTP endpoints (`npcore serve`): `POST /v1/events` (one OCSF object, an array or JSON Lines), `GET /v1/subjects/<id>`,
`POST /v1/cases/<id>/review`, `GET /v1/caep` (poll), `GET /v1/ledger/verify`, `GET /v1/health`. Set `NPCORE_TOKEN` to
require a bearer token; run behind a TLS proxy.

```bash
docker build -t npcore .
docker run -p 8080:8080 -v $PWD/directory.json:/config/directory.json npcore
curl -X POST --data-binary @events.ocsf.jsonl localhost:8080/v1/events
```

Sample data: `npcore export-ocsf --out examples/ocsf` writes a synthetic organisation as OCSF plus its directory
file; `examples/ocsf-sample.jsonl` is a small checked-in excerpt. `tests/test_integrations.py` shows that the OCSF
path gives exactly the same decisions as running the engine on the original events.

## 2. Input: OCSF classes used

| OCSF class (class_uid) | Activity | Becomes | Attributes read |
|---|---|---|---|
| Authentication (3002) | 1 Logon, status 1 Success | login | `time`, `user.uid`, `device.uid`/`device.hostname`, `src_endpoint.ip`, `src_endpoint.location.country`, `actor.session.uid` |
| File System Activity (1001) | 2 Read, 14 Open | file read | `file.path`, `file.size`, `file.confidentiality_id` (≥ 2 = restricted), `unmapped.decoy_id` |
| File System Activity (1001) | 1 Create on a removable volume | copy to removable media | as above, `unmapped.source_path` (source of the copy, as DLP agents report it) |
| Email Activity (4009) | 1 Send, direction 2 Outbound / 3 Internal | e-mail | `email.to`, `email.files[]` (`name`, `path`, `size`, `confidentiality_id`) |
| HTTP Activity (4002) | 6 Post, 7 Put to a file-sharing category | upload to cloud | `http_request.url.hostname`, `http_request.url.categories`, `traffic.bytes_out` |

All classes: `actor.session.uid` and `src_endpoint.ip` per request enable the detection of stolen session tokens
(one session used from two networks at once). Without them, everything else still works.

Schema reference: OCSF v1.9.0 (released 3 August 2026), [schema.ocsf.io](https://schema.ocsf.io),
[github.com/ocsf/ocsf-schema](https://github.com/ocsf/ocsf-schema).

## 3. The directory file

Logs do not carry everything the engine needs. `directory.json` supplies it:

```json
{
  "departments": {"u001": "Finance", "u002": "Engineering"},
  "path_departments": {"//fs/Finance/": "Finance", "//fs/Engineering/": "Engineering"},
  "partner_domains": ["auditor.example", "bank.example"],
  "home_countries": ["DE"],
  "support_staff": ["u017"],
  "internal_domains": ["corp.example"]
}
```

`support_staff` is the role registry for IT support: their logins into colleagues' accounts are recorded in the ledger
but not scored as evidence (v0.2; see the stress-test report).

## 4. Output

`npcore stream` writes one JSON object per line:

* `{"type": "decision", ...}`: the policy decision for an event that was not simply allowed or that produced
  evidence (`allow`, `step_up`, `dual_control`, `deny`) with the evidence and its explanation. A policy enforcement
  point (DLP, proxy, PAM) applies it; in shadow mode it is only logged.
* `{"type": "level", ...}`: a containment level change of a person or an account (`acct:<id>`), with the trust value.
* `{"type": "caep", "set": {...}}`: an OpenID CAEP 1.0 Security Event Token payload
  ([spec, 29 Aug 2025](https://openid.net/specs/openid-caep-1_0-final.html)):
  * `risk-level-change` with `principal` = `USER` (a person) or `SESSION` (an account under attribution P4),
    `current_level`/`previous_level` = LOW (L0–L1), MEDIUM (L2), HIGH (L3–L4), and `risk_reason`;
  * `session-revoked` when a subject reaches L4.

The payloads are **unsigned**. In production they must be signed as JWS and delivered over an SSF stream (push or
poll) to each receiver; `sub_id` must then use an identifier the receiver knows (`iss_sub` or `email` format), which
means the pseudonym is resolved only at this boundary, by the transmitter, under the four-eyes rule.

## 5. Deployment sequence

1. **Shadow mode:** run on a copy of the log pipeline and enforce nothing. Learn baselines and set thresholds to a case
   budget the organisation can review; settings from another organisation do not transfer.
2. **Signals only:** send CAEP `risk-level-change` to the IdP and let it require step-up for MEDIUM/HIGH.
3. **Enforcement:** wire decisions into DLP/proxy dual control and `session-revoked` into the IdP, with a staffed
   review rota for L4 cases.

## 6. Not included

Signing and transport of SETs, persistence of engine state across restarts, and vendor-specific log parsers (map them
to OCSF first; many SIEMs already do).
