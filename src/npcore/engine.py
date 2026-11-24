# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj)
"""Streaming NullProtocol Negative Trust engine.

    event --> policy check (current containment of account and owner person)
          --> [harness resolves step-up / dual control]          <- outside the engine
          --> signals + deception + correlation  -> evidence
          --> trust model -> containment level -> ledger
          --> cases for human review at L4 (auto mode) or alerts (alert mode)

The engine never sees ground truth. Human decisions (step-up outcomes, second approvers,
case reviews) are supplied by the caller, so the same engine runs in the simulator and in
production. The engine is a policy decision point in the sense of NIST SP 800-207: it extends the
zero-trust trust algorithm with signed, evidence-driven trust.

Configurations (preset names) used in the evaluation. The zt_* presets are zero-trust baselines
re-implemented inside this engine; the nt presets are the same zero-trust setup extended with
NullProtocol Negative Trust:

    perimeter   no signals, no enforcement (RBAC and perimeter only)
    zt_alert    zero-trust baseline: context step-up + UEBA risk score, alerts to a SOC (24 h triage)
    zt_auto     zero-trust baseline with automatic containment on the same risk score
    zt_strong   zt_auto plus sequence correlation and decoys
    nt          zero trust extended with NullProtocol Negative Trust: asymmetric trust, deception,
                correlation, attribution, graduated containment; ablations nt_no_* switch one principle off

Releases: preset(name) is v0.1; preset(name, v02=True) and preset(name, v03=True) select the later
signal library for any architecture (fair comparisons); version_preset("v0.3") is the recommended
NT configuration of a release (message-tone signal off).
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from . import policy as P
from .correlate import Correlator
from .deception import DecoyRegistry
from .evidence import Evidence, ACCOUNT, PERSON
from .ledger import Ledger
from .privacy import Pseudonymizer
from .signals import SignalExtractor, W
from .trust import TrustConfig, TrustModel


@dataclass
class EngineConfig:
    name: str = "nt"
    signals: bool = True
    deception: bool = True
    correlation: bool = True
    trust: TrustConfig = field(default_factory=TrustConfig)
    enforce: str = "auto"            # auto | alert | none
    context_stepup: bool = True
    alert_threshold: float = -2.5
    alert_delay_h: float = 24.0
    review_delay_h: float = 8.0
    policy: P.PolicyConfig = field(default_factory=P.PolicyConfig)
    disabled_signals: tuple = ()     # e.g. ("negative_sentiment",) for deployments that exclude content analysis
    attribution: bool = True         # P4: evidence from unproven session contexts goes to the account
    device_attribution: bool = False  # v0.2: login from a device enrolled to another employee -> that employee
    signals_v02: bool = False        # v0.2 signals: habitual-egress baseline, lookalike domains
    warmup_days: int = 14            # baseline-learning period of the signal extractor
    session_binding: bool = False    # v0.3: one session used from two networks at once -> session replay (token theft)
    proportional: bool = False       # v0.3: beyond L2 (dual control) only with evidence of intent
    campaign_needs_strong: bool = False  # v0.3: multi-signal campaign only if one of its signals is strong
    signals_v04: bool = False        # v0.4: incident-based signals (help desk, MFA fatigue, dormant, lifecycle, EDR, workloads)
    signals_v05: bool = False        # v0.5: identity-provider logs (password spraying, impossible travel, IdP risk alerts)
    signals_v06: bool = False        # v0.6: cloud audit logs (privilege changes, audit tampering, forwarding, bulk access)
    signals_v07: bool = False        # v0.7: Windows endpoint logs (same rules; version marks the endpoint adapter)
    signals_v08: bool = False        # v0.8: bursts on habitual egress channels, HR notice periods
    signals_v09: bool = False        # v0.9: upload routine judged by breadth, not per destination
    patch: int = 0                   # 1.0.z patch level; rules added in a patch check `cfg.patch >= z`
    signals_v11: bool = False        # 1.0.1 (first labelled v1.1): denied attempts to tamper, disable or destroy (adapters classify by verb/object)
    signals_v10: bool = False        # v1.0: GitHub, Google, Kubernetes, data-movement services, AI assistants and agents,
                                     #       concurrent networks, distributed spraying, device-code sign-ins


def preset(name: str, v02: bool = False, v03: bool = False, v04: bool = False, v05: bool = False,
           v06: bool = False, v07: bool = False, v08: bool = False, v09: bool = False, v10: bool = False, v11: bool = False) -> EngineConfig:
    """Architecture preset on a signal-library version. v02=True / v03=True give every architecture the
    same newer signals (fair comparison); NT presets also get that version's NT mechanisms."""
    cfg = _preset(name)
    v10 = v10 or v11
    v09 = v09 or v10
    v08 = v08 or v09
    v07 = v07 or v08
    v06 = v06 or v07
    v05 = v05 or v06
    v04 = v04 or v05
    v03 = v03 or v04
    if v04:
        cfg.signals_v04 = True
    if v05:
        cfg.signals_v05 = True
    if v06:
        cfg.signals_v06 = True
    if v07:
        cfg.signals_v07 = True
    if v08:
        cfg.signals_v08 = True
    if v09:
        cfg.signals_v09 = True
    if v10:
        cfg.signals_v10 = True
    if v11:
        cfg.signals_v11 = True
    if v02 or v03:
        cfg.signals_v02 = True
        if name.startswith("nt") and name not in ("nt_no_attribution",):
            cfg.device_attribution = True
    if v03:
        cfg.campaign_needs_strong = True
        if name.startswith("nt"):
            cfg.session_binding = name != "nt_no_attribution"
            cfg.proportional = True
    return cfg


def version_preset(version: str) -> EngineConfig:
    """The recommended NT configuration of each release (message-tone signal off)."""
    version = {"v1.1": "v1.0.1"}.get(version, version)   # 1.0.1 was first labelled v1.1 in recorded results
    patch = int(version.split(".")[2]) if version.count(".") == 2 else 0
    cfg = preset("nt_no_sentiment", v02=version.startswith(("v0.2", "v0.3", "v0.4", "v0.5", "v0.6", "v0.7", "v0.8", "v0.9", "v1.0")),
                 v03=version == "v0.3", v04=version == "v0.4", v05=version == "v0.5", v06=version == "v0.6",
                 v07=version == "v0.7", v08=version == "v0.8", v09=version == "v0.9", v10=version == "v1.0", v11=version.startswith("v1.0.") and patch >= 1)
    cfg.patch = patch
    cfg.name = f"nt {version}"
    return cfg


def _preset(name: str) -> EngineConfig:
    if name == "perimeter":
        return EngineConfig(name, signals=False, deception=False, correlation=False,
                            trust=TrustConfig.symmetric(), enforce="none", context_stepup=False)
    if name == "zt_alert":
        return EngineConfig(name, deception=False, correlation=False, trust=TrustConfig.symmetric(), enforce="alert",
                            attribution=False)
    if name == "zt_auto":
        return EngineConfig(name, deception=False, correlation=False, trust=TrustConfig.symmetric(), enforce="auto",
                            attribution=False)
    if name == "nt":
        return EngineConfig(name)
    if name == "nt_no_deception":
        return EngineConfig(name, deception=False)
    if name == "nt_symmetric":
        return EngineConfig(name, trust=TrustConfig.symmetric())
    if name == "nt_no_correlation":
        return EngineConfig(name, correlation=False)
    if name == "nt_no_sentiment":
        return EngineConfig(name, disabled_signals=("negative_sentiment",))
    if name == "nt_no_attribution":
        return EngineConfig(name, attribution=False)
    if name == "zt_strong":
        return EngineConfig(name, trust=TrustConfig.symmetric(), attribution=False)
    if name == "nt_v02":
        return EngineConfig(name, disabled_signals=("negative_sentiment",), device_attribution=True, signals_v02=True)
    raise ValueError(name)


PRESETS = ["perimeter", "zt_alert", "zt_auto", "nt", "nt_no_deception", "nt_symmetric", "nt_no_correlation", "nt_no_sentiment"]
PRESETS_V02 = ["zt_alert", "zt_auto", "zt_strong", "nt", "nt_no_sentiment", "nt_no_attribution", "nt_v02"]


def category(e) -> str:
    k = e.kind
    if k == "login":
        return P.AUTH
    if k == "read":
        return P.SENSITIVE_READ if e.sensitive else P.READ
    if k in ("copy", "archive") or (k == "clone" and e.attrs.get("count", 0) >= 10):
        return P.BULK
    if k in ("egress_usb", "egress_cloud") or (k == "email" and e.attrs.get("external") and e.attrs.get("attachment")):
        return P.EGRESS
    if k in ("grant", "config_change"):
        return P.ADMIN
    if k == "api_export":
        return P.EGRESS
    if k == "record_read":
        return P.SENSITIVE_READ if e.sensitive else P.READ
    if k in ("audit_change", "mail_rule"):
        return P.ADMIN
    if k == "data_access":
        return P.BULK
    return P.OTHER


IDP_ANOMALIES = {"new_device", "foreign_ip", "impossible_context", "off_hours_login", "dormant_reuse", "no_mfa_login"}
# Evidence that shows intent rather than carelessness (v0.3 proportionality). Without any of it, a person is
# not taken beyond L2 (dual control): careless behaviour gets guard rails and training, not read-only access.
INTENT_KINDS = {"exfil_chain", "egress_personal_cloud", "email_personal", "lookalike_repeat", "cross_account_login",
                "social_engineering", "collusion_link", "bulk_copy", "archive", "leak_site_contact", "spyware_download",
                "read_volume_spike", "cross_dept_sensitive_read", "clone_spike",
                "post_termination_activity", "record_volume_spike", "edr_high", "identity_config_change",
                "audit_tamper", "mail_forwarding", "bulk_data_access", "control_disabled", "destructive_change"}
SESSION_WINDOW_H = 0.5


class Engine:
    def __init__(self, cfg: EngineConfig, owners: Dict[str, str], owners_dept: Dict[str, str],
                 decoys: Optional[DecoyRegistry] = None, partner_domains=(), pseudonymizer: Optional[Pseudonymizer] = None,
                 support_staff=(), workloads=()):
        self.cfg = cfg
        self.workloads = set(workloads)
        self.support = set(support_staff)          # role registry: IT support may log into others' accounts
        self.owners = owners                       # account -> person
        self.trust = TrustModel(cfg.trust)
        self.sig = SignalExtractor(owners_dept, warmup_days=cfg.warmup_days, partner_domains=partner_domains, v02=cfg.signals_v02,
                                   v04=cfg.signals_v04, v08=cfg.signals_v08, v09=cfg.signals_v09)
        self._reset: Dict[str, tuple] = {}         # account -> (time, verified) of the last help-desk reset
        self._fatigue: Dict[str, float] = {}       # account -> time of the last push-bombing signal
        self._fail_ip: Dict[str, List[tuple]] = defaultdict(list)   # v0.5: ip -> [(time, account)] of failed sign-ins
        self._sprayed: Dict[str, float] = {}
        self._last_geo: Dict[str, tuple] = {}      # v0.5: account -> (time, lat, lon)
        self._fail_acct: Dict[str, List[float]] = defaultdict(list)   # v0.6: account -> failed sign-in times
        self._reads: Dict[str, List[tuple]] = defaultdict(list)       # v0.6: account -> [(time, api, error)]
        self._once: Dict[tuple, float] = {}
        self.corr = Correlator(owners, strong_only_campaigns=cfg.campaign_needs_strong)
        self.decoys = decoys or DecoyRegistry()
        self.ledger = Ledger()
        self.pz = pseudonymizer or Pseudonymizer(key=b"demo-key-not-for-production-use!")
        self.level: Dict[str, P.Level] = defaultdict(lambda: P.Level.L0_OBSERVE)
        self.forced: Dict[str, P.Level] = {}
        self.cases: Dict[str, dict] = {}           # subject -> open case
        self.case_log: List[dict] = []
        self.level_log: List[tuple] = []           # (t, subject, old, new)
        self.leases = P.LeaseBook(cfg=cfg.policy)
        self._day_neg: Dict[tuple, bool] = defaultdict(bool)
        self._day_act: Dict[tuple, int] = defaultdict(int)
        self._untrusted_ctx: set = set()
        self._stepped: set = set()
        self._blocked_spent: Dict[tuple, float] = defaultdict(float)
        self._dev_index: Dict[str, str] = {}       # device -> account it is enrolled to (first owner)
        self._sess: Dict[str, dict] = {}           # session id -> {ip: [first_t, last_t, device]}, first ip
        self._sens_egress: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        self._borrowed: Dict[tuple, str] = {}      # (account, ctx) -> account owning the device used
        # v1.0 state
        self._nets: Dict[str, Dict[str, tuple]] = defaultdict(dict)   # account -> {network: (first_t, last_t)}
        self._sess_geo: Dict[str, tuple] = {}      # session id -> (t, lat, lon)
        self._tenant_fail: List[tuple] = []        # [(t, account, ip)] failed sign-ins, whole tenant
        self._obj_reads: Dict[str, List[float]] = defaultdict(list)
        self._forbidden: Dict[str, List[float]] = defaultdict(list)
        self._ai_hour: Dict[tuple, int] = defaultdict(int)            # (principal, hour) -> input tokens

    def confirm_stepup(self, account: str, t: float) -> None:
        self._stepped.add((account, int(t // 24)))

    # ------------------------------------------------------------------ levels
    def subject_level(self, s: str) -> P.Level:
        if s in self.forced:
            return self.forced[s]
        if self.cfg.enforce != "auto":
            return P.Level.L0_OBSERVE
        return self.level[s]

    def session_level(self, account: str, e=None) -> P.Level:
        """Containment that applies to this action. Account-level containment (a compromised
        credential) applies to sessions from unproven contexts; the owner's verified sessions are
        governed by the person's own level (in practice: credentials reset, owner re-enrolled)."""
        person = self.owners.get(account, account)
        lvl = self.subject_level(person)
        acct_lvl = self.subject_level("acct:" + account)
        if account in self.workloads:
            return max(lvl, acct_lvl)
        if e is not None and self._borrowed:
            b = self._borrowed.get((account, (e.attrs.get("device"), e.attrs.get("ip"))))
            if b is not None:
                lvl = max(lvl, self.subject_level(self.owners.get(b, b)), acct_lvl)
        if acct_lvl > lvl:
            ctx = (e.attrs.get("device"), e.attrs.get("ip")) if e is not None else (None, None)
            st = self.sig.s[account]
            known = e is not None and ((account, ctx) not in self._untrusted_ctx) and (
                ctx[0] in st.devices or (ctx[0] is None and (ctx[1] is None or ctx[1] in st.ips)))
            if not known:
                lvl = acct_lvl
        return lvl

    # Evidence attribution principle: behaviour observed inside a session whose context is not
    # proven to belong to the owner (unknown device AND foreign IP, or a vishing-linked login)
    # is attributed to the *account* ("acct:<id>"), not to the person who owns it.
    def _attribute(self, e, ev: List[Evidence]) -> List[Evidence]:
        ctx = (e.attrs.get("device"), e.attrs.get("ip"))
        if not self.cfg.attribution:
            # no person/account distinction: everything lands on the account owner (classic UEBA)
            return [Evidence(x.t, self.owners.get(x.subject[5:], x.subject[5:]), x.kind, x.weight, x.desc, PERSON,
                             x.behavior, x.refs, x.source) if x.subject.startswith("acct:") else x for x in ev]
        b = self._borrowed.get((e.account, ctx))
        if b is not None and self.owners.get(b, b) in self.support:
            # IT support session: expected login anomalies are not evidence against anyone; any misuse
            # (data movement, decoy contact) inside the session is attributed to the support person
            return [x for x in [Evidence(x.t, self.owners.get(b, b), x.kind, x.weight, x.desc + " [IT support session]", PERSON,
                                         x.behavior, x.refs, x.source) if (x.subject == e.account and x.subject_kind == PERSON) else x
                                for x in ev] if x.kind not in IDP_ANOMALIES]
        if b is not None:
            # session runs on a device enrolled to another employee: person-level evidence goes to the
            # device owner; the account session is restricted too (copy at account level)
            dev_owner = self.owners.get(b, b)
            out = []
            for x in ev:
                if x.subject == e.account and x.subject_kind == PERSON:
                    out.append(Evidence(x.t, dev_owner, x.kind, x.weight, x.desc + f" [attributed to device owner: session on {e.account} from {dev_owner}'s device]",
                                        PERSON, x.behavior, x.refs, x.source))
                    out.append(Evidence(x.t, "acct:" + e.account, x.kind, x.weight, x.desc + " [account session from another employee's device]",
                                        ACCOUNT, x.behavior, x.refs, x.source))
                else:
                    out.append(x)
            return out
        if e.kind == "login" and any(x.kind in ("impossible_context", "account_compromise", "dormant_reuse",
                                                    "account_takeover_reset") for x in ev):
            self._untrusted_ctx.add((e.account, ctx))
        if (e.account, ctx) not in self._untrusted_ctx:
            return ev
        out = []
        for x in ev:
            if x.subject == e.account and x.subject_kind == PERSON:
                x = Evidence(x.t, "acct:" + e.account, x.kind, x.weight, x.desc + " [attributed to account: unproven session context]",
                             ACCOUNT, x.behavior, x.refs, x.source)
            out.append(x)
        return out

    def decide(self, e) -> str:
        """Policy decision before the action executes."""
        if self.cfg.enforce == "none":
            return P.ALLOW
        lvl = self.session_level(e.account, e)
        d = P.decide(lvl, category(e))
        if d == P.STEP_UP and (e.account, int(e.t // 24)) in self._stepped:
            d = P.ALLOW                               # one step-up per account and day
        if d == P.ALLOW and self.cfg.context_stepup and e.kind == "login" and e.account in self.owners:
            dev, ip = e.attrs.get("device"), e.attrs.get("ip")
            st = self.sig.s.get(e.account)
            if st is not None and int(e.t // 24) + 1 > self.sig.warmup and (dev not in st.devices or (e.attrs.get("ip_type") == "foreign" and ip not in st.ips)):
                d = P.STEP_UP
        if d != P.ALLOW:
            self.ledger.append("decision", {"account": self.pz.pseudonym(e.account), "kind": e.kind, "decision": d,
                                            "level": int(lvl)}, e.t)
        return d

    # ------------------------------------------------------------------ observation
    def observe(self, e, allowed: bool = True) -> List[Evidence]:
        ev: List[Evidence] = []
        if self.cfg.signals:
            ev += [x for x in self.sig.observe(e) if x.kind not in self.cfg.disabled_signals]
        if self.cfg.deception and e.attrs.get("decoy_id"):
            inter = "use" if e.attrs.get("credential") else ("egress" if category(e) == P.EGRESS else ("copy" if e.kind == "copy" else "view"))
            if e.kind == "login" and self.decoys.decoys.get(e.attrs["decoy_id"]) and self.decoys.decoys[e.attrs["decoy_id"]].cls == "account":
                inter = "login"
            x = self.decoys.check(e.t, e.account, e.attrs["decoy_id"], inter,
                                  subject_dept=self.sig.dept.get(self.owners.get(e.account, e.account)))
            if x:
                ev.append(x)
        # v0.2: a blocked attempt is evidence only if the attempted action is itself suspicious
        # (restricted data, or it produced substantial evidence), not for routine actions
        relevant = (not self.cfg.signals_v02) or e.sensitive or any(x.weight >= 0.5 for x in ev)
        if (not allowed and self.cfg.signals and e.account in self.owners and relevant
                and category(e) in (P.EGRESS, P.BULK, P.ADMIN)):
            key = (e.account, int(e.t // 24))
            if self._blocked_spent[key] < 1.0:          # at most 1.0 per account and day
                self._blocked_spent[key] += W["blocked_attempt"]
                ev.append(Evidence(e.t, e.account, "blocked_attempt", W["blocked_attempt"],
                                   f"attempted {e.kind} ({category(e)}) while contained", behavior=None))
        if self.cfg.device_attribution and e.kind == "login" and e.account in self.owners:
            ev += self._device_check(e)
        if self.cfg.signals_v05 and e.account in self.owners:
            ev += self._idp_check(e)
        if self.cfg.signals_v06 and e.account in self.owners:
            ev += self._cloud_check(e)
        if self.cfg.signals_v10 and e.account in self.owners:
            ev += self._v10_check(e)
        if self.cfg.signals_v04 and e.account in self.owners:
            ev += self._identity_check(e, ev)
            # push bombing is evidence about the account under attack, not about its owner
            ev = [Evidence(x.t, "acct:" + e.account, x.kind, x.weight, x.desc, ACCOUNT, x.behavior, x.refs, x.source)
                  if x.kind == "mfa_fatigue" and x.subject == e.account else x for x in ev]
        if self.cfg.session_binding and e.attrs.get("sid") and e.account in self.owners:
            ev += self._session_check(e)
        if self.cfg.proportional and e.sensitive and category(e) == P.EGRESS and e.account in self.owners:
            dest = ("usb" if e.kind == "egress_usb" else str(e.attrs.get("dest") or str(e.attrs.get("to", "")).split("@")[-1]))
            self._sens_egress[self.owners[e.account]][dest] += 1
        if self.cfg.correlation:
            ev += self.corr.observe(e, ev)
            ev = self._attribute(e, ev)
            ev += self.corr.campaign(e.t, ev)
        elif not self.cfg.attribution or self._borrowed or self.cfg.signals_v04:
            ev = self._attribute(e, ev)
        if e.account in self.workloads:             # an integration has no person behind it
            ev = [Evidence(x.t, "acct:" + e.account, x.kind, x.weight, x.desc, ACCOUNT, x.behavior, x.refs, x.source)
                  if x.subject == e.account else x for x in ev]
        for x in ev:
            self._add(x)
        if allowed and e.kind == "login" and e.account in self.owners and self.cfg.signals:
            ctx = (e.attrs.get("device"), e.attrs.get("ip"))
            if (e.account, ctx) not in self._untrusted_ctx:
                self.sig.enroll(e.account, *ctx)
        if e.kind == "login" and e.account in self.owners and self.cfg.device_attribution:
            dev = e.attrs.get("device")
            if dev is not None and dev in self.sig.s[e.account].devices:
                self._dev_index.setdefault(dev, e.account)
        if e.account in self.owners:
            key = (e.account, int(e.t // 24) + 1)
            self._day_act[key] += 1
        return ev

    def _device_check(self, e) -> List[Evidence]:
        """v0.2: a login to account X from a device that is enrolled to another employee Y. This is
        how one insider uses a colleague's credentials (CERT r4.2 scenario 3). It is not an external
        compromise, so the account-only rule of P4 would leave the colleague to take the blame."""
        dev = e.attrs.get("device")
        other = self._dev_index.get(dev)
        if other is None or other == e.account or dev in self.sig.s[e.account].devices:
            return []
        ctx = (dev, e.attrs.get("ip"))
        self._borrowed[(e.account, ctx)] = other
        self._untrusted_ctx.add((e.account, ctx))
        person = self.owners.get(other, other)
        if person in self.support:
            self.ledger.append("support_session", {"account": self.pz.pseudonym(e.account), "by": self.pz.pseudonym(person)}, e.t)
            return []
        return [Evidence(e.t, person, "cross_account_login", 1.5,
                         f"{person} logged into {e.account}'s account from {person}'s own enrolled device {dev}",
                         behavior="account_misuse", source="correlation")]

    def _session_check(self, e) -> List[Evidence]:
        """v0.3: the same session (cookie / token) in use from two networks at the same time. A network
        handover (VPN reconnect, mobile) moves a session from one IP to another; a replayed token makes two
        IPs *interleave*. The networks other than the session's first one are treated as unproven contexts
        (P4): the account session is contained, the owner is not blamed."""
        sid, ip = e.attrs["sid"], e.attrs.get("sip")
        if ip is None or e.kind == "mfa_push":       # push answers come from the authenticator app on the phone's network
            return []
        st = self._sess.setdefault(sid, {"first": ip, "ips": {}, "flagged": False, "ua": e.attrs.get("ua")})
        ips = st["ips"]
        out = []
        ua = e.attrs.get("ua")
        if self.cfg.signals_v04 and ua and st.get("ua") and ua != st["ua"] and not st["flagged"]:
            st["flagged"] = True
            self._untrusted_ctx.add((e.account, (e.attrs.get("device"), e.attrs.get("ip"))))
            out.append(Evidence(e.t, "acct:" + e.account, "session_replay", 3.0,
                                f"session {sid[:24]} presented by a different client ({ua}) than the one it was issued to",
                                subject_kind=ACCOUNT, behavior="account_takeover", source="correlation"))
        if ip not in ips:
            ips[ip] = [e.t, e.t, e.attrs.get("device")]
        cur = ips[ip]
        for other, (f_t, l_t, _dev) in ips.items():
            if other == ip:
                continue
            # interleaving: the network that appeared first is still in use after the other one appeared
            interleaved = True if cur[0] <= f_t else l_t >= cur[0]
            if interleaved and e.t - l_t <= SESSION_WINDOW_H and not st["flagged"]:
                st["flagged"] = True
                for bad_ip, (_, _, bdev) in ips.items():
                    if bad_ip != st["first"]:
                        self._untrusted_ctx.add((e.account, (bdev, bad_ip)))
                out.append(Evidence(e.t, "acct:" + e.account, "session_replay", 3.0,
                                    f"session {sid[:24]} used from {ip} and {other} at the same time (stolen session token)",
                                    subject_kind=ACCOUNT, behavior="account_takeover", source="correlation"))
        cur[1] = e.t
        return out

    def _identity_check(self, e, ev) -> List[Evidence]:
        """v0.4: help-desk resets and push bombing followed by a sign-in from a new device (MGM 2023, Uber 2022).
        The evidence is about the account: the employee is the victim."""
        out: List[Evidence] = []
        acct = e.account
        if e.kind == "mfa_reset":
            self._reset[acct] = (e.t, bool(e.attrs.get("verified")))
            return out
        if any(x.kind == "mfa_fatigue" for x in ev):
            self._fatigue[acct] = e.t
        if e.kind != "login":
            return out
        new_dev = e.attrs.get("device") not in self.sig.s[acct].devices
        if not new_dev:
            return out
        r = self._reset.get(acct)
        if r is not None and 0 <= e.t - r[0] <= 24:
            w = 0.8 if r[1] else 3.0
            out.append(Evidence(e.t, "acct:" + acct, "account_takeover_reset", w,
                                f"sign-in from a new device {60 * (e.t - r[0]):.0f} min after a "
                                f"{'verified' if r[1] else 'help-desk'} MFA reset", subject_kind=ACCOUNT,
                                behavior="account_takeover", source="correlation"))
        f = self._fatigue.get(acct)
        if f is not None and 0 <= e.t - f <= 2:
            out.append(Evidence(e.t, "acct:" + acct, "account_takeover_reset", 3.0,
                                "sign-in from a new device right after a burst of denied push prompts", subject_kind=ACCOUNT,
                                behavior="account_takeover", source="correlation"))
        return out

    def _idp_check(self, e) -> List[Evidence]:
        """v0.5: rules for identity-provider logs. All of them describe an account under attack, so the evidence
        is about the account (P4), not about the employee."""
        import math
        out: List[Evidence] = []
        acct, a = e.account, "acct:" + e.account
        ip = e.attrs.get("ip")
        if e.kind == "login_failure" and ip:
            win = [(t, x) for t, x in self._fail_ip[ip] if e.t - t <= 1.0] + [(e.t, acct)]
            self._fail_ip[ip] = win
            targets = {x for _, x in win}
            if len(targets) >= 5:
                for x in targets:
                    if e.t - self._sprayed.get(x + "|" + ip, -1e9) > 24:
                        self._sprayed[x + "|" + ip] = e.t
                        out.append(Evidence(e.t, "acct:" + x, "password_spray", 1.0,
                                            f"one network ({ip}) failed sign-ins on {len(targets)} accounts within an hour",
                                            subject_kind=ACCOUNT, behavior="credential_attack", source="correlation"))
        if e.kind == "idp_risk":
            w = 2.0 if e.attrs.get("severity") == "high" else 1.0
            out.append(Evidence(e.t, a, "idp_risk", w, f"identity provider risk alert: {e.attrs.get('source', 'risk signal')}",
                                subject_kind=ACCOUNT, behavior="account_takeover", source="identity provider"))
        if e.kind == "app_denied":
            out.append(Evidence(e.t, acct, "app_denied", 0.4, "attempted access to an application not assigned",
                                behavior="privilege_misuse"))
        if e.kind == "mfa_enroll":
            self._reset[acct] = (e.t, True)        # a new factor or device: a later new-device sign-in is weak evidence
        lat, lon = e.attrs.get("lat"), e.attrs.get("lon")
        if lat is not None and lon is not None and e.kind in ("login", "mfa_push", "config_change", "login_failure"):
            prev = self._last_geo.get(acct)
            if prev is not None:
                p1, p2 = math.radians(prev[1]), math.radians(lat)
                dl = math.radians(lon - prev[2])
                km = 6371 * math.acos(max(-1.0, min(1.0, math.sin(p1) * math.sin(p2) + math.cos(p1) * math.cos(p2) * math.cos(dl))))
                hours = max(e.t - prev[0], 1 / 60)
                if km > 500 and km / hours > 1000:
                    self._untrusted_ctx.add((acct, (e.attrs.get("device"), ip)))
                    out.append(Evidence(e.t, a, "impossible_travel", 2.0,
                                        f"{km:.0f} km from the previous sign-in location in {60 * hours:.0f} min",
                                        subject_kind=ACCOUNT, behavior="account_takeover", source="correlation"))
            self._last_geo[acct] = (e.t, lat, lon)
        return out

    def _cloud_check(self, e) -> List[Evidence]:
        """v0.6: rules for cloud audit logs (Entra ID, Microsoft 365, AWS CloudTrail). Each rule fires at most once a
        day per account and kind. Changes and data access are attributed to the person; repeated failures to the account."""
        out: List[Evidence] = []
        acct, person = e.account, self.owners.get(e.account, e.account)
        what = e.attrs.get("what")

        def once(kind, subject, weight, desc, behavior, subject_kind=None, source="cloud audit log"):
            key = (kind, subject, what if kind != "brute_force" else None, int(e.t // 24))
            if key in self._once:
                return
            self._once[key] = e.t
            kw = {"subject_kind": subject_kind} if subject_kind else {}
            out.append(Evidence(e.t, subject, kind, weight, desc, behavior=behavior, source=source, **kw))

        if e.kind == "config_change" and what in ("privilege_grant", "credential_added", "mfa_method"):
            w = 0.3 if e.attrs.get("ticket") else (0.5 if e.attrs.get("minor") and self.cfg.patch >= 2 else 2.0)
            once("identity_config_change", person, w, f"identity configuration changed: {what}", "privilege_misuse")
        elif e.kind == "config_change" and what == "new_principal":
            once("new_principal", person, 0.5, "new user, guest or application created", "privilege_misuse")
        elif e.kind == "audit_change":
            once("audit_tamper", person, 3.0, f"logging or protection changed: {what}", "defense_evasion")
        elif e.kind == "mail_rule":
            once("mail_forwarding", person, 2.0, f"mail rule created or changed: {what}", "exfiltration")
        elif e.kind == "data_access":
            once("bulk_data_access", person, 1.5, f"sensitive data access: {what}", "exfiltration")
        elif e.kind == "login_failure":
            win = [t for t in self._fail_acct[acct] if e.t - t <= 1.0] + [e.t]
            self._fail_acct[acct] = win
            if len(win) >= 10:
                once("brute_force", "acct:" + acct, 1.0, f"{len(win)} failed sign-ins within an hour", "credential_attack",
                     subject_kind=ACCOUNT, source="correlation")
        elif e.kind == "api_read":
            win = [x for x in self._reads[acct] if e.t - x[0] <= 1.0] + [(e.t, what, e.attrs.get("error"))]
            self._reads[acct] = win
            if len({x[1] for x in win}) >= 20 or sum(1 for x in win if x[2]) >= 10:
                once("discovery", person, 1.0, f"{len({x[1] for x in win})} different read calls, "
                     f"{sum(1 for x in win if x[2])} denied, within an hour", "reconnaissance", source="correlation")
        return out

    def _v10_check(self, e) -> List[Evidence]:
        """v1.0 rules (events from npcore.sources plus the earlier adapters). Each rule fires at most once a day per
        subject and kind. Subjects: changes and data movement -> the person; attacks on a credential (spraying,
        device-code phishing, concurrent networks, a session that jumps) -> the account; what an AI agent does with
        its tools -> the agent's own account ("acct:agent:<id>"), so the person who runs the agent is not blamed."""
        import ipaddress
        import math
        from . import aiguard
        out: List[Evidence] = []
        acct, person = e.account, self.owners.get(e.account, e.account)
        k, what, a = e.kind, e.attrs.get("what"), e.attrs
        day = int(e.t // 24)

        def once(kind, subject, weight, desc, behavior, extra=None, account=False, source="v1.0 rule"):
            key = ("v10", kind, subject, extra, day)
            if key in self._once:
                return
            self._once[key] = e.t
            kw = {"subject_kind": ACCOUNT} if account else {}
            out.append(Evidence(e.t, subject, kind, weight, desc, behavior=behavior, source=source, **kw))

        def window(lst, h=1.0):
            lst[:] = [x for x in lst if e.t - (x[0] if isinstance(x, tuple) else x) <= h]

        agent = "acct:agent:" + acct
        # ---- code platforms and cloud control planes
        if k == "control_change":
            once("control_disabled", person, 2.5, f"security control switched off: {what}", "defense_evasion", what)
        elif k == "destructive_change":
            from .opclass import critical
            if self.cfg.patch >= 2:                        # 1.0.2: weight by impact
                w = 0.5 if what == "repo.archived" else (2.0 if critical(what) else 0.5)
            else:
                w = 1.0 if what == "repo.archived" else 2.0
            once("destructive_change", person, w, f"destructive change: {what}", "sabotage", what)
        elif k == "denied_change" and self.cfg.signals_v11:                         # v1.1: a denied attempt to tamper, disable or destroy
            intended, w = str(what).split("|", 1)
            kind = {"audit_change": "audit_tamper", "control_change": "control_disabled",
                    "secret_read": "secret_access"}.get(intended, "destructive_change")
            once(kind, person, 0.5 if intended == "secret_read" else 1.0, f"attempted, denied: {w}", "defense_evasion",
                 "denied:" + w)
        elif k == "protected_push":
            once("protected_push", person, 1.5, f"branch protection overridden to push to {what}", "defense_evasion", what)
        elif k == "external_share":
            once("external_share", person, 0.5 if str(what).startswith("mail") else 1.0,
                 f"{what} to {a.get('dest')}", "exfiltration", a.get("dest"))
        elif k == "secret_read":
            w = 2.0 if str(what).startswith("list *") else 1.0
            if self.cfg.patch >= 2 and str(what).startswith(("get ", "watch ")):
                w = 0.5                                    # one named secret in one namespace: what applications do
            once("secret_access", person, w, f"Kubernetes secret read: {what}", "credential_access", what)
        elif k == "workload_create":
            w = {"privileged_pod": 2.0, "host_namespace": 2.0, "dangerous_capabilities": 2.0, "daemonset": 1.0, "exec": 1.0,
                 "system_namespace": 1.0, "remote_exec": 1.0, "admission_webhook": 1.5}.get(what, 0.5)
            if what == "exec" and self.cfg.patch >= 2:
                w = 0.5                                    # developers exec into pods routinely
            once("privileged_workload", person, w, f"{what} created ({a.get('ns')}/{a.get('name')})", "privilege_misuse", what)
        elif k == "forbidden":
            lst = self._forbidden[acct]
            lst.append(e.t)
            window(lst)
            anon = a.get("anonymous")
            if len(lst) >= (3 if anon else 5):
                once("discovery", ("acct:" + acct) if anon else person, 1.0, f"{len(lst)} denied API requests within an hour",
                     "reconnaissance", account=bool(anon))
            elif a.get("write") and not anon:
                once("discovery", person, 0.5, f"denied write: {what}", "reconnaissance", what)
        elif k == "scanner_seen":
            ext = acct.startswith(("anonymous@", "cluster:"))
            once("discovery", ("acct:" + acct) if ext else person, 1.5, f"cluster scanner seen: {what}", "reconnaissance",
                 what, account=ext)
        elif k == "object_read":
            lst = self._obj_reads[acct]
            lst.append(e.t)
            window(lst)
            if len(lst) >= 50:
                once("bulk_data_access", person, 1.5, f"{len(lst)} objects read within an hour", "exfiltration")
        elif k == "device_code_login":
            once("device_code_phish", "acct:" + acct, 1.0, f"sign-in with the device-code flow ({a.get('app')})",
                 "account_takeover", account=True)
        # ---- AI assistants and agents
        elif k == "ai_invoke":
            subj = agent if a.get("agent") else person
            inj = aiguard.injection(a.get("prompt") or "")
            if inj:
                once("prompt_injection", subj, 1.0, f"prompt-injection / jailbreak phrasing ({', '.join(inj)})",
                     "policy_violation", account=subj == agent)
            sec = aiguard.secrets(a.get("prompt") or "")
            if sec:
                once("sensitive_prompt", subj, 0.5, f"credentials in a prompt ({', '.join(sec)})", "data_handling",
                     account=subj == agent)
            risky = aiguard.risky_tools(a.get("tools") or [])
            if risky:
                once("agent_high_risk_tool", agent, 0.5, f"agent called tools that run code, write files or reach the "
                     f"network: {', '.join(risky)}", "excessive_agency", account=True)
            hour = int(e.t)
            self._ai_hour[(acct, hour)] += int(a.get("in_tok") or 0)
            peers = sorted(v for (p, _), v in self._ai_hour.items() if p != acct)
            med = peers[len(peers) // 2] if peers else 0
            if self._ai_hour[(acct, hour)] >= max(500_000, 10 * med):
                once("ai_usage_spike", subj, 0.5, f"{self._ai_hour[(acct, hour)]:,} input tokens within an hour",
                     "unbounded_consumption", "tokens", account=subj == agent)
            if int(a.get("out_tok") or 0) >= 10_000:
                once("ai_usage_spike", subj, 0.5, f"{a['out_tok']:,} output tokens in one response",
                     "unbounded_consumption", "output", account=subj == agent)
            r1, r2 = a.get("region"), a.get("inference_region")
            if r1 and r2 and r1.split("-")[0] != r2.split("-")[0]:
                once("ai_usage_spike", subj, 0.5, f"request from {r1} served in {r2} (another geography)",
                     "unbounded_consumption", "region", account=subj == agent)
        elif k == "agent_exec":
            cli = aiguard.autonomy_override(a.get("cmdline") or "")
            if cli:
                once("agent_autonomy_override", agent, 1.0, f"{cli} started with every approval switched off",
                     "excessive_agency", cli, account=True)
        # ---- credentials: distributed spraying, concurrent networks, a session that jumps
        if k == "login_failure":
            self._tenant_fail.append((e.t, acct, a.get("ip")))
            window(self._tenant_fail)
            accts = {x[1] for x in self._tenant_fail}
            ips = {x[2] for x in self._tenant_fail if x[2]}
            if len(accts) >= 10 and len(ips) >= 5:
                for x in sorted(accts):
                    key = ("v10", "password_spray", "acct:" + x, "distributed", day)
                    if key not in self._once:
                        self._once[key] = e.t
                        out.append(Evidence(e.t, "acct:" + x, "password_spray", 0.5,
                                            f"failed sign-ins on {len(accts)} accounts from {len(ips)} networks within an hour "
                                            f"(distributed spraying)", subject_kind=ACCOUNT, behavior="credential_attack",
                                            source="correlation"))
        ip = a.get("ip")
        ua = str(a.get("ua") or "")
        if ua.lower().replace("-", " ").startswith("aws internal"):   # AWS console placeholder: names no device
            ua = ""
        if k in ("login", "api_read") and ip and not a.get("error"):
            try:
                addr = ipaddress.ip_address(str(ip))
            except ValueError:
                addr = None
            if addr is not None and addr.is_global:
                net = str(ipaddress.ip_network(f"{addr}/{16 if addr.version == 4 else 48}", strict=False))
                nets = self._nets[acct]
                f, _, uas = nets.get(net, (e.t, e.t, set()))
                uas = uas | ({ua} if ua else set())
                nets[net] = (f, e.t, uas)
                # another network of the same IP family, in use within 10 minutes, by a different client
                others = [n for n, (_, l, u2) in nets.items() if n != net and e.t - l <= 1 / 6 and
                          ipaddress.ip_network(n).version == addr.version and not (uas & u2)]
                if others:
                    once("session_replay", "acct:" + acct, 1.0, f"account used from {net} and {others[0]} within 10 minutes",
                         "account_takeover", "concurrent", account=True, source="correlation")
        sid, lat, lon = a.get("sid"), a.get("lat"), a.get("lon")
        if sid and lat is not None and lon is not None:
            prev = self._sess_geo.get(sid)
            if prev is not None:
                p1, p2 = math.radians(prev[1]), math.radians(lat)
                km = 6371 * math.acos(max(-1.0, min(1.0, math.sin(p1) * math.sin(p2) + math.cos(p1) * math.cos(p2)
                                                    * math.cos(math.radians(lon - prev[2])))))
                hours = max(e.t - prev[0], 1 / 60)
                if km > 500 and km / hours > 1000:
                    once("session_replay", "acct:" + acct, 3.0, f"the same session {str(sid)[:20]} moved {km:.0f} km in "
                         f"{60 * hours:.0f} min (stolen session cookie)", "account_takeover", "geo", account=True,
                         source="correlation")
            self._sess_geo[sid] = (e.t, lat, lon)
        return out

    def _intent(self, person: str) -> bool:
        if any(x.weight > 0 and (x.kind in INTENT_KINDS or x.source == "deception") for x in self.trust.evidence(person)):
            return True
        # restricted data sent to the same destination again: a pattern, not a slip
        return any(n >= 2 for n in self._sens_egress.get(person, {}).values())

    def _add(self, x: Evidence) -> None:
        self.trust.add(x)
        if x.weight > 0:
            self._day_neg[(x.subject, int(x.t // 24) + 1)] = True
        p = x.to_dict(); p["subject"] = self.pz.pseudonym(x.subject)
        self.ledger.append("evidence", p, x.t)
        self._update_level(x.subject, x.t, x.subject_kind)

    def _update_level(self, s: str, t: float, kind: str = PERSON) -> None:
        tr = self.trust.trust(s, t)
        new = P.level_for(tr, self.cfg.policy)
        if (self.cfg.proportional and kind == PERSON and not s.startswith("acct:") and s not in self.forced
                and new > P.Level.L2_DUAL_CONTROL and not self._intent(s)):
            new = P.Level.L2_DUAL_CONTROL
        old = self.level[s]
        if new != old:
            self.level[s] = new
            self.level_log.append((t, s, int(old), int(new)))
            self.ledger.append("level_change", {"subject": self.pz.pseudonym(s), "from": int(old), "to": int(new),
                                                "trust": round(tr, 3)}, t)
            if new >= P.Level.L3_READ_ONLY and self.cfg.enforce == "auto":
                n = self.leases.revoke_all(s)
                if n:
                    self.ledger.append("leases_revoked", {"subject": self.pz.pseudonym(s), "count": n}, t)
        if s in self.cases or s in self.forced:
            return
        if self.cfg.enforce == "auto" and new >= P.Level.L4_ISOLATE:
            self._open_case(s, t, t + self.cfg.review_delay_h, "isolation")
        elif self.cfg.enforce == "alert" and tr < self.cfg.alert_threshold:
            self._open_case(s, t, t + self.cfg.alert_delay_h, "alert")

    def _open_case(self, s, t, due, kind):
        ev = [x for x in self.trust.evidence(s) if x.weight > 0][-12:]
        case = {"subject": s, "opened": t, "due": due, "kind": kind, "trust": round(self.trust.trust(s, t), 3),
                "evidence": [x.desc for x in ev]}
        self.cases[s] = case
        self.ledger.append("case_opened", {"subject": self.pz.pseudonym(s), "kind": kind, "due": due}, t)

    def due_cases(self, t: float) -> List[dict]:
        return [c for c in self.cases.values() if c["due"] <= t]

    def review(self, subject: str, confirmed: bool, t: float, reviewer: str = "reviewer") -> None:
        """Human decision on a case. Confirmed -> isolate until resolved. Dismissed -> negative
        evidence is scaled down (kept in the ledger) and containment is lifted."""
        case = self.cases.pop(subject)
        case.update(closed=t, confirmed=confirmed)
        self.case_log.append(case)
        self.ledger.append("case_closed", {"subject": self.pz.pseudonym(subject), "confirmed": confirmed, "by": reviewer}, t)
        if confirmed:
            self.forced[subject] = P.Level.L4_ISOLATE
        else:
            self.trust.reset_negative(subject, t, factor=0.2)
            self._update_level(subject, t)

    # ------------------------------------------------------------------ day boundary
    def end_of_day(self, day: int) -> None:
        t = day * 24 - 0.001
        if not self.cfg.signals:
            return
        for (acct, d), n in list(self._day_act.items()):
            if d == day and n >= 5 and not self._day_neg[(acct, d)]:
                self._add(Evidence(t, acct, "clean_day", W["clean_day"], "full working day without negative evidence"))
        for s in list(self.level.keys()):
            self._update_level(s, t)
