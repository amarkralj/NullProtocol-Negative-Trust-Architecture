# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 amarkralj (https://github.com/amarkralj), Xevoris Labs
"""Behaviour signals with personal baselines.

Each signal is deliberately simple and explainable (robust statistics, no black box), because
monitoring results that affect employees must be explainable to the employee, the works council
and, if it comes to it, a labour court. Weights are the evidential strength in trust units.
The same signal library is used by the NullProtocol Negative Trust engine and by the zero-trust/UEBA baseline,
so differences in results come from the architecture, not from better features.
"""
from __future__ import annotations

import statistics
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .evidence import Evidence

PERSONAL_DOMAINS = ("gmail.", "protonmail.", "outlook.", "gmx.", "web.de", "yahoo.", "icloud.")
PERSONAL_CLOUD = ("personal", "dropbox", "mega", "google drive", "onedrive-personal", "icloud")

W = {
    "off_hours_login": 0.35,
    "new_device": 0.4,
    "foreign_ip": 0.5,
    "impossible_context": 0.8,
    "cross_dept_sensitive_read": 0.3,
    "read_volume_spike": 0.8,
    "bulk_copy": 1.0,
    "archive": 0.6,
    "egress_removable": 1.2,
    "egress_personal_cloud": 1.2,
    "egress_cloud": 0.6,
    "email_personal": 0.9,
    "email_unknown_external": 0.4,
    "email_sensitive_attachment": 0.3,
    "clone_spike": 0.8,
    "negative_sentiment": 0.2,
    "secret_in_commit": 0.7,
    "cross_dept_grant": 0.4,
    "blocked_attempt": 0.5,
    "clean_day": -0.15,
    # v0.2 signals (enabled with SignalExtractor(v02=True))
    "egress_habitual": 0.15,         # non-sensitive data over a channel this person uses routinely
    "lookalike_domain": 0.6,         # attachment to a domain that imitates a known partner/used domain
    "lookalike_repeat": 1.2,         # sensitive data to the same lookalike domain again (intent, not typo)
    "egress_rate_spike": 1.0,        # many more removable-media copies today than this person's normal
    "leak_site_contact": 1.5,        # web gateway category: anonymous disclosure / leak site
    "spyware_download": 1.2,         # web gateway category: keylogger / spyware vendor
    # v0.4 signals (enabled with SignalExtractor(v04=True)); modelled on documented incidents
    "dormant_reuse": 1.5,            # account unused for 30+ days, now used from a new device or without MFA
    "no_mfa_login": 0.4,             # sign-in completed without a second factor
    "mfa_fatigue": 1.0,              # five or more denied push prompts within an hour
    "identity_config_change": 2.0,   # new identity provider, federation, admin API token, MFA policy
    "purpose_violation": 0.15,       # customer record opened without an assigned ticket (weak alone)
    "record_volume_spike": 1.2,      # many more unassigned look-ups than this person's normal
    "post_termination_activity": 4.0,  # any activity after the HR end date
    "edr_high": 2.5,                 # endpoint security: high-severity finding (e.g. infostealer)
    "remote_access_tool": 0.8,       # endpoint security: remote-access tool
    "edr_low": 0.1,                  # endpoint security: low-severity finding (e.g. adware)
    # v0.8 signals (SignalExtractor(v08=True)): habitual channels and leavers
    "channel_burst": 0.0,            # 7-day burst on an egress channel; off: trained weight on CERT r4.2 is 0 (false alarms)
    "leaver_egress": 0.5,            # routine egress during an HR-recorded notice period (trained on CERT r4.2)
    "workload_new_network": 1.0,     # an integration token used from a network it never used
    "workload_volume_spike": 1.5,    # an integration exporting far more than its normal
    "secret_search": 2.5,            # queries searching stored data for credentials
}
SECRET_TERMS = ("akia", "password", "secret_key", "vpn", "api_key", "token=")
DAILY_CAP = {"off_hours_login": 0.35, "cross_dept_sensitive_read": 1.2, "negative_sentiment": 0.4,
             "email_personal": 1.8, "email_unknown_external": 0.8, "egress_habitual": 0.3,
             "purpose_violation": 0.6, "no_mfa_login": 0.4, "edr_low": 0.2, "workload_new_network": 1.0,
             "post_termination_activity": 4.0}
BEHAVIOR = {
    "off_hours_login": "unusual_hours_access", "cross_dept_sensitive_read": "cross_dept_snooping",
    "read_volume_spike": "excessive_access", "bulk_copy": "host_data_hoarding", "archive": "host_data_hoarding",
    "egress_removable": "data_exfil", "egress_personal_cloud": "data_exfil", "egress_cloud": "data_exfil",
    "email_personal": "data_exfil_email", "email_unknown_external": "data_exfil_email",
    "email_sensitive_attachment": "data_exfil_email", "clone_spike": "excessive_repo_cloning",
    "negative_sentiment": "sentiment_drift", "secret_in_commit": "secret_in_commit",
    "new_device": "idp_anomaly", "foreign_ip": "idp_anomaly", "impossible_context": "idp_anomaly",
    "cross_dept_grant": "privilege_misuse",
    "egress_habitual": "data_exfil", "lookalike_domain": "data_exfil_email", "lookalike_repeat": "data_exfil_email",
    "egress_rate_spike": "data_exfil", "leak_site_contact": "data_exfil", "spyware_download": "malware_tooling",
    "dormant_reuse": "account_takeover", "no_mfa_login": "idp_anomaly", "mfa_fatigue": "account_takeover",
    "identity_config_change": "privilege_misuse", "purpose_violation": "unauthorised_lookup",
    "record_volume_spike": "unauthorised_lookup", "post_termination_activity": "lifecycle_violation",
    "edr_high": "malware_tooling", "remote_access_tool": "malware_tooling", "edr_low": "malware_tooling",
    "channel_burst": "data_exfil", "leaver_egress": "data_exfil",
    "workload_new_network": "token_misuse", "workload_volume_spike": "token_misuse", "secret_search": "token_misuse",
}
HABIT_MIN = 3        # prior uses of a channel before it counts as habitual
BREADTH_DESTS = 5    # v0.9: someone who has uploaded to this many different sites ...
BREADTH_USES = 10    # ... at least this many times treats a new (non-storage) site as routine
BURST_P = 1e-3       # v0.8: a 7-day count this unlikely under the person's own weekly rate (Poisson) is a burst
BURST_MIN = 5        # ... and at least this many events in the 7 days
BURST_HIST_W = 4     # ... with at least this many weeks of history


def _poisson_tail(k: int, lam: float) -> float:
    """P(X >= k) for X ~ Poisson(lam)."""
    import math
    if lam <= 0:
        return 0.0 if k > 0 else 1.0
    term, cdf = math.exp(-lam), 0.0
    for i in range(k):
        cdf += term
        term *= lam / (i + 1)
    return max(0.0, 1.0 - cdf)


def _edit_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 9
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def _stem(dom: str) -> str:
    return dom.split(".")[0].replace("-", "").replace("_", "")


@dataclass
class _Acct:
    login_hours: List[float] = field(default_factory=list)
    devices: set = field(default_factory=set)
    ips: set = field(default_factory=set)
    reads_by_day: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    msgs: int = 0
    neg_msgs: int = 0
    ext_domains: set = field(default_factory=set)
    spent_today: Dict[tuple, float] = field(default_factory=lambda: defaultdict(float))
    spiked: set = field(default_factory=set)
    channel_uses: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    lookalikes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    usb_by_day: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    usb_spiked: set = field(default_factory=set)
    last_login_day: Optional[int] = None
    denies: List[float] = field(default_factory=list)
    unassigned_by_day: Dict[int, int] = field(default_factory=lambda: defaultdict(int))
    lookup_spiked: set = field(default_factory=set)
    wl_ips: set = field(default_factory=set)
    wl_objects: List[int] = field(default_factory=list)
    ch_days: Dict[str, Dict[int, int]] = field(default_factory=lambda: defaultdict(lambda: defaultdict(int)))
    ch_first: Dict[str, int] = field(default_factory=dict)
    burst_day: Dict[str, int] = field(default_factory=dict)
    leaver_days: set = field(default_factory=set)
    cloud_dests: set = field(default_factory=set)
    cloud_uses: int = 0


class SignalExtractor:
    def __init__(self, owners_dept: Dict[str, str], warmup_days: int = 14, partner_domains=(), v02: bool = False,
                 v04: bool = False, v08: bool = False, v09: bool = False):
        self.v02 = v02
        self.v04 = v04
        self.v08 = v08 or v09
        self.v09 = v09
        self.notice: Dict[str, float] = {}       # v0.8: account -> start of the HR-recorded notice period
        self.terminated: Dict[str, float] = {}
        self.dept = owners_dept
        self.warmup = warmup_days
        self.partners = tuple(partner_domains)
        self.s: Dict[str, _Acct] = defaultdict(_Acct)

    # -- helpers ---------------------------------------------------------------------------
    def _emit(self, out, a: _Acct, day, t, subj, kind, desc, refs=(), weight=None):
        w = W[kind] if weight is None else weight
        cap = DAILY_CAP.get(kind)
        if cap is not None:
            used = a.spent_today[(day, kind)]
            if used >= cap:
                return
            w = min(w, cap - used)
            a.spent_today[(day, kind)] += w
        out.append(Evidence(t, subj, kind, w, desc, behavior=BEHAVIOR.get(kind), refs=tuple(refs)))

    def _off_hours(self, a: _Acct, hour: float) -> bool:
        hs = a.login_hours
        if len(hs) < 8:
            return hour < 6.5 or hour > 20
        q = statistics.quantiles(hs, n=20)
        return hour < q[0] - 1.0 or hour > q[-1] + 1.0

    def enroll(self, account: str, device, ip) -> None:
        """Called after a login was verified (step-up passed): the device/IP become known."""
        a = self.s[account]
        a.devices.add(device); a.ips.add(ip)

    def _habitual(self, a: _Acct, channel: str, e, warm: bool):
        """v0.2: personal baseline for egress channels. During the learning period, non-sensitive
        egress only builds the baseline ("learn": no evidence). Afterwards a channel this person has
        used at least HABIT_MIN times is routine; routine use with non-sensitive data is weak
        evidence. Sensitive data over a routine channel, and any first use, keep the full weight."""
        if not self.v02:
            return False
        n = a.channel_uses[channel]
        a.channel_uses[channel] += 1
        if not warm and not e.sensitive:
            return "learn"
        return n >= HABIT_MIN and not e.sensitive

    def _channel(self, e) -> Optional[str]:
        if e.kind == "egress_usb":
            return "usb"
        if e.kind == "egress_cloud":
            return "cloud"
        if e.kind == "email" and e.attrs.get("external") and e.attrs.get("attachment") \
                and str(e.attrs.get("to", "")).split("@")[-1] not in self.partners:
            return "email_ext"
        return None

    def _v08(self, e, a: _Acct, acct: str, day: int, warm: bool) -> List[Evidence]:
        """v0.8: (1) bursts on egress channels measured against the person's own weekly rate, so routine use does
        not hide a sudden increase; (2) HR notice periods: routine egress by someone who is leaving is evidence again."""
        out: List[Evidence] = []
        if e.kind == "lifecycle" and e.attrs.get("status") == "notice":
            self.notice[acct] = e.t
            return out
        ch = self._channel(e)
        if ch is None:
            return out
        a.ch_first.setdefault(ch, day)
        a.ch_days[ch][day] += 1
        if not warm:
            return out
        start = max(a.ch_first[ch], day - 63)
        weeks = (day - 7 - start) / 7
        if weeks >= BURST_HIST_W and day - a.burst_day.get(ch, -99) >= 7:
            c7 = sum(a.ch_days[ch].get(d, 0) for d in range(day - 6, day + 1))
            base = sum(a.ch_days[ch].get(d, 0) for d in range(start, day - 6)) / weeks
            if c7 >= BURST_MIN and _poisson_tail(c7, base) < BURST_P:
                a.burst_day[ch] = day
                self._emit(out, a, day, e.t, acct, "channel_burst",
                           f"{c7} {ch} transfers in 7 days vs {base:.1f} per week usually")
        return out

    def _routine(self, out, a: _Acct, day, e, acct, channel: str, desc: str):
        """Routine (habitual) egress: weak evidence; during a notice period (v0.8) it counts as leaver egress."""
        if self.v08 and acct in self.notice and e.t >= self.notice[acct]:
            if (channel, day) not in a.leaver_days:
                a.leaver_days.add((channel, day))
                self._emit(out, a, day, e.t, acct, "leaver_egress", desc.replace("routine for this person", "during notice period"))
            return
        self._emit(out, a, day, e.t, acct, "egress_habitual", desc)

    def _v04(self, e, a: _Acct, acct: str, day: int, warm: bool) -> List[Evidence]:
        """Signals modelled on documented incidents (see sim_cases)."""
        out: List[Evidence] = []
        k = e.kind
        if k == "lifecycle" and e.attrs.get("status") == "terminated":
            self.terminated[acct] = e.t
            return out
        if acct in self.terminated and e.t > self.terminated[acct] + 1 and k not in ("lifecycle", "mfa_push"):
            self._emit(out, a, day, e.t, acct, "post_termination_activity", f"{k} on an account whose holder left the organisation")
        if k == "login":
            if e.attrs.get("mfa") is False:
                self._emit(out, a, day, e.t, acct, "no_mfa_login", "sign-in without a second factor")
            last = a.last_login_day
            new_dev = e.attrs.get("device") not in a.devices
            if warm and last is not None and day - last >= 30 and (new_dev or e.attrs.get("mfa") is False):
                self._emit(out, a, day, e.t, acct, "dormant_reuse", f"first use in {day - last} days, from a new device or without MFA")
            a.last_login_day = day
        elif k == "mfa_push":
            if e.attrs.get("result") == "deny":
                a.denies = [t for t in a.denies if e.t - t <= 1.0] + [e.t]
                if len(a.denies) == 5:
                    self._emit(out, a, day, e.t, acct, "mfa_fatigue", "5 denied push prompts within an hour (push bombing)")
        elif k == "config_change":
            if e.attrs.get("what") in ("add_identity_provider", "federation", "add_admin_api_token", "mfa_policy", "disable_mfa"):
                if e.attrs.get("ticket"):     # approved change with a change ticket: recorded, weak
                    self._emit(out, a, day, e.t, acct, "identity_config_change", f"identity configuration changed under "
                               f"change {e.attrs['ticket']}: {e.attrs.get('what')}", weight=0.3)
                else:
                    self._emit(out, a, day, e.t, acct, "identity_config_change", f"identity configuration changed: {e.attrs.get('what')}")
        elif k == "record_read":
            if not e.attrs.get("assigned"):
                a.unassigned_by_day[day] += 1
                self._emit(out, a, day, e.t, acct, "purpose_violation", f"customer record {e.resource} opened without an assigned ticket")
                hist = [v for d, v in a.unassigned_by_day.items() if d < day]
                if warm and day not in a.lookup_spiked and a.unassigned_by_day[day] >= max(6, 3 * (statistics.median(hist) if hist else 0)):
                    a.lookup_spiked.add(day)
                    self._emit(out, a, day, e.t, acct, "record_volume_spike", f"{a.unassigned_by_day[day]} look-ups without a ticket today")
        elif k == "detection":
            sev, name = e.attrs.get("severity"), e.attrs.get("name", "")
            if name == "remote_access_tool":
                self._emit(out, a, day, e.t, acct, "remote_access_tool", "endpoint security: remote-access tool on the device")
            elif sev == "high":
                self._emit(out, a, day, e.t, acct, "edr_high", f"endpoint security: high-severity finding ({name})")
            else:
                self._emit(out, a, day, e.t, acct, "edr_low", f"endpoint security: low-severity finding ({name})")
        elif k == "api_export":
            ip, n, q = e.attrs.get("ip"), int(e.attrs.get("objects", 0)), str(e.attrs.get("query", "")).lower()
            if warm and a.wl_ips and ip not in a.wl_ips:
                self._emit(out, a, day, e.t, acct, "workload_new_network", f"integration token used from a new network {ip}")
            if warm and len(a.wl_objects) >= 50:
                med = statistics.median(a.wl_objects[-500:])
                if n > max(6 * med, 300):
                    self._emit(out, a, day, e.t, acct, "workload_volume_spike", f"{n} objects exported vs a median of {med:.0f}")
            if any(t in q for t in SECRET_TERMS):
                self._emit(out, a, day, e.t, acct, "secret_search", "query searches stored data for credentials")
            if not warm or ip in a.wl_ips or not a.wl_ips:
                a.wl_ips.add(ip)
                a.wl_objects.append(n)
        return out

    def _lookalike(self, a: _Acct, dom: str):
        if dom in self.partners:
            return None
        for k in self.partners:
            if _edit_distance(dom, k) <= 2 or (_stem(dom) == _stem(k) and dom != k) or \
                    (len(_stem(k)) >= 5 and _stem(k) in dom.replace("-", "").replace(".", "")):
                return k
        return None

    # -- main ------------------------------------------------------------------------------
    def observe(self, e) -> List[Evidence]:
        """e is an object with t, account, kind, resource, rdept, sensitive, nbytes, attrs."""
        out: List[Evidence] = []
        acct = e.account
        if acct not in self.dept:          # e.g. external caller: no account to attribute to
            return out
        a = self.s[acct]
        day = int(e.t // 24) + 1
        hour = e.t % 24
        warm = day > self.warmup
        k = e.kind
        if self.v04:
            out += self._v04(e, a, acct, day, warm)
        if self.v08:
            out += self._v08(e, a, acct, day, warm)
        if k == "login":
            dev, ip, ipt = e.attrs.get("device"), e.attrs.get("ip"), e.attrs.get("ip_type")
            new_dev = warm and dev not in a.devices
            foreign = warm and ipt == "foreign" and ip not in a.ips
            if warm and self._off_hours(a, hour):
                self._emit(out, a, day, e.t, acct, "off_hours_login", f"login at {hour:04.1f}h, outside personal working-hours profile")
            if new_dev:
                self._emit(out, a, day, e.t, acct, "new_device", f"login from unknown device {dev}")
            if foreign:
                self._emit(out, a, day, e.t, acct, "foreign_ip", f"login from never-seen foreign IP {ip}")
            if new_dev and foreign:
                self._emit(out, a, day, e.t, acct, "impossible_context", "unknown device and foreign IP in the same login")
            if not warm or not (new_dev or foreign):
                a.login_hours.append(hour)
                a.devices.add(dev); a.ips.add(ip)
        elif k == "read":
            a.reads_by_day[day] += 1
            if e.sensitive and e.rdept and e.rdept != self.dept[acct]:
                self._emit(out, a, day, e.t, acct, "cross_dept_sensitive_read", f"read of restricted {e.rdept} file {e.resource}", (e.resource,))
            hist = [v for d, v in a.reads_by_day.items() if d < day]
            if warm and len(hist) >= 7 and day not in a.spiked:
                med = statistics.median(hist)
                mad = statistics.median([abs(x - med) for x in hist]) or 1
                if a.reads_by_day[day] > max(2 * med, med + 6 * mad, 25):
                    a.spiked.add(day)
                    self._emit(out, a, day, e.t, acct, "read_volume_spike", f"{a.reads_by_day[day]} reads today vs median {med:.0f}")
        elif k == "copy":
            self._emit(out, a, day, e.t, acct, "bulk_copy", f"bulk copy of {e.attrs.get('files', '?')} files ({e.nbytes/1e6:.0f} MB) to local staging")
        elif k == "archive":
            self._emit(out, a, day, e.t, acct, "archive", f"archive created from staged data ({e.nbytes/1e6:.0f} MB)")
        elif k == "egress_usb":
            if self.v02:
                a.usb_by_day[day] += 1
                hist = [v for d, v in a.usb_by_day.items() if d < day]
                if warm and len(hist) >= 5 and day not in a.usb_spiked:
                    med = statistics.median(hist)
                    if a.usb_by_day[day] > max(3 * med, med + 8, 10):
                        a.usb_spiked.add(day)
                        self._emit(out, a, day, e.t, acct, "egress_rate_spike",
                                   f"{a.usb_by_day[day]} removable-media copies today vs median {med:.0f} on active days")
            hab = self._habitual(a, "usb", e, warm)
            if hab == "learn":
                pass
            elif hab:
                self._routine(out, a, day, e, acct, "usb", f"{e.nbytes/1e6:.0f} MB of non-sensitive data to removable media (routine for this person)")
            else:
                self._emit(out, a, day, e.t, acct, "egress_removable", f"{e.nbytes/1e6:.0f} MB written to removable media")
        elif k == "egress_cloud":
            dest = str(e.attrs.get("dest", "")).lower()
            kind = "egress_personal_cloud" if any(x in dest for x in PERSONAL_CLOUD) else "egress_cloud"
            hab = self._habitual(a, "cloud:" + dest, e, warm)
            broad = len(a.cloud_dests) >= BREADTH_DESTS and a.cloud_uses >= BREADTH_USES
            a.cloud_dests.add(dest)
            a.cloud_uses += 1
            if self.v09 and hab is False and broad and kind == "egress_cloud" and not e.sensitive:
                hab = True              # v0.9: routine judged by the person's upload breadth, not per site
            if hab == "learn":
                pass
            elif hab:
                self._routine(out, a, day, e, acct, "cloud", f"{e.nbytes/1e6:.0f} MB of non-sensitive data to {dest} (routine for this person)")
            else:
                self._emit(out, a, day, e.t, acct, kind, f"{e.nbytes/1e6:.0f} MB moved to cloud destination {dest}")
        elif k == "email" and e.attrs.get("external"):
            to = str(e.attrs.get("to", "")).lower()
            dom = to.split("@")[-1]
            if e.attrs.get("attachment") and self.v02 and dom not in self.partners:
                look = self._lookalike(a, dom)
                if look:
                    a.lookalikes[dom] += e.sensitive
                    if e.sensitive and a.lookalikes[dom] >= 2:
                        self._emit(out, a, day, e.t, acct, "lookalike_repeat", f"restricted file sent again to lookalike domain {dom} (imitates {look})")
                    else:
                        self._emit(out, a, day, e.t, acct, "lookalike_domain", f"attachment sent to {dom}, which imitates {look}")
            if e.attrs.get("attachment"):
                if any(dom.startswith(p) or p in dom for p in PERSONAL_DOMAINS):
                    hab = self._habitual(a, "email_personal", e, warm)
                    if hab == "learn":
                        pass
                    elif hab:
                        self._routine(out, a, day, e, acct, "email_personal", f"non-sensitive attachment to personal webmail {to} (routine for this person)")
                    else:
                        self._emit(out, a, day, e.t, acct, "email_personal", f"attachment sent to personal webmail {to}")
                elif dom not in self.partners and dom not in a.ext_domains:
                    self._emit(out, a, day, e.t, acct, "email_unknown_external", f"attachment sent to never-used external domain {dom}")
                if e.sensitive:
                    self._emit(out, a, day, e.t, acct, "email_sensitive_attachment", "attachment is a restricted file")
            a.ext_domains.add(dom)
        elif k == "web":
            cat = e.attrs.get("category")
            if cat == "leak_site":
                self._emit(out, a, day, e.t, acct, "leak_site_contact", f"visited anonymous-disclosure site ({str(e.resource)[:40]})")
            elif cat == "spyware":
                self._emit(out, a, day, e.t, acct, "spyware_download", f"visited keylogger/spyware vendor ({str(e.resource)[:40]})")
        elif k == "clone":
            if e.attrs.get("count", 0) >= 10:
                self._emit(out, a, day, e.t, acct, "clone_spike", f"{e.attrs['count']} repositories cloned in one session")
        elif k == "msg":
            a.msgs += 1
            neg = e.attrs.get("sentiment") == "negative"
            a.neg_msgs += neg
            if neg and warm and (a.neg_msgs / max(a.msgs, 1)) > 0.08:
                self._emit(out, a, day, e.t, acct, "negative_sentiment", "negative message tone above personal baseline")
        elif k == "commit" and e.attrs.get("secret"):
            self._emit(out, a, day, e.t, acct, "secret_in_commit", "credential committed to repository")
        elif k == "grant":
            g = e.attrs.get("grantee")
            if g in self.dept and self.dept[g] != (e.rdept or self.dept[acct]):
                self._emit(out, a, day, e.t, acct, "cross_dept_grant", f"granted {e.rdept} restricted access to {g} from {self.dept[g]}")
        return out
