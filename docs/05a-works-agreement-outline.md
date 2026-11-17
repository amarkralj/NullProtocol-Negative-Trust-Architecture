# Outline: works agreement (Betriebsvereinbarung) for a NullProtocol Negative Trust system

*Author: [github.com/amarkralj](https://github.com/amarkralj)*

*Template for discussion with a works council. Not legal advice.*

1. **Purpose.** Protection of trade secrets, personal data of customers and employees, and IT systems against
   misuse and compromise. Use for performance or behaviour evaluation is prohibited.
2. **Scope.** Systems and data sources connected (IdP, endpoint/DLP, mail gateway, file/DB/repo audit logs). No content
   inspection of e-mail, chat or documents. Message-tone analysis: not used.
3. **Signals.** Exhaustive list of signals and their weights (annex), including decoys in general terms. Changes need
   the works council's approval.
4. **Pseudonymisation.** All analysis on pseudonyms. The pseudonymisation key is held by [data protection officer].
   Re-identification only with two approvers from [DPO, CISO, works council member], a documented reason and an
   entry in the ledger. The works council receives the list of re-identifications quarterly.
5. **Containment levels.** L1 step-up, L2 second approver for data egress, L3 read-only, L4 isolation. L4 always opens
   a case; review within [8] working hours. The affected person is informed when L3/L4 lasts longer than [one working day]
   and may present their view.
6. **Consequences.** No employment measure based solely on the system. Any measure requires a human assessment of the
   evidence and a hearing of the employee.
7. **Victims and negligence.** Compromised accounts are handled as security incidents of the account; the owner is
   treated as a victim. Negligent incidents lead to support and training, not disciplinary steps, unless repeated
   after training.
8. **Whistleblowing.** Reporting channels under the HinSchG are allow-listed and exempt.
9. **Retention.** Weak evidence: [14] days. Evidence on persons cleared by review: deleted after [30] days (payload
   keys destroyed; ledger hashes remain). Confirmed cases: until conclusion of proceedings.
10. **Reporting.** Quarterly report to the works council with the metrics in `docs/03-metrics.md`: innocents contained,
    innocent cases, step-ups and dual-control requests per 1000 user-days, re-identifications.
11. **Evaluation and termination.** Review after 12 months; the agreement ends the use of the system if the
    false-containment rate exceeds [agreed threshold].
