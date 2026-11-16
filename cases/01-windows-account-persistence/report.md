# Case 01: Windows account persistence

**Classification:** synthetic training case. **Disposition:** requires analyst validation.

## Executive assessment

The supplied records show the creation of local account `svc-support`, its addition to built-in Administrators, a later logon by the same account SID, and a Security log clear. An exact SID connects the created account and group member. These observations justify review for unauthorized persistence; they do not prove compromise or identify the person responsible.

## Scope and evidence

The collection represents standalone workstation `LAB-WIN01` on 2026-02-10. Evidence consists of eight authored normalized Security events and collection notes. No original EVTX, image, memory, EDR data or approval records are available. Byte lengths and SHA-256 values are recorded in [manifest.json](manifest.json).

References below are one-based line numbers in [security.jsonl](evidence/security.jsonl).

| UTC | Evidence | Observation |
|---|---|---|
| 09:00:00–09:00:30 | Lines 1–2, records 1001–1002 | Two failed logons for operator from 192.0.2.25 |
| 09:02:00 | Line 3, record 1003 | Successful operator logon from the same address |
| 09:05:00 | Line 4, record 1004 | Local svc-support account created with SID ending in 1105 |
| 09:06:00 | Line 5, record 1005 | Exact same SID added to S-1-5-32-544, built-in Administrators |
| 09:07:00 | Line 6, record 1006 | Different SID added to ordinary Users; contrast event |
| 09:08:00 | Line 7, record 1007 | Successful svc-support logon with the created SID |
| 09:10:00 | Line 8, record 1008 | Security log clear attributed to the operator account |

## Findings

**W01 — New local account added to Administrators.** Lines 4 and 5 share the host and account SID. This supports the entity relationship independently of display names. Line 7 supports subsequent account use but is not needed for W01. Account scope comes from the fictional standalone-host inventory, not an assumed native `account_scope` field.

**W02 — Security log clear.** Line 8 records the action. Its position after the other events is consistent with a concealment hypothesis but does not establish intent. The dataset is not evidence that earlier logs were wholly destroyed; forwarded copies may exist.

Two failed logons followed by success do not establish password guessing, stolen credentials or initial access. The source address is an investigation pivot, not a malicious indicator by itself.

## Competing explanations

1. An unauthorized operator session created a privileged persistence account and cleared logs.
2. An authorized support procedure created a local account; the log clear was documented maintenance.
3. More than one person used the same operator account. Account names alone do not resolve human identity.

No supplied change ticket or session/process evidence eliminates these alternatives.

## ATT&CK mapping

- [T1136.001 — Local Account](https://attack.mitre.org/techniques/T1136/001/): account creation visibility, not proof of adversary control.
- [T1098.007 — Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/): built-in Administrators membership change.
- [T1685.005 — Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/): clear event; no claim of a complete behavioral-chain analytic.

## Next evidence and response

Preserve original and forwarded logs; obtain logon IDs, authentication context, account-owner confirmation, group history, process trees and change records. Compare host and collector clocks. Validate whether the new account is authorized before applying the organization's containment process. If unauthorized activity is confirmed, preserve evidence before revoking sessions or removing persistence.

## Reproduce

From the repository root, run `python -m casebook.analyze 01-windows-account-persistence`. Compare with [analysis.json](expected/analysis.json) and [timeline.csv](expected/timeline.csv). Expected: eight events and W01/W02. Automated findings support this report; the alternative explanations and response recommendations are analyst reasoning.
