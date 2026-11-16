# Evidence handling and analytical method

## Provenance and integrity

All artifacts were authored for this repository. Collection IDs and timestamps are fictional scenario metadata. `manifest.json` inventories only `evidence/`; generated outputs and reports are derivatives. SHA-256 and exact byte length are verified before parsing. `.gitattributes` disables line-ending conversion for evidence and expected outputs so a Windows checkout preserves those bytes.

The manifest itself is a repository artifact, not a signed independent trust anchor. An attacker able to replace both evidence and manifest could evade this check. Git history supports change review but is not a legal chain of custody. For a real case, record acquisition method, operator, source system, tool/version, timezone, transfers, access and trusted hashes in the organization's evidence system.

## Supported inputs

Windows fixtures are JSONL objects with `timestamp`, `host`, `channel`, `provider`, `record_id` and integer `event_id`. Supported IDs: 4625, 4624, 4720, 4732 and 1102. `target_sid`, `member_sid`, `group_sid`, `actor`, `target_user`, `source_ip` and enriched `account_scope` support interpretation. This is a project-defined normalization contract, not a native EVTX schema. It does not infer missing SIDs or scope.

Linux fixtures use a narrow SSH log grammar with an ISO timestamp, host, sshd PID, Accepted/Failed outcome, password/publickey method, user, source address and port. Only five-field user-crontab schedules are represented; macros, environment assignments, system-crontab user columns and distribution-specific formats are not supported. Schedule syntax is retained as text, not executed or fully validated. The engine fails on unrecognized lines.

## Time and provenance

Explicit offsets are mandatory. Output uses UTC with fixed microsecond precision, preserving fractional ordering. No host clock corrections are invented. Each row retains one-based source file/line references; cron rows additionally reference collection metadata. Source logs and snapshots can have different evidentiary meaning even when displayed in one timeline.

## Correlation boundaries

W01 requires a nonempty created SID, local scope, same host, a subsequent addition of that SID to built-in Administrators. Display-name coincidence, different hosts, ordinary groups and reversed chronology do not satisfy it. This is retrospective case analysis, not a configurable streaming detection threshold. Multiple qualifying additions generate separate findings sharing the W01 finding category.

W02 records a Security log clear without claiming the actor's intent. L01 highlights a cron command containing `/tmp/`; it is a simple triage heuristic and can produce false positives. Its optional SSH reference is context, not proof of installation. No finding proves malicious behavior.

## Output and execution safety

`analysis.json` preserves normalized details and reference-based findings; `timeline.csv` is a flattened analyst view. Spreadsheet formula-leading cells are prefixed with an apostrophe in CSV only; the JSON preserves the original content. No evidence strings are executed, no network calls occur and no response actions run. Output directories must be new and outside `cases/`. Exit 0 indicates successful analysis, not a benign verdict; exit 2 indicates an error.

## Review checklist

1. Verify integrity before analysis and preserve original bytes.
2. Separate event time from collection time and document unknown clock skew.
3. Follow exact entity references before asserting relationships.
4. State observations, inference, competing explanations and missing evidence separately.
5. Map only supported behavior to ATT&CK; do not infer technique coverage from a label.
6. Request corroborating artifacts before containment or actor attribution.
