# Case 02: Linux SSH access and a cron snapshot

**Classification:** synthetic training case. **Disposition:** suspicious configuration requiring validation; session causality unproven.

## Executive assessment

A successful SSH authentication for local account `deploy` precedes the collection of its user crontab. One cron entry references a shell script in `/tmp`, warranting investigation. The collection does not contain that script, its metadata, execution records or a cron-install event. It therefore cannot establish payload behavior, who created the job, when it was created or whether it executed.

## Evidence and time normalization

- [auth.log](evidence/auth.log): four synthetic SSH entries with explicit `+02:00` offsets.
- [crontab.txt](evidence/crontab.txt): authored user-crontab snapshot with a routine-looking backup entry and a temporary-directory script reference.
- [snapshot.json](evidence/snapshot.json): fictional owner, host and collection time.
- [collection-notes.txt](evidence/collection-notes.txt): provenance and missing artifacts.
- [manifest.json](manifest.json): byte sizes and SHA-256 inventory.

| UTC, 2026-02-11 | Evidence | Observation |
|---|---|---|
| 08:00:00 | auth.log:1 | Failed password authentication for deploy from 198.51.100.23 |
| 08:01:00 | auth.log:2 | Another failed password authentication |
| 08:03:00 | auth.log:3 | Public-key authentication accepted for deploy from the same address |
| 08:04:00 | auth.log:4 | Public-key authentication for a different account, backup |
| 08:15:00 | crontab.txt:2; snapshot.json:1 | Backup command observed in deploy's collected crontab |
| 08:15:00 | crontab.txt:3; snapshot.json:1 | `/bin/sh /tmp/.cache-maint.sh` observed with a five-minute schedule |

The last two timestamps are **collection times**, not creation, modification or execution times. The parser converts explicit offsets to UTC; no clock-skew correction is possible from this collection.

## Finding L01

The temporary-directory script reference merits review because its purpose, owner and contents are unknown. The analyzer includes the most recent earlier same-user/host SSH success as context. This is not a session-to-file-write correlation: neither a session ID nor a creation event links the login to the cron entry.

The failed password attempts and later successful public-key login use different authentication methods. They do not establish that a password was guessed. The ordinary-looking backup job is not verified as authorized merely because of its filename.

## Alternative explanations and gaps

- A legitimate administrator installed a temporary maintenance job before the observed session.
- An unauthorized person used a valid key and established persistence.
- The entry predates all supplied log records, or never ran because the script was absent.

All remain possible. No network capture supports exfiltration, and no file content supports a malware classification. Documentation-space IP addresses are fictional pivots, not blocklist recommendations.

## ATT&CK mapping

[T1053.003 — Cron](https://attack.mitre.org/techniques/T1053/003/) describes the scheduling mechanism. This case provides configuration visibility only, not proof of malicious persistence or execution. [T1078.003 — Local Accounts](https://attack.mitre.org/techniques/T1078/003/) is a conditional hypothesis if misuse of the fictional local account is established; a successful login alone is not enough. It is deliberately not emitted as an automated finding.

## Next evidence and response

Acquire the referenced script without running it, preserve file metadata and hashes, and obtain auditd/process telemetry, cron execution history, SSH key fingerprints, session records and change tickets. Check owner authorization and clock offsets. If unauthorized access is confirmed, follow the organization's process for session revocation, key rotation and persistence removal after preservation.

## Reproduce

Run `python -m casebook.analyze 02-linux-ssh-cron`. Compare [analysis.json](expected/analysis.json) and [timeline.csv](expected/timeline.csv). Expected: six timeline entries and one L01 finding. The parser never installs cron content or executes the referenced command.
