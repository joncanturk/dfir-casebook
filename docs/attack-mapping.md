# MITRE ATT&CK mapping rationale

Framework: [MITRE ATT&CK Enterprise](https://attack.mitre.org/). Canonical pages reviewed on **2026-11-16**. This is an independent educational project, not a MITRE-endorsed assessment.

| Technique | Case and evidence | Supported observation | Limit |
|---|---|---|---|
| [T1136.001: Local Account](https://attack.mitre.org/techniques/T1136/001/) | Windows, security.jsonl:4 | A local account was created | Intent and authorization unknown |
| [T1098.007: Additional Local or Domain Groups](https://attack.mitre.org/techniques/T1098/007/) | Windows, security.jsonl:5 | Created SID added to Administrators | Does not establish compromise or human identity |
| [T1685.005: Clear Windows Event Logs](https://attack.mitre.org/techniques/T1685/005/) | Windows, security.jsonl:8 | Security log clear | Does not establish concealment intent or complete data loss |
| [T1053.003: Cron](https://attack.mitre.org/techniques/T1053/003/) | Linux, crontab.txt:3 and snapshot.json:1 | Scheduled command present at collection | Creation and execution not observed |
| [T1078.003: Local Accounts](https://attack.mitre.org/techniques/T1078/003/) | Linux, auth.log:3 and collection notes | Valid local-account authentication | Conditional misuse hypothesis only; not emitted by the analyzer |

These mappings provide an investigation vocabulary, not completeness scores. Local account creation, authentication, group management and cron scheduling are also normal administrative activities. The analysis deliberately avoids mapping failed-password attempts to brute force or claiming exfiltration without sufficient evidence.

MITRE technique revisions can change identifiers and names. Review canonical pages when revising reports and golden outputs. The current log-clearing mapping is T1685.005; do not substitute historical IDs without explaining the version context.
