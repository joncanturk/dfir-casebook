# DFIR Casebook

[![Case validation](https://github.com/joncanturk/dfir-casebook/actions/workflows/tests.yml/badge.svg)](https://github.com/joncanturk/dfir-casebook/actions/workflows/tests.yml)

Two synthetic digital-forensics investigations with verifiable evidence, reproducible UTC timelines, and reports that distinguish observations from hypotheses.

**MITRE ATT&CK-aligned · Python standard library · Offline**

This portfolio demonstrates evidence handling and analytical reasoning. All identities, addresses, events and collection records are fictional. These are authored evidence fixtures, not records from a real intrusion or a claim of hands-on forensic acquisition.

## Cases

| Case | Investigation question | Artifacts | Report |
|---|---|---|---|
| 01 — Windows account persistence | Was a newly created local account subsequently added to Administrators? | Normalized Security events, collection notes, hash manifest | [Investigation](cases/01-windows-account-persistence/report.md) |
| 02 — Linux SSH and cron | What can SSH history and a user crontab snapshot establish about possible persistence? | Synthetic SSH log, cron snapshot, collection metadata, hash manifest | [Investigation](cases/02-linux-ssh-cron/report.md) |

The Windows case links account creation and privilege assignment using an exact SID and host. The Linux case deliberately demonstrates an evidence gap: an earlier SSH login does not prove that the session installed a cron job.

## Reproduce in minutes

Python 3.11 or newer; no dependencies, agents or external services required. Run from the repository root:

```sh
python -m unittest discover -s tests -v
python -m casebook.analyze 01-windows-account-persistence
python -m casebook.analyze 02-linux-ssh-cron
python -m casebook.analyze 01-windows-account-persistence --output results/windows
python -m casebook.analyze 02-linux-ssh-cron --output results/linux
```

Use `python3` if needed. Output directories must be new; use another name for a subsequent run. The tool refuses to overwrite existing directories or write inside `cases/`.

Expected results:

- **Windows:** 8 timeline events; 2 review findings (linked account/group change and log clear).
- **Linux:** 6 timeline entries; 1 review finding (a cron entry referencing `/tmp`). Two entries represent snapshot observations, not cron creation or execution events.
- Each case includes committed `expected/analysis.json` and `expected/timeline.csv` for byte-for-byte reproduction tests.

## Investigation workflow

```text
Verify evidence inventory and SHA-256
        -> parse supported fixtures
        -> normalize explicit offsets to UTC
        -> preserve file/line provenance
        -> correlate exact identities where supported
        -> review findings, alternatives and evidence gaps
```

Every run verifies the evidence manifest before parsing. It fails on tampering, missing/extra files, duplicate manifest paths or unsafe paths. A hash proves consistency with the supplied manifest, not authenticity or a legal chain of custody.

## MITRE ATT&CK

The behavioral framework is [MITRE ATT&CK Enterprise](https://attack.mitre.org/). See [mapping rationale](docs/attack-mapping.md) for T1136.001, T1098.007, T1685.005, T1053.003 and the conditional T1078.003 hypothesis. Mappings do not establish malicious intent, actor attribution or complete technique coverage.

## Contents

```text
casebook/               Integrity checks, parsers, correlation and CLI
cases/<case>/evidence/  Immutable synthetic source files
cases/<case>/manifest.json
cases/<case>/expected/ Reproducible JSON and CSV outputs
cases/<case>/report.md Analyst assessment and evidence references
docs/                  Methodology, ATT&CK rationale and validation
tests/                 Positive, negative, integrity and CLI checks
```

## Scope and limitations

The Windows parser consumes the documented normalized JSONL format, not EVTX. The Linux parser accepts only the fixture's timestamped SSH line format and simple five-field user-crontab entries. Unsupported inputs fail rather than silently disappearing. The project does not acquire disks or memory, install cron jobs, execute commands from evidence, contact hosts, or perform containment.

No process-level causality, payload behavior, credential theft, data exfiltration or legal evidentiary status is claimed. The files are small in-memory teaching datasets. Real cases require trusted acquisition, broader artifact support, clock assessment, access controls and independent review.

## Documentation

- [Evidence handling and methodology](docs/methodology.md)
- [Validation and analytical acceptance criteria](docs/validation.md)
- [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [MIT license](LICENSE)

Related project: [Detection Engineering Lab](https://github.com/joncanturk/detection-engineering-lab).
