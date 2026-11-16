# Validation

## Acceptance criteria

The offline suite contains 16 test methods. The two principal acceptance checks assert independently specified evidence relationships, event counts and normalized times; golden-output tests additionally detect accidental format or narrative drift.

| Area | Expected outcome |
|---|---|
| Windows reconstruction | Eight events; W01 references security.jsonl lines 4 and 5; W02 references line 8 |
| Linux reconstruction | Six timeline entries; one L01 finding; cron observations are timestamped at collection |
| Negative correlations | Different SID, host, ordinary group, reversed chronology and unknown scope cannot produce W01 |
| Linux alternatives | SSH alone is not a finding; routine cron entry is not flagged; cron review can exist without an SSH session |
| Time | Offsets normalize to UTC; fractional seconds remain ordered; naive timestamps fail |
| Integrity | Changed bytes, absent or extra evidence, traversal and duplicate manifest paths fail |
| Provenance | Every emitted evidence reference resolves to a source line |
| Safe output | Spreadsheet formula-leading cells escaped in CSV; JSON preserved; existing output and case directories protected |
| Parser scope | Unsupported SSH lines fail explicitly |
| Reproduction | JSON and CSV match the committed expected files byte-for-byte |
| Documentation | Relative Markdown links resolve |

## Run

```sh
python -m unittest discover -s tests -v
```

The GitHub Actions matrix runs Python 3.11 and 3.13 on Windows and Ubuntu, followed by both CLI export commands. Inspect [workflow runs](https://github.com/joncanturk/dfir-casebook/actions) for current remote results.

These tests validate this small synthetic corpus and supported parser contract. They do not measure production detection accuracy, forensic-tool certification, exhaustive parser security or performance on real incident volumes. Expected reports are analyst-authored; automated facts do not establish attribution or malicious intent.
