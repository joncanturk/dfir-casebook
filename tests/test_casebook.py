import copy
import csv
import hashlib
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

from casebook.analyze import ROOT, CASES, analyze, findings, linux, render_csv, utc, verify


class CasebookTests(unittest.TestCase):
    def case(self, index=0):
        return ROOT / 'cases' / CASES[index]

    def copy_case(self, folder, index=0):
        target = Path(folder) / CASES[index]
        shutil.copytree(self.case(index), target)
        return target

    def test_golden_outputs_for_both_cases(self):
        for name in CASES:
            with self.subTest(case=name):
                case = ROOT / 'cases' / name
                actual = analyze(case)
                self.assertEqual((json.dumps(actual, indent=2) + '\n').encode(), (case / 'expected/analysis.json').read_bytes())
                self.assertEqual(render_csv(actual).encode(), (case / 'expected/timeline.csv').read_bytes())

    def test_independent_windows_acceptance_facts(self):
        result = analyze(self.case())
        self.assertEqual(result['event_count'], 8)
        self.assertEqual([f['id'] for f in result['findings']], ['W01', 'W02'])
        self.assertEqual(result['findings'][0]['evidence_refs'], ['evidence/security.jsonl:4', 'evidence/security.jsonl:5'])
        self.assertEqual(result['findings'][1]['evidence_refs'], ['evidence/security.jsonl:8'])
        self.assertEqual(result['timeline'][6]['user'], 'svc-support')

    def test_independent_linux_acceptance_facts(self):
        result = analyze(self.case(1))
        self.assertEqual(result['event_count'], 6)
        self.assertEqual(len(result['findings']), 1)
        self.assertEqual(result['findings'][0]['attack'], ['T1053.003'])
        self.assertEqual(result['findings'][0]['evidence_refs'], ['evidence/auth.log:3', 'evidence/crontab.txt:3', 'evidence/snapshot.json:1'])
        self.assertEqual(result['timeline'][0]['timestamp_utc'], '2026-02-11T08:00:00.000000Z')
        self.assertTrue(all(e['timestamp_utc'] == '2026-02-11T08:15:00.000000Z' for e in result['timeline'] if e['kind'] == 'cron_snapshot'))

    def test_temporal_order_preserves_fractional_seconds(self):
        self.assertLess(utc('2026-01-01T00:00:00Z'), utc('2026-01-01T00:00:00.001Z'))
        self.assertEqual(utc('2026-01-01T02:00:00+02:00'), utc('2026-01-01T00:00:00Z'))
        with self.assertRaises(ValueError):
            utc('2026-01-01T00:00:00')

    def test_integrity_rejects_changed_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            case = self.copy_case(folder)
            path = case / 'evidence/security.jsonl'
            path.write_bytes(path.read_bytes() + b'\n')
            with self.assertRaisesRegex(ValueError, 'integrity failure'):
                analyze(case)

    def test_integrity_rejects_missing_and_extra_files(self):
        with tempfile.TemporaryDirectory() as folder:
            case = self.copy_case(folder)
            (case / 'evidence/extra.txt').write_text('unlisted')
            with self.assertRaisesRegex(ValueError, 'inventory'):
                verify(case)
        with tempfile.TemporaryDirectory() as folder:
            case = self.copy_case(folder)
            (case / 'evidence/security.jsonl').unlink()
            with self.assertRaises(OSError):
                verify(case)

    def test_manifest_rejects_traversal_and_duplicate_paths(self):
        for mutation in ('traversal', 'duplicate'):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as folder:
                case = self.copy_case(folder)
                path = case / 'manifest.json'
                manifest = json.loads(path.read_text())
                if mutation == 'traversal':
                    manifest['files'][0]['path'] = 'evidence/../../outside.txt'
                else:
                    manifest['files'].append(manifest['files'][0])
                path.write_text(json.dumps(manifest))
                with self.assertRaises(ValueError):
                    verify(case)

    def test_no_windows_correlation_without_exact_identity_and_order(self):
        events = analyze(self.case())['timeline']
        for field, value in [('member_sid', 'different'), ('host', 'OTHER-HOST'), ('group_sid', 'S-1-5-32-545'), ('timestamp_utc', '2020-01-01T00:00:00.000000Z')]:
            altered = copy.deepcopy(events)
            altered[4][field] = value
            with self.subTest(field=field):
                self.assertNotIn('W01', [f['id'] for f in findings(altered)])
        altered = copy.deepcopy(events)
        altered[3]['account_scope'] = 'unknown'
        self.assertNotIn('W01', [f['id'] for f in findings(altered)])

    def test_cron_does_not_require_or_invent_ssh_causality(self):
        events = analyze(self.case(1))['timeline']
        cron_only = [e for e in events if e['kind'] == 'cron_snapshot']
        result = findings(cron_only)
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['evidence_refs'], ['evidence/crontab.txt:3', 'evidence/snapshot.json:1'])
        self.assertIn('not proven', result[0]['assessment'])
        self.assertEqual(findings(events[:4]), [])

    def test_ordinary_cron_entry_is_not_flagged(self):
        events = analyze(self.case(1))['timeline']
        ordinary = [e for e in events if e['kind'] == 'cron_snapshot' and '/tmp/' not in e['command']]
        self.assertEqual(len(ordinary), 1)
        self.assertEqual(findings(ordinary), [])

    def test_unsupported_auth_line_fails_explicitly(self):
        with tempfile.TemporaryDirectory() as folder:
            case = self.copy_case(folder, 1)
            (case / 'evidence/auth.log').write_text('unsupported log format\n')
            with self.assertRaisesRegex(ValueError, 'unsupported auth log line'):
                linux(case)

    def test_every_evidence_reference_resolves(self):
        for index in range(2):
            case = self.case(index)
            result = analyze(case)
            refs = [e['evidence_ref'] for e in result['timeline']]
            refs += [ref for f in result['findings'] for ref in f['evidence_refs']]
            for ref in refs:
                path, line = ref.rsplit(':', 1)
                self.assertGreater(int(line), 0)
                self.assertLessEqual(int(line), len((case / path).read_text().splitlines()))

    def test_csv_escapes_formula_cells_without_changing_json(self):
        result = analyze(self.case())
        result['timeline'][0]['user'] = '=1+1'
        rows = list(csv.DictReader(io.StringIO(render_csv(result))))
        self.assertEqual(rows[0]['user'], "'=1+1")
        self.assertEqual(result['timeline'][0]['user'], '=1+1')

    def test_cli_writes_outputs_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / 'results'
            command = [sys.executable, '-m', 'casebook.analyze', CASES[0], '--output', str(target)]
            result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads((target / 'analysis.json').read_text())['event_count'], 8)
            repeated = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
            self.assertEqual(repeated.returncode, 2)

    def test_cli_cannot_write_into_case_directory(self):
        result = subprocess.run([sys.executable, '-m', 'casebook.analyze', CASES[0], '--output', str(self.case() / 'blocked-output')], cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 2)
        self.assertFalse((self.case() / 'blocked-output').exists())

    def test_local_documentation_links_exist(self):
        for path in ROOT.rglob('*.md'):
            for link in re.findall(r'\]\(([^)]+)\)', path.read_text(encoding='utf-8')):
                if '://' not in link and not link.startswith('#'):
                    self.assertTrue((path.parent / link.split('#')[0]).exists(), (path, link))


if __name__ == '__main__':
    unittest.main()
