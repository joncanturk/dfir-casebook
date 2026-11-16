"""Verify evidence, normalize timestamps, and produce reproducible case outputs."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path, PurePosixPath
import re
import sys

ROOT = Path(__file__).resolve().parents[1]
CASES = ('01-windows-account-persistence', '02-linux-ssh-cron')


def utc(value):
    stamp = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if stamp.tzinfo is None:
        raise ValueError('timestamp requires an explicit UTC offset')
    return stamp.astimezone(timezone.utc).isoformat(timespec='microseconds').replace('+00:00', 'Z')


def verify(case):
    """Check exact evidence inventory, safe paths, byte sizes and SHA-256 hashes."""
    case = Path(case).resolve()
    manifest = json.loads((case / 'manifest.json').read_text(encoding='utf-8'))
    expected = set()
    for item in manifest['files']:
        name = item['path']
        parts = PurePosixPath(name)
        if '\\' in name or parts.is_absolute() or '..' in parts.parts or not name.startswith('evidence/'):
            raise ValueError(f'unsafe evidence path: {name}')
        if name in expected:
            raise ValueError(f'duplicate manifest path: {name}')
        expected.add(name)
        path = case / name
        if path.is_symlink() or not path.resolve().is_relative_to(case / 'evidence'):
            raise ValueError(f'evidence path escapes collection: {name}')
        payload = path.read_bytes()
        if len(payload) != item['bytes'] or hashlib.sha256(payload).hexdigest() != item['sha256']:
            raise ValueError(f'evidence integrity failure: {name}')
    actual = {p.relative_to(case).as_posix() for p in (case / 'evidence').rglob('*') if p.is_file()}
    if not expected or actual != expected:
        raise ValueError('evidence inventory differs from manifest')
    return manifest


def row(time, host, kind, user, ref, detail, **fields):
    return {'timestamp_utc': utc(time), 'host': host, 'kind': kind,
            'user': user, 'evidence_ref': ref, 'detail': detail, **fields}


def windows(case):
    result = []
    seen = set()
    names = {4625: 'logon_failed', 4624: 'logon_success', 4720: 'account_created',
             4732: 'group_member_added', 1102: 'security_log_cleared'}
    path = case / 'evidence/security.jsonl'
    for number, line in enumerate(path.read_text(encoding='utf-8').splitlines(), 1):
        e = json.loads(line)
        identity = (e['host'], e['channel'], e['record_id'])
        if identity in seen:
            raise ValueError('duplicate Windows event identity')
        seen.add(identity)
        eid = e['event_id']
        provider = 'Microsoft-Windows-Eventlog' if eid == 1102 else 'Microsoft-Windows-Security-Auditing'
        if type(eid) is not int or eid not in names or e['channel'] != 'Security' or e['provider'] != provider:
            raise ValueError('unsupported Windows event or provider')
        result.append(row(e['timestamp'], e['host'], names[eid], e.get('target_user', e.get('actor', 'unknown')),
                          f'evidence/security.jsonl:{number}', f"Windows event {eid}; record {e['record_id']}",
                          target_sid=e.get('target_sid', ''), member_sid=e.get('member_sid', ''),
                          group_sid=e.get('group_sid', ''), account_scope=e.get('account_scope', 'unknown'),
                          actor=e.get('actor', ''), source_ip=e.get('source_ip', '')))
    return result


SSH = re.compile(r'(?P<time>\S+) (?P<host>\S+) sshd\[(?P<pid>\d+)\]: (?P<outcome>Accepted|Failed) (?P<method>password|publickey) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+) ssh2(?:.*)$')


def linux(case):
    result = []
    for number, line in enumerate((case / 'evidence/auth.log').read_text(encoding='utf-8').splitlines(), 1):
        match = SSH.fullmatch(line)
        if match is None:
            raise ValueError(f'unsupported auth log line {number}; parser is fixture-specific')
        e = match.groupdict()
        result.append(row(e['time'], e['host'], 'ssh_success' if e['outcome'] == 'Accepted' else 'ssh_failed',
                          e['user'], f'evidence/auth.log:{number}',
                          f"{e['outcome']} {e['method']} from {e['ip']}; sshd PID {e['pid']}", source_ip=e['ip']))
    metadata = json.loads((case / 'evidence/snapshot.json').read_text(encoding='utf-8'))
    for number, line in enumerate((case / 'evidence/crontab.txt').read_text(encoding='utf-8').splitlines(), 1):
        if not line.strip() or line.lstrip().startswith('#'):
            continue
        parts = line.split(None, 5)
        if len(parts) != 6:
            raise ValueError(f'unsupported crontab line {number}')
        result.append(row(metadata['captured_at'], metadata['host'], 'cron_snapshot', metadata['owner'],
                          f'evidence/crontab.txt:{number}', 'Observed at collection; schedule=' + ' '.join(parts[:5]) + '; command=' + parts[5],
                          command=parts[5], metadata_ref='evidence/snapshot.json:1'))
    return result


def findings(events):
    """Conservative correlations; no automatic malicious/benign verdict."""
    output = []
    def add(fid, title, technique, refs, conclusion):
        output.append({'id': fid, 'title': title, 'attack': technique, 'evidence_refs': refs,
                       'assessment': conclusion, 'disposition': 'requires analyst validation'})
    for created in (e for e in events if e['kind'] == 'account_created' and e.get('account_scope') == 'local' and e.get('target_sid')):
        added = [e for e in events if e['kind'] == 'group_member_added' and e['host'] == created['host']
                 and e.get('member_sid') == created['target_sid'] and e.get('group_sid') == 'S-1-5-32-544'
                 and e['timestamp_utc'] >= created['timestamp_utc']]
        for member in added:
            add('W01', 'New local account added to Administrators', ['T1136.001', 'T1098.007'],
                [created['evidence_ref'], member['evidence_ref']],
                'Exact SID and host link the created account to a later privileged-group addition. Authorization and human identity remain unproven.')
    for event in events:
        if event['kind'] == 'security_log_cleared':
            add('W02', 'Security log clear observed', ['T1685.005'], [event['evidence_ref']],
                'A log clear is recorded. Intent and the full extent of unavailable earlier records cannot be determined from this event alone.')
        if event['kind'] == 'cron_snapshot' and '/tmp/' in event.get('command', ''):
            sessions = [e for e in events if e['kind'] == 'ssh_success' and e['host'] == event['host'] and e['user'] == event['user'] and e['timestamp_utc'] <= event['timestamp_utc']]
            refs = [event['evidence_ref'], event['metadata_ref']]
            if sessions:
                refs.insert(0, sessions[-1]['evidence_ref'])
            add('L01', 'Cron entry references a temporary-directory script', ['T1053.003'], refs,
                'The collected user crontab references /tmp. A prior same-user SSH event, when referenced, provides context only: collection time is not creation time and the session is not proven to have installed the entry.')
    return output


def analyze(case):
    case = Path(case).resolve()
    manifest = verify(case)
    if manifest['parser'] == 'windows-normalized-jsonl':
        events = windows(case)
    elif manifest['parser'] == 'linux-auth-and-cron':
        events = linux(case)
    else:
        raise ValueError('unsupported parser')
    events.sort(key=lambda e: (e['timestamp_utc'], e['evidence_ref']))
    return {'case_id': manifest['case_id'], 'synthetic': True, 'integrity': 'verified',
            'event_count': len(events), 'timeline': events, 'findings': findings(events)}


def render_csv(result):
    stream = io.StringIO(newline='')
    columns = ['timestamp_utc', 'host', 'kind', 'user', 'evidence_ref', 'detail']
    writer = csv.DictWriter(stream, fieldnames=columns, extrasaction='ignore', lineterminator='\n')
    writer.writeheader()
    for event in result['timeline']:
        # Prevent formula evaluation when an analyst opens CSV in a spreadsheet.
        writer.writerow({k: "'" + v if isinstance(v, str) and v.startswith(('=', '+', '-', '@', '\t', '\r')) else v for k, v in event.items()})
    return stream.getvalue()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('case', choices=CASES)
    parser.add_argument('--output', type=Path, help='new directory for analysis.json and timeline.csv; must not already exist')
    args = parser.parse_args()
    try:
        result = analyze(ROOT / 'cases' / args.case)
        text = json.dumps(result, indent=2) + '\n'
        if args.output:
            target = args.output.resolve()
            if target.is_relative_to(ROOT / 'cases'):
                raise ValueError('output must be outside case evidence and reports')
            target.mkdir(parents=True, exist_ok=False)
            (target / 'analysis.json').write_bytes(text.encode('utf-8'))
            (target / 'timeline.csv').write_bytes(render_csv(result).encode('utf-8'))
        else:
            print(text, end='')
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
