"""Synthetic public-format logs through the real projection/normalizer; no live I/O."""
from contextlib import closing, redirect_stdout
from copy import deepcopy
from datetime import timedelta
import io
import json
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from test_intake_detection import raw, normalized, client_for
from test_cloudtrail import EVENTS, projected
from cloud_soc.processing.contract import normalize, NORMALIZED
from cloud_soc.detection.behavior import detect_behavior
from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.worker import approved_rules, run_once
from cloud_soc.detection.rule_loader import validate_rule
from cloud_soc.detection.incremental import run_incremental, utc
from cloud_soc.detection.telemetry import evaluate
from cloud_soc.detection.__main__ import main
from cloud_soc.main import make_alert_id, build_security_alert
from cloud_soc.portal.operations import Operations

RULES = {r['id']: r for r in approved_rules(include_attacks=True) if r['id'].startswith('ATTACK-')}
BASE = utc('2026-10-01T00:00:00Z')
APIS = [('ec2.amazonaws.com', 'DescribeInstances'), ('iam.amazonaws.com', 'ListUsers'),
        ('s3.amazonaws.com', 'ListBuckets'), ('lambda.amazonaws.com', 'ListFunctions')]


def ssh(number, *, seconds=None, outcome='failure', org='team-a', host='host-a', user='fixture', ip='192.0.2.10'):
    hit = raw(number, seconds=seconds, organization=org)
    stamp = (BASE + timedelta(seconds=number if seconds is None else seconds)).isoformat()
    hit['_source']['@timestamp'] = stamp
    hit['_source']['event']['ingested'] = stamp
    hit['_source']['host'] = {'id': host}
    hit['_source']['message'] = utc(hit['_source']['@timestamp']).strftime('%b %d %H:%M:%S') + (
        f' host sshd[100]: Failed password for {user} from {ip} port 12345 ssh2' if outcome == 'failure' else
        f' host sshd[100]: Accepted password for {user} from {ip} port 12345 ssh2')
    return as_event(normalized(hit))


def sudo(number=50, *, seconds=60, org='team-a', host='host-a', user='fixture', target='root'):
    hit = raw(number, seconds=seconds, organization=org)
    stamp = (BASE + timedelta(seconds=seconds)).isoformat()
    hit['_source']['@timestamp'] = stamp
    hit['_source']['event']['ingested'] = stamp
    hit['_source']['host'] = {'id': host}
    hit['_source']['message'] = utc(hit['_source']['@timestamp']).strftime('%b %d %H:%M:%S') + (
        f' host sudo[200]: pam_unix(sudo:session): session opened for user {target}(uid={0 if target == "root" else 1000}) by {user}(uid=1000)')
    return as_event(normalized(hit))


def as_event(hit):
    event = deepcopy(hit['_source'])
    event['_cloud_soc_meta'] = {'index': hit['_index'], 'document_id': hit['_id']}
    return event


def aws(number, *, seconds=None, action=None, provider=None, request=None, failed=False):
    event = deepcopy(EVENTS[1])
    chosen = APIS[number % len(APIS)]
    event.update(eventTime=(BASE + timedelta(seconds=number if seconds is None else seconds)).isoformat(),
                 eventID=f'11111111-2222-3333-4444-{number:012d}', eventName=action or chosen[1],
                 eventSource=provider or chosen[0], requestParameters=request or {})
    event.pop('errorCode', None)
    if failed:
        event['errorCode'] = 'AccessDenied'
    index, identifier, source = projected(event)
    source['event']['ingested'] = event['eventTime']
    key, record, row = normalize({'_index': index, '_id': identifier, '_source': source}, event['eventTime'])
    assert record['status'] == 'normalized', record
    row['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
    return row


def iam(number=100, *, seconds=0, **kwargs):
    return aws(number, seconds=seconds, action='AttachRolePolicy', provider='iam.amazonaws.com',
               request={'policyArn': 'arn:aws:iam::aws:policy/AdministratorAccess', 'roleName': 'target'}, **kwargs)


def audit(number=101, *, seconds=60, **kwargs):
    return aws(number, seconds=seconds, action='StopLogging', provider='cloudtrail.amazonaws.com',
               request={'name': 'fixture-trail'}, **kwargs)


def attack_one(failures=5, sudo_seconds=60):
    return [ssh(i) for i in range(failures)] + [ssh(40, seconds=10, outcome='success'), sudo(seconds=sudo_seconds)]


class AttackTests(unittest.TestCase):
    def detect(self, rule_id, rows, rule=None):
        return detect_events(rows, [rule or RULES[rule_id]])

    def test_profile_is_explicit_and_existing_rules_unchanged(self):
        self.assertEqual([r['id'] for r in approved_rules()], ['AUTH-001'])
        self.assertEqual(len(approved_rules(include_cloud=True, include_sequence=True)), 6)
        self.assertEqual(len(approved_rules(include_attacks=True)), 4)
        self.assertEqual(len(approved_rules(include_attacks=True, include_cloud=True, include_sequence=True)), 9)
        stream = io.StringIO()
        with redirect_stdout(stream):
            self.assertEqual(main(['--include-attacks']), 0)
        self.assertIn('offline; no writes', stream.getvalue())
        self.assertNotIn('ATTACK-04', stream.getvalue())

    def test_ssh_threshold_and_stage_evidence(self):
        for failures, expected in [(4, 0), (5, 1), (6, 1)]:
            with self.subTest(failures=failures):
                result = self.detect('ATTACK-01', attack_one(failures))
                self.assertEqual(len(result), expected)
                if result:
                    self.assertEqual(result[0]['event_count'], 7)
                    self.assertEqual([s['count'] for s in result[0]['assessment']['stages']], [5, 1, 1])
                    self.assertTrue(all(e['complete'] for e in result[0]['evidence']))
                    self.assertNotIn('PRIVATE_CANARY', json.dumps(result))
                    self.assertIn('not_same_session', result[0]['assessment']['limitations'][0])

    def test_sudo_alone_or_no_success_or_non_root_does_not_match(self):
        for rows in ([sudo()], [ssh(i) for i in range(5)] + [sudo()],
                     attack_one()[:-1] + [sudo(target='fixture')],
                     [ssh(1, outcome='success'), sudo()],
                     attack_one()[:-1] + [sudo(seconds=5)]):
            self.assertEqual(self.detect('ATTACK-01', rows), [])

    def test_ssh_source_scope_and_all_group_boundaries(self):
        prior = attack_one()[:-1]
        for kwargs in ({'org': 'other'}, {'host': 'other'}, {'user': 'other'}):
            self.assertEqual(self.detect('ATTACK-01', prior + [sudo(**kwargs)]), [])
        self.assertEqual(self.detect('ATTACK-01', [ssh(i) for i in range(5)] +
                                    [ssh(40, seconds=10, outcome='success', ip='192.0.2.20'), sudo()]), [])

    def test_ssh_window_inclusive_and_strict_order(self):
        for delay, expected in [(600, 1), (601, 0)]:
            self.assertEqual(len(self.detect('ATTACK-01', attack_one(sudo_seconds=10 + delay))), expected)
        for delay, expected in [(300, 1), (301, 0), (0, 0)]:
            rows = [ssh(i, seconds=0) for i in range(5)] + [ssh(40, seconds=delay, outcome='success'), sudo(seconds=delay + 1)]
            self.assertEqual(len(self.detect('ATTACK-01', rows)), expected)

    def test_success_resets_failure_cohort_and_latest_login_matters(self):
        rows = attack_one()[:-1] + [ssh(41, seconds=20, outcome='success'), sudo()]
        self.assertEqual(self.detect('ATTACK-01', rows), [])

    def test_api_count_and_distinct_boundaries(self):
        for count, expected in [(19, 0), (20, 1), (21, 1)]:
            self.assertEqual(len(self.detect('ATTACK-02', [aws(i) for i in range(count)])), expected)
        for types, expected in [(3, 0), (4, 1)]:
            rows = [aws(i, provider=APIS[i % types][0], action=APIS[i % types][1]) for i in range(20)]
            result = self.detect('ATTACK-02', rows)
            self.assertEqual(len(result), expected)
            if result:
                self.assertEqual(result[0]['assessment']['distinct_count'], 4)

    def test_api_allowlist_uses_provider_action_pairs_not_prefixes(self):
        for provider, action in [('iam.amazonaws.com', 'DescribeInstances'), ('ec2.amazonaws.com', 'ListUsers'),
                                 ('ec2.amazonaws.com', 'GetAnything'), ('ec2.amazonaws.com', 'DescribeMadeUp')]:
            self.assertEqual(evaluate(aws(1, provider=provider, action=action), RULES['ATTACK-02'])[0], 'not_matched')

    def test_api_window_boundary(self):
        for end, expected in [(300, 1), (301, 0)]:
            rows = [aws(i, seconds=0) for i in range(19)] + [aws(23, seconds=end)]
            self.assertEqual(len(self.detect('ATTACK-02', rows)), expected)

    def test_aws_scope_separation(self):
        for rule_id, rows in [('ATTACK-02', [aws(i) for i in range(20)]), ('ATTACK-03', [iam(), audit()])]:
            for group, key, value in [('organization', 'id', 'other'), ('user', 'id', 'other'),
                                      ('cloud', 'account', {'id': '999999999999'})]:
                changed = deepcopy(rows)
                for row in changed[len(changed)//2:]:
                    row[group][key] = value
                self.assertEqual(self.detect(rule_id, changed), [])
            changed = deepcopy(rows)
            for row in changed[len(changed)//2:]:
                row['cloud_soc']['detail']['fields']['identity_arn'] = 'arn:aws:iam::123456789012:user/other'
            self.assertEqual(self.detect(rule_id, changed), [])

    def test_unknown_actor_is_not_inferred_from_name_or_ip(self):
        for missing in ['user.id', 'cloud.account.id', 'cloud_soc.detail.fields.identity_arn']:
            row = aws(1)
            target = row
            parts = missing.split('.')
            for part in parts[:-1]:
                target = target[part]
            del target[parts[-1]]
            self.assertEqual(evaluate(row, RULES['ATTACK-02'])[0], 'unknown')
            self.assertEqual(self.detect('ATTACK-02', [row] * 20), [])

    def test_malformed_identity_fields_fail_closed(self):
        for value in [None, '', ' ', [], {}, True, '[REDACTED]']:
            rows = [aws(i) for i in range(20)]
            for row in rows:
                row['user']['id'] = value
            self.assertEqual(self.detect('ATTACK-02', rows), [])

    def test_duplicates_and_different_references_do_not_inflate_calls(self):
        rows = [aws(i) for i in range(19)]
        duplicate = deepcopy(rows[-1])
        duplicate['_cloud_soc_meta']['document_id'] = 'duplicate-normalized'
        duplicate['cloud_soc']['provenance']['raw']['id'] = 'duplicate-raw'
        duplicate['cloud_soc']['normalized_at'] = '2026-10-01T00:01:00Z'
        self.assertEqual(self.detect('ATTACK-02', rows + [duplicate] * 100), [])
        self.assertEqual(len(self.detect('ATTACK-02', rows + [aws(19)] + rows)), 1)

    def test_denied_calls_are_attempts_not_success(self):
        result = self.detect('ATTACK-02', [aws(i, failed=True) for i in range(20)])
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0]['assessment']['attack_success'], 'not_established')

    def test_iam_audit_order_and_time_window(self):
        for delay, expected in [(1, 1), (900, 1), (901, 0), (0, 0), (-1, 0)]:
            rows = [iam(), audit(seconds=delay)]
            self.assertEqual(len(self.detect('ATTACK-03', rows)), expected)
        self.assertEqual(self.detect('ATTACK-03', [iam(failed=True), audit()]), [])
        self.assertEqual(self.detect('ATTACK-03', [iam(), audit(failed=True)]), [])

    def test_existing_singles_remain_separate_for_legitimate_risky_work(self):
        rows = [iam(), audit()]
        result = detect_events(rows, approved_rules(include_attacks=True, include_cloud=True))
        self.assertEqual({r['rule_id'] for r in result}, {'AWS-IAM-001', 'AWS-AUDIT-001', 'ATTACK-03'})

    def test_explicit_scoped_exception_not_falsepositive_description(self):
        rows = [aws(i) for i in range(20)]
        rule = deepcopy(RULES['ATTACK-02'])
        rule['falsepositives'] = ['Everything is normal']
        self.assertEqual(len(self.detect('ATTACK-02', rows, rule)), 1)
        rule['exclusions'] = [{'conditions': [{'field': f, 'operator': 'equals',
            'value': self.value(rows[0], f)} for f in rule['group_by']],
            'time_range': {'start': BASE.isoformat(), 'end': (BASE + timedelta(seconds=300)).isoformat()}}]
        validate_rule(rule)
        self.assertEqual(self.detect('ATTACK-02', rows, rule), [])
        self.assertEqual(evaluate(rows[0], rule)[0], 'excluded')
        self.assertEqual(evaluate(aws(30, seconds=300), rule)[0], 'matched')
        period = rule['exclusions'][0]['time_range']
        period['end'] = (BASE + timedelta(days=2)).isoformat()
        with self.assertRaises(ValueError):
            validate_rule(rule)
        period['end'] = (BASE + timedelta(seconds=300)).isoformat()
        rule['exclusions'][0]['conditions'].pop()
        with self.assertRaises(ValueError):
            validate_rule(rule)

    @staticmethod
    def value(row, field):
        for part in field.split('.'):
            row = row[part]
        return row

    def test_reordered_inputs_and_json_runtime_have_deterministic_ids(self):
        for rule_id, rows in [('ATTACK-01', attack_one()), ('ATTACK-02', [aws(i) for i in range(20)]),
                              ('ATTACK-03', [iam(), audit()])]:
            result = self.detect(rule_id, rows)
            self.assertEqual(make_alert_id(result[0]), make_alert_id(self.detect(rule_id, list(reversed(rows)))[0]))
            runtime = {}
            self.assertEqual(detect_behavior(rows[:-1], RULES[rule_id], runtime), [])
            restored = json.loads(json.dumps(runtime))
            resumed = detect_behavior(rows[-1:], RULES[rule_id], restored)
            self.assertEqual(make_alert_id(result[0]), make_alert_id(resumed[0]))
            self.assertEqual(detect_behavior(rows[-1:], RULES[rule_id], restored), [])

    def test_alert_assessment_and_existing_portal_evidence_path(self):
        rows = [iam(), audit()]
        detection = self.detect('ATTACK-03', rows)[0]
        alert = build_security_alert(detection)
        reader = Operations(client_for([]))
        with patch.object(reader, 'get', return_value=alert):
            detail = json.loads(reader.detail([('id', make_alert_id(detection))]))
        self.assertEqual(detail['evidence_count'], 2)
        self.assertEqual(detail['assessment']['reason'], 'ordered_metadata_stages')
        self.assertEqual(detail['assessment']['stages'][1]['evidence_offsets'], [1])
        self.assertEqual(detail['assessment']['attack_success'], 'not_established')
        self.assertEqual(alert['cloud_soc']['provenance']['evidence'][0]['raw'],
                         rows[0]['cloud_soc']['provenance']['raw'])

    def test_missing_exact_evidence_never_becomes_complete_alert(self):
        rows = [iam(), audit()]
        rows[0]['cloud_soc']['provenance'].pop('raw')
        with self.assertRaises(ValueError):
            self.detect('ATTACK-03', rows)

    def test_web_status_and_process_alone_cannot_produce_web_attack_rules(self):
        rows = [sudo()]
        rows[0]['event'].update(action='http_access', category=['web'], outcome='failure')
        self.assertEqual(detect_events(rows, approved_rules(include_attacks=True)), [])
        self.assertFalse({'ATTACK-04', 'ATTACK-05'} & RULES.keys())

    def test_rule_validation_rejects_unsupported_and_unbounded_specs(self):
        for path, value in [('stages', []), ('time_window', {'seconds': True}),
                            ('threshold', {'count': True}), ('limitations', []),
                            ('group_by', ['organization.id', []]), ('cooldown', {'seconds': -1}),
                            ('time_window', None), ('threshold', []), ('cooldown', None)]:
            rule = deepcopy(RULES['ATTACK-01'])
            rule[path] = value
            with self.assertRaises(ValueError):
                validate_rule(rule)

    def test_shared_ip_and_account_name_do_not_override_host_or_principal_scope(self):
        rows = attack_one()[:-1] + [sudo(host='other')]
        self.assertEqual(self.detect('ATTACK-01', rows), [])
        rows = [iam(), audit()]
        rows[1]['user']['id'] = 'FIXTURE:different-session'
        self.assertEqual(self.detect('ATTACK-03', rows), [])

    def test_one_api_repeated_and_inventory_below_threshold_are_not_recon(self):
        self.assertEqual(self.detect('ATTACK-02', [aws(i, provider='ec2.amazonaws.com', action='DescribeInstances')
                                                 for i in range(30)]), [])
        self.assertEqual(self.detect('ATTACK-02', [aws(i) for i in range(8)]), [])

    def test_cross_region_is_explicit_account_scope_not_region_inference(self):
        rows = [iam(), audit()]
        rows[1]['cloud']['region'] = 'ap-northeast-1'
        self.assertEqual(len(self.detect('ATTACK-03', rows)), 1)

    def test_multiple_audit_actions_are_independent_terminal_events(self):
        results = self.detect('ATTACK-03', [iam(), audit(), audit(102, seconds=61)])
        self.assertEqual(len(results), 2)
        self.assertNotEqual(make_alert_id(results[0]), make_alert_id(results[1]))

    def test_distinct_source_refs_on_ssh_do_not_create_fake_login_attempts(self):
        rows = [ssh(0)] * 5 + [ssh(40, seconds=10, outcome='success'), sudo()]
        self.assertEqual(self.detect('ATTACK-01', rows), [])

    def test_missing_ssh_ip_and_aws_event_identity_are_visible_unknown(self):
        row = ssh(0)
        del row['source']['ip']
        self.assertEqual(evaluate(row, RULES['ATTACK-01'])[0], 'unknown')
        row = aws(0)
        del row['cloud_soc']['detail']['fields']['event_id']
        self.assertEqual(evaluate(row, RULES['ATTACK-02'])[0], 'unknown')

    def test_malformed_unused_ssh_action_does_not_crash_counter(self):
        rows = attack_one()
        rows[0]['event']['action'] = ['invalid-action']
        self.assertEqual(len(self.detect('ATTACK-01', rows)), 1)

    def test_sudo_command_payload_or_unidentified_session_cannot_match_followup(self):
        prior = attack_one()[:-1]
        for message in ('fixture : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/bin/echo PRIVATE_CANARY',
                        'pam_unix(sudo:session): session opened for user root', '[REDACTED]'):
            hit = raw(80, seconds=60)
            hit['_source']['@timestamp'] = (BASE + timedelta(seconds=60)).isoformat()
            hit['_source']['host'] = {'id': 'host-a'}
            hit['_source']['labels']['log_source'] = 'linux_journald'
            hit['_source']['process'] = {'name': 'sudo'}
            hit['_source']['message'] = message
            key, record, row = normalize(hit, BASE.isoformat())
            if row:
                row['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
                self.assertEqual(self.detect('ATTACK-01', prior + [row]), [])


class AttackIncrementalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / 'runtime.sqlite'
        self.hits = []
        self.client = client_for([])
        self.client.field_caps.return_value = {'fields': {'cloud_soc.normalized_at': {'date': {}}}}
        self.client.count.return_value = {'count': 0}
        self.saved_ids = set()

        def write(*args, **kwargs):
            identifier = kwargs['document_id']
            result = 'existing' if identifier in self.saved_ids else 'created'
            self.saved_ids.add(identifier)
            return {'result': result}
        self.writer = patch('cloud_soc.detection.incremental.save_security_alert', side_effect=write)
        self.writer_mock = self.writer.start()
        self.addCleanup(self.writer.stop)

    def add(self, rows, receipt):
        for row in rows:
            event = deepcopy(row)
            meta = event.pop('_cloud_soc_meta')
            event['cloud_soc']['normalized_at'] = (BASE + timedelta(seconds=receipt)).isoformat()
            self.hits.append({'_index': NORMALIZED, '_id': meta['document_id'], '_source': event})

    def scan(self, *args, **kwargs):
        bounds = kwargs['query']['range']['cloud_soc.normalized_at']
        return deepcopy([h for h in self.hits if utc(bounds['gte']) <= utc(h['_source']['cloud_soc']['normalized_at']) < utc(bounds['lt'])])

    def run_at(self, seconds, **options):
        return run_incremental(self.client, state_path=self.path, start=BASE,
            now=BASE + timedelta(seconds=seconds), lateness_seconds=60, include_attacks=True,
            scanner=self.scan, **options)

    def state(self):
        with closing(sqlite3.connect(self.path)) as db:
            row = db.execute('SELECT body FROM runtime').fetchone()
            return json.loads(row[0]) if row else None

    def test_aws_correlation_cross_batch_restart_and_repeat(self):
        self.add([iam()], 10)
        self.assertEqual(self.run_at(140)['created'], 0)
        self.add([audit()], 130)
        self.assertEqual(self.run_at(230)['created'], 1)
        self.assertEqual(self.run_at(300)['created'], 0)
        self.assertEqual(len(self.saved_ids), 1)

    def test_diversity_cross_batch_and_expired_runtime(self):
        self.add([aws(i) for i in range(19)], 10)
        self.assertEqual(self.run_at(140)['created'], 0)
        self.add([aws(19, seconds=160)], 170)
        self.assertEqual(self.run_at(280)['created'], 1)
        for stamp in (500, 800, 1100):
            self.run_at(stamp)
        self.assertEqual(self.state()['rule_groups']['ATTACK-02'], {})

    def test_ssh_cross_batch_runtime(self):
        rows = attack_one(sudo_seconds=160)
        self.add(rows[:-1], 10)
        self.assertEqual(self.run_at(140)['created'], 0)
        self.add(rows[-1:], 170)
        self.assertEqual(self.run_at(280)['created'], 1)

    def test_late_arrival_within_buffer_is_sorted(self):
        self.add([audit()], 10)
        self.run_at(70)
        self.add([iam()], 50)
        self.assertEqual(self.run_at(180)['created'], 1)

    def test_late_after_frontier_is_excluded_not_silently_counted(self):
        self.run_at(140)
        self.add([iam(), audit(seconds=10)], 130)
        result = self.run_at(240)
        self.assertEqual(result['created'], 0)
        self.assertEqual(result['late'], 2)

    def test_missing_actor_visible_in_exclusion(self):
        row = aws(1)
        del row['user']['id']
        self.add([row], 10)
        self.run_at(140)
        exclusions = [c.kwargs['document'] for c in self.client.create.call_args_list
                      if c.kwargs.get('index') == 'soc-detection-exclusions-v1']
        self.assertTrue(any(e['reason'] == 'missing_condition_fields' and 'user.id' in e['missing_fields'] for e in exclusions))

    def test_write_failure_retains_state_and_retries_same_id(self):
        self.add([iam()], 10)
        self.run_at(140)
        old = self.state()
        self.add([audit()], 130)
        self.writer_mock.side_effect = RuntimeError('unavailable')
        with self.assertRaises(RuntimeError):
            self.run_at(230)
        identifier = self.writer_mock.call_args.kwargs['document_id']
        self.assertEqual(self.state(), old)
        self.writer_mock.side_effect = None
        self.writer_mock.return_value = {'result': 'created'}
        self.assertEqual(self.run_at(230)['created'], 1)
        self.assertEqual(identifier, self.writer_mock.call_args.kwargs['document_id'])

    def test_evidence_failure_keeps_checkpoint(self):
        self.run_at(70)
        old = self.state()
        self.add([iam()], 40)
        del self.hits[0]['_source']['cloud_soc']['provenance']['raw']
        with self.assertRaises(RuntimeError):
            self.run_at(140)
        self.assertEqual(self.state(), old)

    def test_option_or_rule_change_requires_new_state_no_auto_migration(self):
        self.run_at(70)
        old = self.state()
        with self.assertRaises(ValueError):
            run_incremental(self.client, state_path=self.path, start=BASE,
                now=BASE + timedelta(seconds=140), lateness_seconds=60, scanner=self.scan)
        self.assertEqual(self.state(), old)

    def test_snapshot_uses_same_profile_and_immutable_ids(self):
        self.add([iam(), audit()], 10)
        self.assertEqual(run_once(client_for(self.hits), include_attacks=True)['created'], 1)

    def test_active_state_limit_fails_without_advancing_checkpoint(self):
        self.run_at(70)
        old = self.state()
        self.add([ssh(0)], 40)
        with self.assertRaises(RuntimeError):
            self.run_at(140, max_active_events=1)
        self.assertEqual(self.state(), old)

    def test_rule_revision_change_does_not_migrate_existing_state(self):
        self.run_at(70)
        old = self.state()
        rules = approved_rules(include_attacks=True)
        rules[-2]['threshold']['count'] = 21
        with patch('cloud_soc.detection.incremental.approved_rules', return_value=rules):
            with self.assertRaises(ValueError):
                self.run_at(140)
        self.assertEqual(self.state(), old)

    def test_terminal_status_write_failure_retries_existing_alert(self):
        self.add([iam()], 10)
        self.run_at(140)
        old = self.state()
        self.add([audit()], 130)
        self.client.index.side_effect = [None, RuntimeError('status unavailable'), None]
        with self.assertRaises(RuntimeError):
            self.run_at(230)
        self.assertEqual(self.state(), old)
        self.client.index.side_effect = None
        self.assertEqual(self.run_at(230)['existing'], 1)

    def test_scoped_time_bounded_exception_is_audited_not_silently_dropped(self):
        rows = [aws(i) for i in range(20)]
        self.add(rows, 10)
        rules = approved_rules(include_attacks=True)
        rule = next(r for r in rules if r['id'] == 'ATTACK-02')
        rule['exclusions'] = [{'conditions': [{'field': f, 'operator': 'equals',
            'value': AttackTests.value(rows[0], f)} for f in rule['group_by']],
            'time_range': {'start': BASE.isoformat(), 'end': (BASE + timedelta(seconds=300)).isoformat()}}]
        validate_rule(rule)
        with patch('cloud_soc.detection.incremental.approved_rules', return_value=rules):
            self.assertEqual(self.run_at(140)['created'], 0)
        docs = [c.kwargs['document'] for c in self.client.create.call_args_list
                if c.kwargs.get('index') == 'soc-detection-exclusions-v1']
        self.assertEqual(sum(d['reason'] == 'approved_policy_exception' for d in docs), 20)
        runs = [c.kwargs['document'] for c in self.client.create.call_args_list
                if c.kwargs.get('index') == 'soc-detection-runs-v1']
        self.assertTrue(any(d['rule']['id'] == 'ATTACK-02' and d['counts']['policy_excluded'] == 20 for d in runs))


if __name__ == '__main__':
    unittest.main()
