"""Real normalization/engine/evidence code with in-memory ES IO; no live claims."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from unittest.mock import Mock, patch

from elasticsearch import NotFoundError
import pytest

from cloud_soc.acceptance import inspect, main, write_report
from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.telemetry import runtime_manifest
from cloud_soc.detection.worker import approved_rules
from cloud_soc.main import build_security_alert
from cloud_soc.processing.contract import normalize, NORMALIZED, RECORDS, STATUS


@pytest.fixture
def pipeline():
    now = datetime.now(timezone.utc)
    since = now - timedelta(minutes=5)
    normalized_at = now - timedelta(seconds=45)
    docs, events = {}, []
    for i in range(10):
        occurred = now - timedelta(seconds=120-i)
        raw = {'@timestamp': occurred.isoformat(), 'event': {'ingested': occurred.isoformat(), 'timezone': 'UTC'},
               'organization': {'id': 'team-a'}, 'labels': {'log_source': 'linux_file'},
               'message': occurred.strftime('%b %d %H:%M:%S') +
               ' host sshd[100]: Failed password for fixture from 192.0.2.10 port 12345 ssh2'}
        hit = {'_index': 'soc-host-raw-acceptance', '_id': str(i), '_source': raw}
        key, record, event = normalize(hit, normalized_at.isoformat())
        assert record['status'] == 'normalized'
        docs[(hit['_index'], hit['_id'])] = raw
        docs[(NORMALIZED, key)] = deepcopy(event)
        docs[(RECORDS, key)] = record
        event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
        events.append(event)
    rules = approved_rules()
    alert = build_security_alert(detect_events(events, rules)[0])
    docs[('security-alerts', 'selected-alert')] = alert
    for worker in ('detector', 'detector-priority', 'detector-additional'):
        docs[(STATUS, worker)] = {'@timestamp': now.isoformat(), 'state': 'success',
                                  'last_success': now.isoformat(), 'checkpoint': now.isoformat(),
                                  'runtime': runtime_manifest(rules, 'continuous')}
    client = Mock()
    client.options.return_value = client
    client.indices.resolve_index.side_effect = lambda **kw: {'indices': [{'name': kw['name']}]}

    def get(**kw):
        value = docs.get((kw['index'], kw['id']))
        if value is None:
            raise NotFoundError('missing', meta=Mock(status=404), body={})
        return {'_source': deepcopy(value), 'found': True}

    client.get.side_effect = get
    options = {'alert_id': 'selected-alert', 'organization': 'team-a', 'rule_id': 'AUTH-001',
               'since': since.isoformat(), 'raw_indices': ['soc-host-raw-acceptance'], 'now': now}
    return client, docs, options


def test_complete_generic_ssh_chain_without_mall(pipeline):
    client, _, options = pipeline
    report = inspect(client, **options)
    assert report['pipeline_evidence'] == 'passed', report
    assert report['evidence_count'] == 10
    assert report['full_acceptance'] == report['browser'] == report['slack_channel_receipt'] == 'unverified'
    assert all(row['passed'] for row in report['checks'])
    for method in ('create', 'index', 'bulk', 'update', 'delete', 'search'):
        getattr(client, method).assert_not_called()
    client.indices.create.assert_not_called()
    assert 'fixture' not in json.dumps(report)


@pytest.mark.parametrize('failure', ['old', 'tampered_norm', 'tampered_raw', 'raw_missing', 'record_missing',
                                     'wrong_org', 'snapshot', 'stopped', 'future', 'wrong_revision',
                                     'wrong_rule', 'duplicate', 'legacy_hash', 'old_checkpoint', 'future_success'])
def test_incomplete_or_unrelated_evidence_never_passes(pipeline, failure):
    client, docs, options = pipeline
    alert = docs[('security-alerts', 'selected-alert')]
    ref = alert['cloud_soc']['provenance']['evidence'][0]
    norm_key = (ref['normalized']['index'], ref['normalized']['id'])
    if failure == 'old':
        options['since'] = (options['now'] - timedelta(seconds=30)).isoformat()
    elif failure == 'tampered_norm':
        docs[norm_key]['event']['outcome'] = 'success'
    elif failure == 'tampered_raw':
        docs[('soc-host-raw-acceptance', '0')]['message'] = 'unrelated service log'
    elif failure == 'raw_missing':
        del docs[('soc-host-raw-acceptance', '0')]
    elif failure == 'record_missing':
        del docs[(RECORDS, ref['normalized']['id'])]
    elif failure == 'wrong_org':
        docs[norm_key]['organization']['id'] = 'other'
    elif failure == 'future':
        docs[('soc-host-raw-acceptance', '0')]['event']['ingested'] = (options['now']+timedelta(days=1)).isoformat()
    elif failure == 'wrong_revision':
        alert['cloud_soc']['provenance']['rule_version'] = 'f'*64
    elif failure == 'wrong_rule':
        options['rule_id'] = 'WEB-ACCESS-01'
    elif failure == 'duplicate':
        alert['cloud_soc']['provenance']['evidence'][1] = deepcopy(ref)
    elif failure == 'legacy_hash':
        ref.pop('event_hash')
    else:
        for key, value in docs.items():
            if key[0] == STATUS:
                if failure == 'snapshot':
                    value['runtime']['mode'] = 'snapshot'
                elif failure == 'stopped':
                    value['@timestamp'] = '2020-01-01T00:00:00Z'
                elif failure == 'old_checkpoint':
                    value['checkpoint'] = options['since']
                elif failure == 'future_success':
                    value['last_success'] = (options['now']+timedelta(days=1)).isoformat()
    assert inspect(client, **options)['pipeline_evidence'] == 'incomplete'


def test_wrong_organization_cannot_read_evidence(pipeline):
    client, _, options = pipeline
    options['organization'] = 'other'
    report = inspect(client, **options)
    assert report['checks'] == [{'name': 'selected_alert_visible', 'passed': False}]
    assert client.get.call_count == 1


def test_explicit_intake_allowlist_checked_before_evidence_fetch(pipeline):
    client, _, options = pipeline
    options['raw_indices'] = ['soc-host-raw-another']
    assert inspect(client, **options)['pipeline_evidence'] == 'incomplete'
    assert client.get.call_count == 1


def test_alias_and_unavailable_are_errors_not_zero_success(pipeline):
    client, _, options = pipeline
    client.indices.resolve_index.side_effect = None
    client.indices.resolve_index.return_value = {'aliases': [{'name': 'security-alerts'}]}
    with pytest.raises(ValueError):
        inspect(client, **options)
    client.get.assert_not_called()


def test_report_is_exclusive_and_errors_hide_secret(tmp_path, capsys):
    target = tmp_path / 'acceptance.json'
    write_report(target, {'read_only': True})
    with pytest.raises(FileExistsError):
        write_report(target, {'changed': True})
    ca = tmp_path / 'ca.crt'
    ca.write_text('fixture', encoding='utf-8')
    with patch('cloud_soc.acceptance.protected_key', side_effect=RuntimeError('SECRET_CANARY')):
        assert main(['--es-url', 'https://127.0.0.1:9200', '--ca-file', str(ca), '--api-key-file', 'unused',
                     '--alert-id', 'selected-alert', '--organization', 'team-a', '--rule-id', 'AUTH-001',
                     '--since', '2026-10-19T00:00:00Z', '--raw-index', 'soc-host-raw-acceptance',
                     '--report', str(tmp_path / 'new.json')]) == 1
    assert 'SECRET_CANARY' not in capsys.readouterr().out
    assert json.loads(target.read_text()) == {'read_only': True}
