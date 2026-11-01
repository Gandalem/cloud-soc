"""Synthetic native records, real SDK contracts and existing normalization/Portal paths."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock, patch

import boto3
from botocore.stub import Stubber
import pytest

from cloud_soc.aws.cloudwatch import main
from cloud_soc.aws.collector import CollectionError, State
from cloud_soc.aws.log_collector import LogSettings, poll_source, run_cycle, DELIVERY_CHECK_STREAM
from cloud_soc.aws.service_logs import KINDS, project
from cloud_soc.detection.engine import detect_events
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.detection.worker import approved_rules
from cloud_soc.portal.log_contract import SOURCE_FIELDS, parse_filters
from cloud_soc.portal.log_query import project_list_hit, LogReader, LogQueryError
from cloud_soc.portal.security_detail import DETAIL_FIELDS, security_detail
from cloud_soc.processing.contract import normalize, NORMALIZED
from cloud_soc.processing.worker import READ_FIELDS

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT, REGION = '123456789012', 'ap-northeast-3'
NOW = datetime(2026, 11, 1, 2, tzinfo=timezone.utc)
AT = '2026-11-01T01:20:00Z'
VPC = 'vpc-0123456789abcdef0'
CANARY = 'PRIVATE_SQL_COOKIE_CANARY'


def entry(kind):
    resource = VPC if kind == 'route53_resolver' else 'fixture-resource'
    group = '/fixture/' + kind
    if kind.startswith('rds_'):
        group = '/aws/rds/instance/' + resource + '/' + kind.removeprefix('rds_')
    return {'id': kind, 'kind': kind, 'region': 'us-east-1' if kind == 'cloudfront' else REGION,
            'log_group': group, 'resource_id': resource}


def config(*kinds):
    return {'account_id': ACCOUNT, 'organization': 'fixture', 'lookback_hours': 1,
            'overlap_minutes': 1560, 'sources': [entry(k) for k in kinds or KINDS]}


def native(kind):
    if kind == 'route53_resolver':
        return {'version': '1.1', 'account_id': ACCOUNT, 'region': REGION, 'vpc_id': VPC,
                'query_timestamp': AT, 'query_name': 'example.com.', 'query_type': 'A',
                'rcode': 'NOERROR', 'srcaddr': '10.250.10.156', 'srcport': '55000', 'transport': 'UDP',
                'answers': [{'rdata': CANARY}]}
    if kind == 'securityhub':
        return {'source': 'aws.securityhub', 'detail-type': 'Security Hub Findings - Imported',
                'id': 'fixture-eventbridge-id', 'account': ACCOUNT, 'region': REGION, 'time': AT,
                'detail': {'findings': [{'Id': 'fixture-finding-id', 'AwsAccountId': ACCOUNT,
                    'UpdatedAt': AT, 'Region': REGION, 'Severity': {'Label': 'HIGH'},
                    'Workflow': {'Status': 'NEW'}, 'RecordState': 'ACTIVE',
                    'Compliance': {'Status': 'FAILED'}, 'Resources': [{'Id': VPC}], 'Description': CANARY}]}}
    if kind == 'rds_general':
        return AT + ' 12 Query SELECT secret FROM member WHERE value=\'' + CANARY + "'\ncontinuation " + CANARY
    if kind == 'rds_error':
        return AT + ' 12 [ERROR] [MY-010001] [Server] ' + CANARY
    if kind == 'cloudfront':
        return {'date': '2026-11-01', 'time': '01:20:00', 'c-ip': '192.0.2.10', 'cs-method': 'GET',
                'sc-status': '200', 'x-edge-request-id': 'fixture-request==', 'x-edge-result-type': 'Hit',
                'cs-uri-query': CANARY, 'cs(Cookie)': CANARY, 'cs-uri-stem': '/' + CANARY}
    event = {'timestamp': AT, 'flow_id': 1234567890123456789,
             'event_type': 'alert' if kind.endswith('alert') else 'netflow',
             'src_ip': '10.250.10.156', 'src_port': 55000, 'dest_ip': '192.0.2.20', 'dest_port': 443, 'proto': 'TCP',
             'payload': CANARY, 'alert': {'action': 'allowed', 'signature_id': 1000001, 'severity': 3, 'signature': CANARY},
             'netflow': {'pkts': 3, 'bytes': 500}}
    return {'firewall_name': 'fixture-resource', 'availability_zone': REGION + 'b', 'event': event}


def envelope(kind, number=1, value=None):
    value = native(kind) if value is None else value
    return {'message': value if isinstance(value, str) else json.dumps(value),
            'timestamp': int(datetime.fromisoformat(AT.replace('Z', '+00:00')).timestamp() * 1000),
            'ingestionTime': int((NOW - timedelta(minutes=10)).timestamp() * 1000),
            'eventId': f'fixture-event-{number}', 'logStreamName': 'fixture-stream'}


def projected(kind, number=1, value=None, org='fixture'):
    source = entry(kind)
    return project(envelope(kind, number, value), account=ACCOUNT, organization=org,
                   region=source['region'], group=source['log_group'], kind=kind, resource_id=source['resource_id'])


def normalized(kind, number=1, value=None):
    index, identifier, raw = projected(kind, number, value)[0]
    raw['event']['ingested'] = NOW.isoformat()
    key, record, event = normalize({'_index': index, '_id': identifier, '_source': raw}, NOW.isoformat())
    assert record['status'] == 'normalized'
    event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
    return raw, event


def selected(source, paths):
    result = {}
    for path in paths:
        value = source
        parts = path.split('.')
        for part in parts:
            if not isinstance(value, dict) or part not in value:
                break
            value = value[part]
        else:
            dest = result
            for part in parts[:-1]:
                dest = dest.setdefault(part, {})
            dest[parts[-1]] = deepcopy(value)
    return result


@pytest.mark.parametrize('kind', KINDS)
def test_native_projection_to_worker_and_portal_with_exact_reference_and_no_original(kind):
    original = envelope(kind)
    before = deepcopy(original)
    source = entry(kind)
    index, identifier, raw = project(original, account=ACCOUNT, organization='fixture', region=source['region'],
        group=source['log_group'], kind=kind, resource_id=source['resource_id'])[0]
    assert original == before
    assert CANARY not in json.dumps(raw)
    assert 'message' not in raw and 'original' not in raw['event'] and 'host' not in raw
    assert raw['aws']['service_logs']['original_sha256'] == hashlib.sha256(original['message'].encode()).hexdigest()
    assert raw['@timestamp'] == AT and 'ingested' not in raw['event']
    raw['event']['ingested'] = NOW.isoformat()
    hit = {'_index': index, '_id': identifier, '_source': selected(raw, READ_FIELDS)}
    key, record, result = normalize(hit, NOW.isoformat())
    assert record['status'] == 'normalized'
    assert result['cloud_soc']['provenance']['raw'] == {'index': index, 'id': identifier}
    assert result['event']['id'] == identifier and result['event']['dataset'] == 'aws.' + kind
    assert result['service']['name'] == KINDS[kind][0]
    assert CANARY not in json.dumps(result)
    row = project_list_hit({**hit, '_source': selected(raw, SOURCE_FIELDS + DETAIL_FIELDS)})
    assert row['source_kind'] == 'aws_service_logs' and row['parse_status'] == 'recognized'
    assert row['os'] == 'cloud' and row['cloud_account'] == ACCOUNT
    assert row['log_type']['code'] == kind
    assert key and record['normalized']['index'] == NORMALIZED


@pytest.mark.parametrize('kind', KINDS)
def test_ids_replay_stable_and_scoped_to_org_region_group_stream_event_and_finding(kind):
    first = projected(kind)
    assert first == projected(kind)
    assert first[0][1] != projected(kind, number=2)[0][1]
    assert first[0][1] != projected(kind, org='another')[0][1]
    source = entry(kind)
    changed = envelope(kind)
    changed['logStreamName'] = 'another-stream'
    assert first[0][1] != project(changed, account=ACCOUNT, organization='fixture', region=source['region'],
        group=source['log_group'], kind=kind, resource_id=source['resource_id'])[0][1]


def test_specific_fields_outcomes_no_claim_that_query_or_alert_succeeded():
    assert normalized('rds_general')[0]['aws']['service_logs']['statement_type'] == 'SELECT'
    assert normalized('rds_general')[1]['event']['outcome'] == 'unknown'
    assert normalized('network_firewall_alert')[1]['cloud_soc']['detail']['fields']['firewall_action'] == 'allowed'
    assert normalized('network_firewall_alert')[1]['event']['outcome'] == 'unknown'
    assert normalized('route53_resolver')[1]['dns']['response_code'] == 'NOERROR'
    assert normalized('cloudfront')[1]['http']['response']['status_code'] == 200
    assert normalized('rds_error')[1]['cloud_soc']['detail']['fields']['error_code'] == 'MY-010001'
    assert normalized('securityhub')[1]['event']['outcome'] == 'unknown'
    assert normalized('network_firewall_flow')[1]['network'] == {'transport': 'tcp', 'bytes': 500, 'packets': 3}


@pytest.mark.parametrize('key', ['resource_id', 'cloudwatch_at', 'query_name'])
def test_incomplete_stored_projection_is_invalid_not_recognized(key):
    raw, _ = normalized('route53_resolver')
    del raw['aws']['service_logs'][key]
    assert security_detail(raw)['status'] == 'invalid'


def test_rds_missing_native_time_is_explicit_cloudwatch_basis_not_guessed_sql_time():
    doc = projected('rds_general', value='12 Query SELECT ' + CANARY)[0][2]
    assert doc['aws']['service_logs']['time_basis'] == 'cloudwatch_event_timestamp_not_statement_time'
    assert CANARY not in json.dumps(doc)


@pytest.mark.parametrize('value', ['55000', 55000])
def test_resolver_observed_decimal_string_and_integer_ports_normalize_identically(value):
    event = native('route53_resolver')
    event['srcport'] = value
    raw, row = normalized('route53_resolver', value=event)
    assert raw['source']['port'] == row['source']['port'] == 55000


@pytest.mark.parametrize('value', ['1.5', '-1', '65536', True, 'port'])
def test_resolver_port_coercion_does_not_accept_invalid_or_boolean_values(value):
    event = native('route53_resolver')
    event['srcport'] = value
    with pytest.raises(ValueError, match='invalid_service_log_event'):
        projected('route53_resolver', value=event)


def test_securityhub_multiple_findings_split_and_updates_not_lost():
    raw = native('securityhub')
    second = deepcopy(raw['detail']['findings'][0])
    second['Id'] += '-second'
    raw['detail']['findings'].append(second)
    docs = projected('securityhub', value=raw)
    assert len(docs) == 2 and docs[0][1] != docs[1][1]
    assert docs[0][1] != projected('securityhub', number=2, value=raw)[0][1]
    raw['detail']['findings'].append(second)
    with pytest.raises(ValueError, match='invalid_service_log_event'):
        projected('securityhub', value=raw)


@pytest.mark.parametrize('kind,key,value', [
    ('route53_resolver', 'account_id', '999999999999'), ('route53_resolver', 'region', 'us-west-2'),
    ('route53_resolver', 'vpc_id', 'vpc-wrong'), ('route53_resolver', 'srcaddr', 'invalid'),
    ('route53_resolver', 'query_timestamp', '2026-11-01T01:00:00'),
    ('securityhub', 'account', '999999999999'), ('securityhub', 'detail-type', 'Findings Imported V2'),
    ('cloudfront', 'sc-status', 'garbage'), ('network_firewall_alert', 'firewall_name', 'another-firewall')])
def test_bad_scope_or_native_format_rejected_with_fixed_error(kind, key, value):
    raw = native(kind)
    raw[key] = value
    with pytest.raises(ValueError, match='^invalid_service_log_event$'):
        projected(kind, value=raw)


@pytest.mark.parametrize('message', ['{"a":1,"a":2}', '{"a":NaN}', '{', '[]', 'x' * (1024 * 1024 + 1)],
                         ids=['duplicate-key', 'nonfinite', 'malformed', 'array', 'oversized'])
def test_bounded_strict_json(message):
    with pytest.raises(ValueError, match='invalid_service_log_event'):
        projected('route53_resolver', value=message)


def test_cloudfront_cross_region_collection_and_same_clock_multiple_sources():
    settings = LogSettings.parse(config('route53_resolver', 'cloudfront'))
    assert {s.region for s in settings.sources} == {REGION, 'us-east-1'}
    assert projected('cloudfront')[0][2]['cloud']['region'] == 'us-east-1'
    assert parse_filters([('collector', 'aws-cloudwatch'), ('os', 'cloud')]).collector == 'aws-cloudwatch'


@pytest.mark.parametrize('change', ['duplicate', 'group', 'rds', 'kind', 'hours', 'unknown'])
def test_config_rejects_ambiguous_or_unapproved_scope(change):
    value = config('rds_general')
    if change == 'duplicate': value['sources'] *= 2
    if change == 'group': value['sources'][0]['log_group'] = '*'
    if change == 'rds': value['sources'][0]['resource_id'] = 'another-db'
    if change == 'kind': value['sources'][0]['kind'] = 'cloudtrail'
    if change == 'hours': value['lookback_hours'] = True
    if change == 'unknown': value['access_key'] = CANARY
    with pytest.raises(CollectionError, match='invalid_cloudwatch_config'):
        LogSettings.parse(value)


class Sink:
    def __init__(self):
        self.docs = {}

    def create(self, index, identifier, document):
        if (index, identifier) in self.docs:
            return False
        self.docs[index, identifier] = deepcopy(document)
        return True


@pytest.fixture
def polling(tmp_path):
    settings = LogSettings.parse(config('route53_resolver'))
    state = State(tmp_path / 'logs.sqlite', settings, now=NOW)
    aws, sts, sink = Mock(), Mock(), Sink()
    sts.get_caller_identity.return_value = {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:role/fixture'}
    yield settings, state, aws, sts, sink
    state.close()


def cycle(polling, **kwargs):
    settings, state, aws, sts, sink = polling
    return run_cycle(settings, state, sts, {REGION: aws}, sink, now=NOW, sleep=lambda _: None, **kwargs)


def test_empty_page_with_token_then_delivery_and_atomic_checkpoint(polling):
    settings, state, aws, _, sink = polling
    aws.filter_log_events.side_effect = [{'events': [], 'nextToken': 'next'}, {'events': [envelope('route53_resolver')]}]
    result = cycle(polling)[0]
    assert result['created'] == 1 and len(sink.docs) == 1
    assert state.status()[0]['watermark'] == '2026-11-01T01:55:00Z'
    calls = aws.filter_log_events.call_args_list
    assert calls[1].kwargs == {**calls[0].kwargs, 'nextToken': 'next'}
    assert calls[0].kwargs['unmask'] is False
    assert settings.sources[0].log_group == calls[0].kwargs['logGroupName']


def test_partial_failure_and_restart_replay_deduplicates_without_skipping(polling, tmp_path):
    settings, state, aws, sts, sink = polling
    aws.filter_log_events.side_effect = [{'events': [envelope('route53_resolver')], 'nextToken': 'next'}, RuntimeError(CANARY)]
    assert cycle(polling)[0]['code'] == 'aws_logs_read_failed'
    assert state.status()[0]['watermark'] == '2026-11-01T01:00:00Z'
    restarted = State(tmp_path / 'logs.sqlite', settings, now=NOW)
    try:
        aws.filter_log_events.side_effect = [{'events': [envelope('route53_resolver'), envelope('route53_resolver', 2)]}]
        result = run_cycle(settings, restarted, sts, {REGION: aws}, sink, now=NOW, sleep=lambda _: None)[0]
        assert (result['created'], result['duplicates']) == (1, 1)
        assert len(sink.docs) == 2
        assert CANARY not in json.dumps(restarted.status())
    finally:
        restarted.close()


def test_es_failure_does_not_commit_window(polling):
    _, state, aws, _, sink = polling
    aws.filter_log_events.return_value = {'events': [envelope('route53_resolver')]}
    sink.create = Mock(side_effect=CollectionError('elasticsearch_write_failed'))
    assert cycle(polling)[0]['code'] == 'elasticsearch_write_failed'
    assert state.status()[0]['watermark'] == '2026-11-01T01:00:00Z'


def test_delivery_check_is_not_native_ingestion_and_does_not_hide_following_page(polling):
    _, state, aws, _, sink = polling
    check = envelope('route53_resolver', value='AWS delivery validation message')
    check['logStreamName'] = DELIVERY_CHECK_STREAM
    aws.filter_log_events.side_effect = [{'events': [check], 'nextToken': 'next'},
                                       {'events': [envelope('route53_resolver')]}]
    result = cycle(polling)[0]
    assert result['ignored_delivery_checks'] == 1 and result['created'] == 1
    assert len(sink.docs) == 1 and state.status()[0]['error'] is None
    assert all(doc['aws']['service_logs']['log_stream'] != DELIVERY_CHECK_STREAM for doc in sink.docs.values())


def test_delivery_check_only_creates_no_service_documents(polling):
    _, _, aws, _, sink = polling
    check = envelope('route53_resolver', value='AWS delivery validation message')
    check['logStreamName'] = DELIVERY_CHECK_STREAM
    aws.filter_log_events.return_value = {'events': [check]}
    result = cycle(polling)[0]
    assert result['created'] == 0 and result['duplicates'] == 0
    assert result['ignored_delivery_checks'] == 1 and not sink.docs


@pytest.mark.parametrize('failure', ['token', 'limit', 'bad_event', 'bad_page'])
def test_invalid_page_or_poison_event_never_advances_checkpoint(polling, failure):
    _, state, aws, _, _ = polling
    if failure in ('token', 'limit'):
        aws.filter_log_events.return_value = {'events': [], 'nextToken': 'repeat'}
    elif failure == 'bad_page':
        aws.filter_log_events.return_value = {'events': {}}
    else:
        aws.filter_log_events.return_value = {'events': [envelope('route53_resolver', value=CANARY)]}
    assert cycle(polling, max_pages=1 if failure == 'limit' else 3)[0]['status'] == 'error'
    assert state.status()[0]['watermark'] == '2026-11-01T01:00:00Z'


def test_account_mismatch_stops_before_cloudwatch_or_es(polling):
    _, state, aws, sts, sink = polling
    sts.get_caller_identity.return_value['Account'] = '999999999999'
    with pytest.raises(CollectionError, match='aws_account_mismatch'):
        cycle(polling)
    aws.filter_log_events.assert_not_called()
    assert not sink.docs
    assert state.status()[0]['error'] == 'aws_account_mismatch'


def test_state_binding_refuses_scope_changes(polling, tmp_path):
    changed = config('route53_resolver')
    changed['organization'] = 'another'
    with pytest.raises(CollectionError, match='state_scope_mismatch'):
        State(tmp_path / 'logs.sqlite', LogSettings.parse(changed), now=NOW)


def test_real_sdk_stubber_validates_filter_request_and_response(polling):
    settings, state, _, _, sink = polling
    client = boto3.client('logs', region_name=REGION, aws_access_key_id='synthetic', aws_secret_access_key='synthetic')
    try:
        with Stubber(client) as stub:
            stub.add_response('filter_log_events', {'events': [envelope('route53_resolver')]},
                {'logGroupName': entry('route53_resolver')['log_group'], 'startTime': int((NOW - timedelta(hours=1)).timestamp()*1000),
                 'endTime': int((NOW - timedelta(minutes=5)).timestamp()*1000), 'limit': 1000, 'unmask': False})
            assert poll_source(settings, state, settings.sources[0], client, sink, now=NOW, sleep=lambda _: None)['created'] == 1
            stub.assert_no_pending_responses()
    finally:
        client.close()


def test_offline_cli_no_aws_no_state_and_status_does_not_report_e2e_success(tmp_path, capsys):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(config('route53_resolver')))
    state = tmp_path / 'state.sqlite'
    with patch('boto3.Session', side_effect=AssertionError('must remain offline')):
        assert main(['--config', str(path), '--state', str(state)]) == 0
        assert not state.exists()
        assert json.loads(capsys.readouterr().out)['aws_contacted'] is False
        db = State(state, LogSettings.parse(config('route53_resolver')), now=NOW)
        db.close()
        assert main(['--config', str(path), '--state', str(state), '--status']) == 0
        assert json.loads(capsys.readouterr().out)['live_ingestion_verified'] is False


def test_unknown_projection_fields_and_original_are_not_disclosed_or_normalized():
    raw, _ = normalized('rds_general')
    raw['aws']['service_logs']['sql'] = CANARY
    raw['message'] = CANARY
    assert CANARY not in json.dumps(security_detail(raw))
    _, _, event = normalize({'_index': 'soc-cloud-aws-test', '_id': 'fixture', '_source': raw}, NOW.isoformat())
    assert CANARY not in json.dumps(event)
    _, record, event = normalize({'_index': 'soc-host-raw-test', '_id': 'fixture', '_source': raw}, NOW.isoformat())
    assert event is None and record['status'] == 'invalid'


@pytest.mark.parametrize('kind', KINDS)
def test_service_detail_uses_exact_mget_allowlist_and_preserves_organization_gate(kind):
    index, identifier, raw = projected(kind)[0]
    raw['event']['ingested'] = NOW.isoformat()
    client = Mock()
    client.options.return_value = client
    client.indices.resolve_index.return_value = {'indices': [{'name': index}], 'aliases': [], 'data_streams': []}
    def mget(*, index, docs):
        return {'docs': [{'_index': index, '_id': docs[0]['_id'], 'found': True,
                          '_source': selected(raw, docs[0]['_source'])}]}
    client.mget.side_effect = mget
    reader = LogReader(client, secret='synthetic-key', principal='fixture', organizations=['fixture'])
    result = json.loads(reader.detail([('index', index), ('id', identifier)]))
    assert result['security']['status'] == 'recognized'
    assert result['security']['fields']['kind'] == kind
    assert result['row']['reference'] == {'index': index, 'id': identifier}
    assert CANARY not in json.dumps(result)
    request = client.mget.call_args.kwargs
    assert request['index'] == index and len(request['docs']) == 1
    assert set(request['docs'][0]['_source']) == set(SOURCE_FIELDS + DETAIL_FIELDS)
    reader.organizations = ('another',)
    with pytest.raises(LogQueryError) as denied:
        reader.detail([('index', index), ('id', identifier)])
    assert denied.value.status == 404


def test_one_group_failure_does_not_advance_it_or_block_other_regions(tmp_path):
    from botocore.exceptions import ClientError
    settings = LogSettings.parse(config('cloudfront', 'route53_resolver'))
    state = State(tmp_path / 'groups.sqlite', settings, now=NOW)
    try:
        clients = {s.region: Mock() for s in settings.sources}
        clients['us-east-1'].filter_log_events.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException', 'Message': CANARY}}, 'FilterLogEvents')
        clients[REGION].filter_log_events.return_value = {'events': [envelope('route53_resolver')]}
        sts = Mock()
        sts.get_caller_identity.return_value = {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:role/fixture'}
        results = run_cycle(settings, state, sts, clients, Sink(), now=NOW, sleep=lambda _: None)
        assert results[0]['code'] == 'aws_access_denied' and results[1]['created'] == 1
        states = {r['region']: r for r in state.status()}
        assert states['cloudfront']['watermark'] == '2026-11-01T01:00:00Z'
        assert states['route53_resolver']['watermark'] == '2026-11-01T01:55:00Z'
        assert CANARY not in json.dumps(results)
    finally:
        state.close()


@pytest.mark.parametrize('kind', ['route53_resolver', 'securityhub', 'rds_error', 'cloudfront', 'network_firewall_alert'])
def test_optional_five_service_detection_candidates_positive_and_negative(kind):
    rules = load_rules(ROOT / 'deploy/aws/service-rules.example.yml', enabled_only=False)
    assert all(not rule['enabled'] for rule in rules)
    assert [r['id'] for r in approved_rules()] == ['AUTH-001']
    assert detect_events([normalized(kind)[1]], rules) == []
    for rule in rules:
        rule['enabled'] = True  # only this isolated in-memory validation
    value = native(kind)
    count = 1
    if kind == 'route53_resolver': value['rcode'], count = 'NXDOMAIN', 10
    if kind == 'cloudfront': value['sc-status'], count = '503', 5
    events = [normalized(kind, n + 1, value)[1] for n in range(count)]
    assert len(detect_events(events, rules)) == 1
    assert len(detect_events(events + deepcopy(events), rules)) == 1
    if count > 1:
        assert detect_events(events[:-1], rules) == []
        assert detect_events([normalized(kind, n + 1)[1] for n in range(count)], rules) == []
    elif kind == 'securityhub':
        value['detail']['findings'][0]['Workflow']['Status'] = 'RESOLVED'
        assert detect_events([normalized(kind, value=value)[1]], rules) == []
    elif kind == 'rds_error':
        assert detect_events([normalized(kind, value=AT + ' [Note] normal')[1]], rules) == []
    else:
        assert detect_events([normalized('network_firewall_flow')[1]], rules) == []
