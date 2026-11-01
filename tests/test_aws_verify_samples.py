from copy import deepcopy
from datetime import timedelta
import json

import pytest

from cloud_soc.aws.verify_samples import SOURCES, GENERAL_SOURCE, FIREWALL_SOURCES, VerificationError, sample, verify
from test_aws_service_logs import ACCOUNT, NOW, CANARY, envelope


def test_existing_real_shapes_are_projected_without_raw_body_or_credentials():
    calls = []
    def call(*args):
        calls.append(args)
        if args[0] == 'sts':
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture'}
        if args[0] == 'cloudfront':
            return {'Distribution': {'ARN': f'arn:aws:cloudfront::{ACCOUNT}:distribution/EGVZJI81RXNWQ'}}
        group = args[args.index('--log-group-name') + 1]
        kind = next(s['kind'] for s in SOURCES if s['group'] == group)
        event = envelope(kind)
        if kind == 'route53_resolver':
            value = json.loads(event['message'])
            value['vpc_id'] = SOURCES[0]['resource']
            event['message'] = json.dumps(value)
        return {'events': [event]}
    report = verify(account=ACCOUNT, call=call, now=NOW, sleep=lambda _: None)
    assert [s['status'] for s in report['sources']] == ['verified'] * 3
    assert CANARY not in json.dumps(report)
    assert report['mode'] == 'manual_readonly_cloudshell_sample'
    assert all('ingested' not in s['document']['event'] for s in report['sources'])
    assert {args[1] for args in calls} <= {'get-caller-identity', 'get-distribution', 'filter-log-events'}


def test_account_mismatch_stops_before_service_calls():
    calls = []
    def call(*args):
        calls.append(args)
        return {'Account': '999999999999', 'Arn': 'arn:aws:iam::999999999999:user/fixture'}
    with pytest.raises(VerificationError, match='aws_account_mismatch'):
        verify(account=ACCOUNT, call=call, now=NOW)
    assert len(calls) == 1


def test_empty_page_continues_and_no_result_does_not_claim_success():
    pages = iter([{'events': [], 'nextToken': 'next'}, {'events': []}])
    result = sample(SOURCES[0], account=ACCOUNT, organization='fixture', start=0,
                    end=int(NOW.timestamp()*1000), call=lambda *args: next(pages), sleep=lambda _: None)
    assert result['status'] == 'no_sample_in_window'


def test_one_failure_does_not_prevent_other_sources_and_never_echoes_private_error():
    def call(*args):
        if args[0] == 'sts':
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture'}
        if args[0] == 'cloudfront':
            raise RuntimeError(CANARY)
        return {'events': []}
    report = verify(account=ACCOUNT, call=call, now=NOW, sleep=lambda _: None)
    assert len(report['sources']) == 3
    assert report['sources'][1]['code'] == 'sample_verification_failed'
    assert CANARY not in json.dumps(report)


def test_cloudfront_cannot_be_bound_to_another_account_distribution():
    with pytest.raises(VerificationError, match='cloudfront_binding_mismatch'):
        sample(SOURCES[1], account=ACCOUNT, organization='fixture', start=0,
               end=int(NOW.timestamp()*1000), call=lambda *args: {'Distribution': {'ARN': 'another'}})


def test_rds_general_query_is_selected_without_sql_argument_export():
    calls = []
    def call(*args):
        calls.append(args)
        if args[0] == 'sts':
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture'}
        return {'events': [envelope('rds_general')]}
    report = verify(account=ACCOUNT, call=call, now=NOW, sources=(GENERAL_SOURCE,))
    assert len(report['sources']) == 1 and report['sources'][0]['status'] == 'verified'
    metadata = report['sources'][0]['document']['aws']['service_logs']
    assert metadata['command'] == 'Query' and metadata['statement_type'] == 'SELECT'
    assert CANARY not in json.dumps(report)
    assert 'Query' in calls[-1] and '--filter-pattern' in calls[-1]


def test_sample_verification_includes_recently_delivered_events_without_polling_lag():
    calls = []
    def call(*args):
        calls.append(args)
        if args[0] == 'sts':
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture'}
        event = envelope('rds_general')
        event['timestamp'] = int((NOW - timedelta(seconds=30)).timestamp()*1000)
        return {'events': [event]}
    report = verify(account=ACCOUNT, call=call, now=NOW, sources=(GENERAL_SOURCE,))
    assert report['sources'][0]['status'] == 'verified'
    request = calls[-1]
    assert int(request[request.index('--end-time') + 1]) == int(NOW.timestamp()*1000)


def test_firewall_samples_use_native_alert_and_flow_filters_and_keep_payload_private():
    calls = []
    def call(*args):
        calls.append(args)
        if args[0] == 'sts':
            return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/fixture'}
        group = args[args.index('--log-group-name') + 1]
        source = next(s for s in FIREWALL_SOURCES if s['group'] == group)
        event = envelope(source['kind'])
        body = json.loads(event['message'])
        body['firewall_name'] = source['resource']
        event['message'] = json.dumps(body)
        return {'events': [event]}
    window = (int((NOW - timedelta(hours=1)).timestamp()*1000), int(NOW.timestamp()*1000))
    report = verify(account=ACCOUNT, call=call, now=NOW, sources=FIREWALL_SOURCES, window=window)
    assert [s['status'] for s in report['sources']] == ['verified', 'verified']
    assert CANARY not in json.dumps(report)
    assert report['window'] == {'start_ms': window[0], 'end_ms': window[1]}
    for request, event_type in zip(calls[1:], ('alert', 'netflow')):
        pattern = request[request.index('--filter-pattern') + 1]
        assert f'$.event.event_type = "{event_type}"' in pattern
        assert '$.event.src_ip = "10.250.10.156"' in pattern and '$.event.dest_port = 443' in pattern
    assert '1000001' in calls[1][calls[1].index('--filter-pattern') + 1]
    assert {c[1] for c in calls} == {'get-caller-identity', 'filter-log-events'}


@pytest.mark.parametrize('window', [(True, 1000), (-1, 1000), (10, 10), (1000, 0),
                                    (0, 172800001), (0, int(NOW.timestamp()*1000)+1)])
def test_invalid_custom_sample_window_is_rejected_before_aws(window):
    with pytest.raises(VerificationError, match='invalid_sample_window'):
        verify(account=ACCOUNT, now=NOW, window=window, call=lambda *a: pytest.fail('AWS contacted'))


@pytest.mark.parametrize('mode', ['repeat_token', 'page_limit', 'wrong_time', 'invalid_body'])
def test_incomplete_or_invalid_sample_is_not_exported(mode):
    event = deepcopy(envelope('route53_resolver'))
    if mode == 'wrong_time': event['timestamp'] = int((NOW + timedelta(days=1)).timestamp()*1000)
    if mode == 'invalid_body': event['message'] = CANARY
    def call(*args):
        return {'events': [], 'nextToken': 'same'} if mode in ('repeat_token', 'page_limit') else {'events': [event]}
    with pytest.raises(VerificationError):
        sample(SOURCES[0], account=ACCOUNT, organization='fixture', start=0,
               end=int(NOW.timestamp()*1000), call=call, sleep=lambda _: None,
               max_pages=1 if mode == 'page_limit' else 2)
