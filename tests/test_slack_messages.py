"""New message presentation without production sends or ledger migrations."""
from copy import deepcopy
import json
from pathlib import Path
import re
from unittest.mock import Mock
from urllib.parse import parse_qs, urlsplit

import pytest
import yaml

from cloud_soc.notifications.messages import connection_test, example_alert, origin
from cloud_soc.notifications.store import SlackStore
from cloud_soc.notifications.transport import Result, SlackError, send
from cloud_soc.notifications.worker import INDICES, Source, deliver, event, scan
from test_slack_notifications import URL, MemorySource, configured, final, notice

PORTAL = 'https://soc.example.test:8443'
ALERT_ID = '2a9021c7afe12cfe5fe7ce28a541e2b3e61d3da769d3947dcd5a5b0c469fccb6'


def visible(payload):
    """Include notification/screen-reader text, headers, fields and button labels, excluding URLs."""
    result = [payload['text']]
    for block in payload.get('blocks', []):
        if 'text' in block:
            value = block['text']['text']
            result.append(re.sub(r'<https?://[^|>]+\|([^>]+)>', r'\1', value)
                          if block['text']['type'] == 'mrkdwn' else value)
        result += [field['text'] for field in block.get('fields', [])]
        result += [element['text']['text'] for element in block.get('elements', [])]
    return '\n'.join(result)


def assert_block_limits(payload):
    assert len(json.dumps(payload, ensure_ascii=True).encode()) <= 12000
    assert len(payload['blocks']) <= 50
    for block in payload['blocks']:
        if block['type'] == 'header':
            assert 1 <= len(block['text']['text']) <= 150
        if block['type'] == 'section':
            assert len(block.get('fields', [])) <= 10
            assert all(1 <= len(field['text']) <= 2000 for field in block.get('fields', []))
            if 'text' in block:
                assert 1 <= len(block['text']['text']) <= 3000


def detail_link(payload):
    return re.fullmatch(r'<([^|>]+)\|([^>]+)>', payload['blocks'][-1]['text']['text']).groups()


def test_connection_test_is_concise_and_keeps_internal_test_identity(tmp_path):
    store, _ = configured(tmp_path)
    result = store.test()
    with store.connect() as db:
        row = dict(db.execute('select * from outbox').fetchone())
    payload = json.loads(row['payload'])
    assert row['id'] == row['source_id'] == result['test_id']
    assert result['test_id'] not in json.dumps(payload)
    assert payload['text'] == '✅ Cloud SOC 연결 테스트 성공\nSlack 알림이 정상적으로 연결되었습니다.'
    assert payload == connection_test()
    assert_block_limits(payload)


def test_operator_example_is_unambiguously_synthetic_in_blocks_and_fallback_and_is_not_a_detection():
    payload = example_alert(reference_id=ALERT_ID, portal_url=PORTAL)
    assert '[테스트 예시]' in payload['text'] and '[테스트 예시]' in payload['blocks'][0]['text']['text']
    assert '실제 탐지 아님' in payload['text']
    fields = payload['blocks'][1]['fields']
    assert '10건 (예시)' in fields[2]['text'] and '실제 탐지 아님' in fields[3]['text']
    assert '기존 경보의 참고 화면' in visible(payload)
    assert '발생 시각\n해당 없음 (테스트 예시)' in visible(payload)
    assert ALERT_ID not in visible(payload)
    url, label = detail_link(payload)
    assert parse_qs(urlsplit(url).query) == {'alert': [ALERT_ID]} and label == '경보 자세히 보기'
    assert_block_limits(payload)


def test_auth_alert_has_clear_fields_and_exact_detail_link_without_visible_identity():
    hit = final(1, identifier=ALERT_ID, rule='AUTH-001')
    hit['_source']['cloud_soc'].update(alert_title='Old technical title', risk_level='high')
    item = event(INDICES[0], hit, portal_url=PORTAL)
    payload = item['payload']
    assert item['id'] == ALERT_ID and item['revision'] == 0 and item['state'] == 'final'
    assert payload['blocks'][0]['text']['text'] == 'SSH 로그인 실패 집중 탐지'
    fields = [x['text'] for x in payload['blocks'][1]['fields']]
    assert fields == ['위험도\n🟠 HIGH', '룰 ID\nAUTH-001', '관측 건수\n10건',
                      '알림 유형\n최종 경보', '발생 시각\n2020-01-01 09:00:00 KST']
    assert ALERT_ID not in visible(payload)
    assert '공격 성공' not in visible(payload)
    url, label = detail_link(payload)
    assert label == '경보 자세히 보기'
    parsed = urlsplit(url)
    assert parsed.scheme + '://' + parsed.netloc == PORTAL
    assert parsed.path == '/workbench.html' and parse_qs(parsed.query) == {'alert': [ALERT_ID]}
    assert payload['unfurl_links'] is False and payload['unfurl_media'] is False
    assert_block_limits(payload)



def test_final_alert_uses_last_observed_window_time_not_send_time():
    hit = final(1)
    hit['_source']['@timestamp'] = '2026-10-18T14:30:00Z'
    hit['_source']['cloud_soc']['window_end'] = '2026-10-18T03:59:16.999999Z'
    payload = event(INDICES[0], hit)['payload']
    assert '발생 시각: 2026-10-18 12:59:16 KST' in payload['text']
    assert '발생 시각\\n2026-10-18 12:59:16 KST' in visible(payload)
    assert '2026-10-18 23:30:00 KST' not in visible(payload)


def test_early_notice_uses_observed_window_time_not_notice_revision_time():
    hit = notice(1, state='verifying')
    hit['_source']['@timestamp'] = '2026-10-18T13:29:00Z'
    hit['_source']['body']['window_end'] = '2026-10-18T03:59:16+00:00'
    payload = event(INDICES[1], hit)['payload']
    assert '발생 시각: 2026-10-18 12:59:16 KST' in payload['text']
    assert '2026-10-18 22:29:00 KST' not in visible(payload)


@pytest.mark.parametrize('value', [
    None, 123, '2026-10-18T03:59:16', '2026-10-99T03:59:16Z',
    '<!here>\\nSENSITIVE_TIME', 'Z' * 200,
])
def test_missing_or_invalid_occurrence_time_is_not_invented(value):
    hit = final(1)
    hit['_source']['@timestamp'] = value
    payload = event(INDICES[0], hit)['payload']
    assert '발생 시각: 미기록' in payload['text']
    assert '발생 시각\\n미기록' in visible(payload)
    assert 'SENSITIVE_TIME' not in json.dumps(payload)
    assert_block_limits(payload)


@pytest.mark.parametrize('rule,title', [('SQLI-FUTURE', 'SQL Injection 요청 탐지'), ('XSS-FUTURE', 'XSS 요청 탐지'),
    ('WIN-AUTH-001', 'Windows 로그인 실패 탐지'), ('NET-FUTURE', '네트워크 연결 집중 탐지'),
    ('NEW-RULE-999', '새 탐지 룰 제목')])
@pytest.mark.parametrize('severity', ['low', 'medium', 'high', 'critical'])
def test_every_rule_and_severity_use_the_same_metadata_driven_format(rule, title, severity):
    hit = final(1, rule=rule, severity=severity)
    hit['_source']['cloud_soc']['alert_title'] = title
    payload = event(INDICES[0], hit, portal_url=PORTAL)['payload']
    assert payload['blocks'][0]['text']['text'] == title
    assert rule in visible(payload) and severity.upper() in visible(payload)
    assert [block['type'] for block in payload['blocks']] == ['header', 'section', 'section']
    assert_block_limits(payload)


def test_missing_metadata_uses_neutral_title_and_never_claims_success():
    hit = final(1)
    hit['_source']['cloud_soc']['event_count'] = None
    payload = event(INDICES[0], hit)['payload']
    assert payload['blocks'][0]['text']['text'] == '보안 이벤트 탐지'
    assert '관측 건수\n미기록' in visible(payload)
    assert '성공' not in visible(payload)
    assert not any(block['type'] == 'actions' for block in payload['blocks'])
    hit['_source']['rule']['name'] = '저장된 룰 이름'
    assert event(INDICES[0], hit)['payload']['blocks'][0]['text']['text'] == '저장된 룰 이름'


@pytest.mark.parametrize('state,label', [('initial', '초기 탐지'), ('verifying', '근거 검증 중'),
    ('delayed', '검증 지연'), ('confirmed', '근거 확정'), ('corrected', '초기 판단 정정')])
def test_notice_is_distinct_from_final_and_does_not_link_to_a_nonexistent_final(state, label):
    hit = notice(1, state=state, rule_id='AUTH-001')
    item = event(INDICES[1], hit, portal_url=PORTAL)
    assert item['id'] == 'logical-notice' and item['revision'] == 1 and item['state'] == state
    assert 'logical-notice' not in visible(item['payload'])
    assert '초기 통지 · ' + label in visible(item['payload'])
    url, label = detail_link(item['payload'])
    assert url == PORTAL + '/index.html' and label == '초기 통지 목록 보기'
    if state == 'confirmed':
        hit['_source']['body']['final_alert_id'] = ALERT_ID
        assert event(INDICES[1], hit, portal_url=PORTAL) is None


def test_untrusted_metadata_is_literal_bounded_and_does_not_include_logs_or_supplied_urls():
    hit = final(1, identifier='id:with.encoded:parts', rule='<@U123> & <!channel>')
    hit['_source']['cloud_soc'].update(alert_title='<!here>\n<https://evil.test|click>\x00' + '😀' * 500,
                                     event_count={'secret': 'DO_NOT_SEND'}, portal_url='https://evil.test')
    hit['_source'].update(message='SENSITIVE_LOG', evidence={'token': 'SENSITIVE_KEY'})
    original = deepcopy(hit)
    payload = event(INDICES[0], hit, portal_url=PORTAL)['payload']
    assert hit == original
    assert '<!here>' not in payload['text'] and '&lt;!here&gt;' in payload['text']
    for block in payload['blocks'][:2]:
        objects = [block['text']] if 'text' in block else block['fields']
        assert all(obj['type'] == 'plain_text' for obj in objects)
        assert all('\x00' not in obj['text'] for obj in objects)
    encoded = json.dumps(payload)
    assert all(word not in encoded for word in ['SENSITIVE_LOG', 'SENSITIVE_KEY', 'DO_NOT_SEND'])
    url, _ = detail_link(payload)
    assert url == PORTAL + '/workbench.html?alert=id%3Awith.encoded%3Aparts'
    assert_block_limits(payload)


@pytest.mark.parametrize('title', ['😀' * 500, '&' * 500, '<' * 500, '가' * 500])
def test_maximum_metadata_fits_existing_transport_budget(title):
    hit = final(1, identifier='a' * 256, rule=title)
    hit['_source']['cloud_soc']['alert_title'] = title
    assert_block_limits(event(INDICES[0], hit, portal_url=PORTAL)['payload'])


@pytest.mark.parametrize('value', ['https://soc.example.test', 'https://soc.example.test:8443/',
    'https://192.168.235.128', 'https://[2001:db8::1]:8443', 'http://localhost:5000'])
def test_portal_links_use_configured_origins_without_network_requests(value):
    assert origin(value) == value.rstrip('/')


@pytest.mark.parametrize('value', ['http://soc.example.test', 'javascript:alert(1)', '//evil.test',
    'https://user:password@soc.example.test', 'https://soc.example.test/other', 'https://soc.example.test?x=1',
    'https://soc.example.test#secret', 'https://soc.example.test:99999', 'https://soc.example.test:0',
    'https://soc.example.test\n', 'https://soc.example.test\\@evil.test', 'https://soc.example.test|bad',
    'https://soc.example.test/<x>', 'https://%65vil.test', None, 123, ''])
def test_unsafe_link_origins_are_rejected(value):
    with pytest.raises(SlackError, match='notification_portal_origin_invalid'):
        origin(value)


def test_scan_delivers_only_new_format_keeps_saved_history_keys_and_dedup(tmp_path, monkeypatch):
    monkeypatch.setenv('SOC_PUBLIC_URL', PORTAL)
    store, clock = configured(tmp_path)
    source = MemorySource()
    scan(store, source)
    old_payload = {'text': 'Legacy immutable payload · legacy-id'}
    with store.connect() as db:
        cfg = db.execute('select * from config where id=1').fetchone()
        store.enqueue(db, cfg, 'legacy', 'final', 'legacy-id', 0, 'final', 'high', old_payload)
        db.execute("update outbox set status='sent',attempts=1")
        old = tuple(db.execute('select * from outbox').fetchone())
        config = tuple(db.execute('select * from config').fetchone())
    key = (store.directory / 'slack.key').read_bytes()
    source.docs[INDICES[0]][0].append(final(1, identifier=ALERT_ID, rule='AUTH-001'))
    scan(store, source)
    sender = Mock(return_value=Result('sent', 'slack_accepted'))
    deliver(store, sender=sender)
    restarted = SlackStore(store.directory, clock=lambda: clock[0])
    restarted.recover()
    scan(restarted, source)
    clock[0] += 2
    deliver(restarted, sender=sender)
    assert sender.call_count == 1 and 'SSH 로그인 실패 집중 탐지' in visible(sender.call_args.args[1])
    with store.connect() as db:
        assert tuple(db.execute("select * from outbox where source_id='legacy-id'").fetchone()) == old
        assert tuple(db.execute('select * from config').fetchone()) == config
        row = db.execute('select * from outbox where source_id=?', (ALERT_ID,)).fetchone()
        assert row['status'] == 'sent' and row['attempts'] == 1 and row['source_id'] == ALERT_ID
    assert (store.directory / 'slack.key').read_bytes() == key
    assert restarted.status()['deliveries'] == {'sent': 2}


def test_scanner_requests_rule_metadata_and_excludes_raw_logs():
    client = Mock()
    client.search.return_value = {'hits': {'hits': []}}
    Source(client).page(INDICES[0], 0, 1)
    fields = client.search.call_args.kwargs['source']
    assert 'rule.name' in fields and 'cloud_soc.alert_title' in fields
    assert '@timestamp' in fields and 'cloud_soc.window_end' in fields
    assert 'message' not in fields and 'cloud_soc.provenance' not in fields


def test_new_install_and_upgrade_pass_portal_origin_only_for_message_links():
    from cloud_soc.deployment.host import site_overlay
    root = Path(__file__).resolve().parents[1]
    compose = yaml.safe_load((root / 'deploy/server/runtime.compose.yaml').read_text())
    cfg = compose['services']['slack-notifier']
    assert cfg['environment']['SOC_PUBLIC_URL'] == 'https://${SOC_PUBLIC_HOST:?Run prepare.py first}'
    assert cfg['mem_limit'] == '64m'
    objects = {'portal': {'Config': {'Env': ['SOC_PUBLIC_URL=' + PORTAL]}}}
    existing = {'services': {'portal': {}, 'elasticsearch': {}}}
    overlay = site_overlay(existing, objects)
    assert overlay['services']['slack-notifier'] == {'environment': {'SOC_PUBLIC_URL': PORTAL}}
    assert overlay['services']['portal']['environment']['SOC_PUBLIC_URL'] == PORTAL


def test_renderer_payload_is_accepted_by_existing_sender_without_real_network(monkeypatch):
    connection = Mock()
    connection.getresponse.return_value.status = 200
    connection.getresponse.return_value.read.return_value = b'ok'
    monkeypatch.setattr('cloud_soc.notifications.transport.PinnedHTTPS', lambda *a, **kw: connection)
    payload = event(INDICES[0], final(1, rule='AUTH-001'), portal_url=PORTAL)['payload']
    result = send(URL, payload)
    assert result.outcome == 'sent'
    assert json.loads(connection.request.call_args.kwargs['body']) == payload
