"""Bounded synthetic privacy/provenance cases; never reads real log files."""
from copy import deepcopy
import json
import pytest

from cloud_soc.parsers.security_mall_edge import (
    EdgeError, DIAGNOSTIC, build_manifest, parse_access, parse_native,
    envelope, identifier, validate, validate_source,
)
from cloud_soc.web.mall_edge_projection import extract, protected_read, write_private, main
from cloud_soc.processing.contract import normalize
from cloud_soc.processing.worker import READ_FIELDS

RID = 'A' * 27
TSV = f'soc-mall-access-v1\t2026-10-16T13:19:40+0000\t127.0.0.1\tGET\t/login\t200\t25\t{RID}\n'
RULE = 'SecRule REQUEST_HEADERS:Host "@rx ^[0-9.]+$" "id:920350,phase:2,block,severity:WARNING,msg:\'no raw data\'"'
MANIFEST = build_manifest([RULE], include_lab_diagnostic=True)


def native(k=RULE, *, request_id=RID):
    return f'--abcd-A--\n[16/Oct/2026:13:19:40 +0000] {request_id} 127.0.0.1 1234 127.0.0.1 18082\n\n--abcd-K--\n{k}\n\n--abcd-Z--\n\n'


def test_access_normalization_reference_duration_and_scope():
    body = parse_access(TSV)
    doc = envelope(body, 'mall-isolated', 'mall-host-isolated')
    doc['event']['ingested'] = '2026-10-16T14:00:00Z'
    hit = {'_index': 'soc-host-raw-mall-edge-unit', '_id': doc['event']['id'], '_source': doc}
    first, record, result = normalize(hit, '2026-10-16T14:01:00Z')
    assert record['status'] == 'normalized'
    assert result['event']['duration'] == 25000
    assert result['http']['request']['id'] == RID
    assert result['url']['path'] == '/login'
    assert result['cloud_soc']['provenance']['raw'] == {'index': hit['_index'], 'id': hit['_id']}
    assert result['event']['id'] == doc['event']['id']
    assert normalize(hit, '2026-10-16T14:02:00Z')[0] == first
    assert result['event']['ingested'] != result['@timestamp']
    assert 'security_mall_edge' in READ_FIELDS


def test_waf_complete_diagnostic_not_blocked_no_raw_data():
    body = parse_native(native(DIAGNOSTIC), MANIFEST)
    assert body['rules'] == [{'id': '10002', 'action': 'pass', 'diagnostic': True}]
    assert body['blocked'] is False
    assert body['engine_mode'] == 'DetectionOnly'
    serialized = json.dumps(body)
    assert all(term not in serialized for term in ['MATCHED_VAR', 'X-WAF-Lab-Check', 'msg:', 'privacy-check'])
    body = parse_native(native(), MANIFEST)
    assert body['rules'][0] == {'id': '920350', 'severity': 'warning', 'action': 'block', 'diagnostic': False}
    # A configured block action is not an executed block in DetectionOnly.
    assert body['blocked'] is False


@pytest.mark.parametrize('change', [
    lambda s: s.replace('/login', '/login?private=CANARY'),
    lambda s: s.replace('/login', '/CANARY'),
    lambda s: s.replace('200\t', '999\t'),
    lambda s: s.replace('2026-10-16', '2026-02-30'),
    lambda s: s.rstrip('\n'),
    lambda s: s + 'CANARY',
])
def test_bad_access(change):
    with pytest.raises(EdgeError) as error:
        parse_access(change(TSV))
    assert 'CANARY' not in str(error.value)


@pytest.mark.parametrize('change', [
    lambda s: s.replace('-K--', '-B--'),
    lambda s: s.replace('--abcd-Z--', '--other-Z--'),
    lambda s: s.split('--abcd-Z--')[0],
    lambda s: s.replace('no raw data', 'CANARY_SECRET'),
    lambda s: s.replace('127.0.0.1 1234', '127.0.0.1 /login?CANARY'),
    lambda s: s + 'CANARY_SECRET\n',
])
def test_bad_native_fixed_errors(change):
    with pytest.raises(EdgeError) as error:
        parse_native(change(native()), MANIFEST)
    assert 'CANARY' not in str(error.value)


def test_partial_chain_not_reported_and_rotation_not_stitched():
    lines = DIAGNOSTIC.splitlines()
    with pytest.raises(EdgeError, match='edge_no_complete_rule_match'):
        parse_native(native(lines[0] + '\n#' + lines[1]), MANIFEST)
    whole = native()
    left, right = whole.split('--abcd-K--')
    events, rejected = extract([TSV], [left, '--abcd-K--' + right], MANIFEST, 'org', 'host')
    assert len(events) == 1
    assert sum(rejected.values()) == 2
    events, rejected = extract([], [whole, whole], MANIFEST, 'org', 'host')
    assert not rejected and len(events) == 2
    assert events[0]['event']['id'] == events[1]['event']['id']


def test_native_chain_child_without_actions_and_shared_child():
    child = 'SecRule ARGS:canary "@rx ^[a-z]+$"'
    starter = 'SecRule REQUEST_METHOD "@streq GET" "id:910001,chain,pass,severity:NOTICE"'
    other = 'SecRule REQUEST_METHOD "@streq POST" "id:910002,chain,pass,severity:NOTICE"'
    manifest = build_manifest([starter + '\n' + child, other + '\n' + child])
    assert parse_native(native(starter + '\n' + child), manifest)['rules'][0]['id'] == '910001'


def test_apache_decoded_literal_quote_is_not_reparsed_as_shell_action_syntax():
    rule = '''SecRule ARGS:value "@rx ^[a-z]+$" "id:920490,pass,severity:'WARNING',msg:'Literal \\' quote, value'"'''
    manifest = build_manifest([rule])
    assert parse_native(native(rule), manifest)['rules'][0]['severity'] == 'warning'


def test_native_microsecond_timestamp_and_waf_normalization():
    body = parse_native(native().replace('13:19:40 +0000', '13:19:40.100377 +0000'), MANIFEST)
    assert body['timestamp'] == '2026-10-16T13:19:40.100377Z'
    source = envelope(body, 'org', 'host')
    source['event']['ingested'] = '2026-10-16T14:00:00Z'
    _, record, event = normalize({'_index': 'soc-host-raw-mall-edge-unit', '_id': 'safe', '_source': source},
                                  '2026-10-16T14:01:00Z')
    assert record['status'] == 'normalized'
    assert event['event']['action'] == 'waf_rule_match' and event['event']['outcome'] == 'unknown'
    assert event['cloud_soc']['security_mall_edge']['blocked'] is False


def test_native_inherited_logging_and_optional_parameter_quotes():
    configured = RULE.replace('severity:WARNING', "severity:'WARNING',ver:'OWASP_CRS/3.3.5'")
    emitted = RULE.replace('id:920350,phase:2', 'phase:2,nolog,auditlog,id:920350').replace(
        'severity:WARNING', 'severity:WARNING,ver:OWASP_CRS/3.3.5')
    assert parse_native(native(emitted), build_manifest([configured]))['rules'][0]['id'] == '920350'


def test_argumentless_operator_native_trailing_separator_and_control_filter():
    configured = 'SecRule REQUEST_BODY "@validateUrlEncoding" "id:920240,pass,severity:WARNING"'
    emitted = configured.replace('@validateUrlEncoding"', '@validateUrlEncoding "')
    assert parse_native(native(emitted), build_manifest([configured]))['rules'][0]['id'] == '920240'
    control = 'SecRule TX:paranoia "@lt 1" "id:920013,pass,skipAfter:END"'
    rules = parse_native(native(control + '\n' + RULE), build_manifest([control, RULE]))['rules']
    assert [r['id'] for r in rules] == ['920350']


@pytest.mark.parametrize('field,value', [('message', 'CANARY'), ('method', []), ('path', '/private'), ('request_id', None)])
def test_payload_unknown_fields_and_types(field, value):
    body = parse_access(TSV)
    body[field] = value
    with pytest.raises(EdgeError):
        validate(body)


def test_identity_scope_stream_and_claimed_envelope():
    body = parse_access(TSV)
    assert identifier(body, 'org', 'host') != identifier(body, 'other', 'host')
    assert identifier(body, 'org', 'host') != identifier(parse_native(native(), MANIFEST), 'org', 'host')
    doc = envelope(body, 'org', 'host')
    assert validate_source(doc, received=False) == body
    for group, field, value in [('event', 'id', 'b' * 64), ('organization', 'id', 'other'), ('host', 'id', 'other')]:
        invalid = deepcopy(doc)
        invalid[group][field] = value
        with pytest.raises(EdgeError):
            validate_source(invalid, received=False)


def test_server_receipt_can_have_nanoseconds_without_relaxing_source_time():
    source = envelope(parse_access(TSV), 'org', 'host')
    source['event']['ingested'] = '2026-10-16T14:00:00.123456789Z'
    assert validate_source(source)['timestamp'] == '2026-10-16T13:19:40Z'
    with pytest.raises(EdgeError):
        body = parse_access(TSV)
        body['timestamp'] = source['event']['ingested']
        validate(body)


@pytest.mark.parametrize('part', ['C', 'E', 'H'])
def test_body_response_or_matching_sections_never_leave_parser(part):
    bad = native().replace('--abcd-Z--', '--abcd-' + part + '--\nHARMLESS_PRIVATE_CANARY\n--abcd-Z--')
    with pytest.raises(EdgeError) as error:
        parse_native(bad, MANIFEST)
    assert 'HARMLESS_PRIVATE_CANARY' not in str(error.value)


def test_malformed_setup_directive_is_rejected_without_raw_text():
    bad = native('SecAction "HARMLESS_PRIVATE_CANARY\n' + RULE)
    with pytest.raises(EdgeError, match='edge_rule_syntax'):
        parse_native(bad, MANIFEST)


def test_setup_only_native_transaction_is_not_invented_as_a_rule_match():
    with pytest.raises(EdgeError, match='edge_no_complete_rule_match'):
        parse_native(native('SecAction "id:10001,phase:5,pass,nolog,noauditlog"'), MANIFEST)


def test_private_output_existing_file_and_error_redaction(tmp_path, capsys):
    tmp_path.chmod(0o700)
    source = tmp_path / 'source'
    source.write_text(TSV, newline='\n')
    source.chmod(0o600)
    assert protected_read(source) == TSV
    out = tmp_path / 'out.jsonl'
    write_private(out, [envelope(parse_access(TSV), 'org', 'host')])
    with pytest.raises(EdgeError, match='edge_output_exists'):
        write_private(out, [])
    assert out.stat().st_size > 0
    assert main(['--access', str(tmp_path / 'CANARY_SECRET'), '--crs-directory', str(tmp_path),
                 '--organization', 'org', '--host', 'host', '--output', str(out)]) == 1
    assert 'CANARY_SECRET' not in capsys.readouterr().err
