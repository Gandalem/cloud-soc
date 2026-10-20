"""Generic ModSecurity metadata, privacy and tenant/site isolation contracts."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import io
import json
import tarfile
from unittest.mock import patch

import pytest

from cloud_soc.detection.engine import detect_rule
from cloud_soc.detection.profiles import select, source_observed
from cloud_soc.detection.patterns import evaluate_pattern
from cloud_soc.pipeline.alerts import build_security_alert
from cloud_soc.portal.log_query import project_list_hit
from cloud_soc.portal.packages import build_bundle
from cloud_soc.processing.contract import normalize, NORMALIZED
from cloud_soc.web.modsecurity import SQLI_IDS, validate
from test_site_agents import web_hit, spec, ROOT, SITE

BASE = datetime(2026, 10, 19, tzinfo=timezone.utc)
RULE_ID = 'WEB-SITE-WAF-001'


def waf_hit(number=0, *, site='site-a', mode='DetectionOnly', interruption='unknown', ids=('942100',), version='4.9.0'):
    hit = web_hit()
    hit['_id'] = f'waf-{number}'
    source = hit['_source']
    source.pop('web')
    stamp = (BASE + timedelta(seconds=number)).isoformat()
    source.update({'@timestamp': stamp, 'service': {'id': site, 'name': 'Generic public website'},
        'labels': {'log_source': 'generic_modsecurity', 'privacy_policy': 'modsecurity-metadata-v1'},
        'event': {'ingested': stamp, 'category': ['web'], 'action': 'waf_rule_match',
                  'dataset': 'cloud_soc.modsecurity', 'outcome': 'unknown'},
        'http': {'request': {'id': f'generic-request-{number}', 'method': 'GET'}, 'response': {'status_code': 403}},
        'waf': {'schema': 'modsecurity-metadata-v1', 'engine_mode': mode, 'interruption': interruption,
                'rules': [{'id': item, 'crs_version': version} for item in ids]}})
    return hit


def normalized(number=0, **options):
    hit = waf_hit(number, **options)
    key, record, event = normalize(hit, (BASE + timedelta(minutes=1)).isoformat())
    assert record['status'] == 'normalized', record
    event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': key}
    return event


def rule():
    return select(rule_ids=[RULE_ID], retain_auth=False)[0]


@pytest.mark.parametrize('identifier', sorted(SQLI_IDS))
@pytest.mark.parametrize('version', ['3.3.5', '4.9.0'])
def test_allowlisted_crs_sqli_three_distinct_requests_and_modes(identifier, version):
    rows = [normalized(n, ids=(identifier,), version=version) for n in range(3)]
    assert not detect_rule(rows[:2], rule())
    result, = detect_rule(rows, rule())
    alert = build_security_alert(result)
    assert result['assessment']['waf'] == {
        'engine_modes': ['DetectionOnly'], 'interruption_states': ['unknown'],
        'matched_rule_ids': [identifier], 'blocking_result': 'not_established', 'application_outcome': 'not_established'}
    assert alert['service']['id'] == 'site-a' and alert['host']['id'] == 'fixture-host'
    assert source_observed(rows[0], RULE_ID)


def test_dedup_is_per_scoped_request_not_rule_match_or_normalization_revision():
    rows = [normalized(0, ids=('942100', '942140')) for _ in range(3)]
    for i, event in enumerate(rows):
        event['_cloud_soc_meta']['document_id'] += str(i)
        event['cloud_soc']['provenance']['raw']['id'] += str(i)
    assert not detect_rule(rows, rule())
    rows = [normalized(n, site='site-a' if n < 2 else 'site-b') for n in range(3)]
    assert not detect_rule(rows, rule())


@pytest.mark.parametrize('mode,interruption', [('On', 'observed'), ('On', 'not_observed'), ('On', 'unknown'), ('DetectionOnly', 'not_observed')])
def test_engine_interruption_never_proves_application_blocking(mode, interruption):
    result, = detect_rule([normalized(n, mode=mode, interruption=interruption) for n in range(3)], rule())
    assert result['assessment']['waf']['interruption_states'] == [interruption]
    assert result['assessment']['waf']['blocking_result'] == 'not_established'


@pytest.mark.parametrize('options', [dict(ids=('10002',)), dict(ids=('949110',)), dict(version=None), dict(mode='Off')])
def test_unrelated_control_unversioned_custom_and_disabled_rules_do_not_match(options):
    assert not detect_rule([normalized(n, **options) for n in range(3)], rule())


@pytest.mark.parametrize('change', [
    lambda s: s['waf'].update(interruption='observed'),
    lambda s: s['waf'].update(body='PRIVATE_CANARY'),
    lambda s: s['waf']['rules'][0].update(message='PRIVATE_CANARY'),
    lambda s: s['waf']['rules'].append(deepcopy(s['waf']['rules'][0])),
    lambda s: s['http']['request'].update(headers={'Cookie': 'PRIVATE_CANARY'}),
    lambda s: s['http']['request'].update(id='bad request id'),
    lambda s: s['event'].update(outcome='success'),
    lambda s: s['service'].update(id='../other'),
])
def test_malformed_or_payload_bearing_projected_metadata_is_rejected(change):
    source = waf_hit()['_source']
    change(source)
    with pytest.raises(ValueError):
        validate(source)


def test_missing_waf_fields_cannot_crash_worker_or_become_positive():
    event = normalized()
    event.pop('waf')
    assert evaluate_pattern(event, rule())[0] in ('unknown', 'not_matched')


def test_site_bundle_has_independent_metadata_only_waf_input_and_offset():
    settings = spec(sites=[{**SITE, 'modsecurity': {'log_path': '/var/log/modsecurity/audit.json', 'timezone': '+09:00'}}])
    blob, _ = build_bundle(settings, ROOT / 'deploy/agents', b'SYNTHETIC CA')
    with tarfile.open(fileobj=io.BytesIO(blob)) as archive:
        compiled = json.load(archive.extractfile('collection-profile.json'))
    access, waf = compiled['web_inputs']
    assert access['fields']['labels']['log_source'] == 'generic_web_access'
    assert waf['fields']['labels']['log_source'] == 'generic_modsecurity'
    assert waf['processors'][0]['script']['params']['timezone'] == '+09:00'
    assert '/var/log/modsecurity' in compiled['web_exclusions']
    row = project_list_hit(waf_hit())
    assert row['source_kind'] == 'generic_modsecurity' and row['parse_status'] == 'recognized'


@pytest.mark.parametrize('modsecurity', [
    {'log_path': '/etc/passwd', 'timezone': '+00:00'},
    {'log_path': SITE['log_path'], 'timezone': '+00:00'},
    {'log_path': '/var/log/modsecurity/audit.json', 'timezone': 'local'},
    {'log_path': '/var/log/modsecurity/audit.json', 'timezone': '+14:30'},
])
def test_waf_path_and_timezone_must_be_explicit_safe_and_separate(modsecurity):
    with pytest.raises(ValueError):
        spec(sites=[{**SITE, 'modsecurity': modsecurity}])


def test_access_and_waf_switch_together_without_resetting_collector_state(tmp_path):
    import importlib.util
    from cloud_soc.portal.site_agents import profile
    settings = spec(sites=[{**SITE, 'modsecurity': {'log_path': '/var/log/modsecurity/audit.json', 'timezone': '+00:00'}}])
    path = tmp_path / 'collection-profile.json'
    path.write_text(json.dumps(profile(settings)))
    (tmp_path / 'collection-switches.json').write_text(json.dumps({'web': {'dvwa': False}}))
    loader = importlib.util.spec_from_file_location('waf_profile_reader', ROOT / 'deploy/agents/profile-reader.py')
    module = importlib.util.module_from_spec(loader); loader.loader.exec_module(module)
    with patch.object(module, '__name__', 'waf_profile_reader'):
        assert all(not value['enabled'] for value in module.read(path)['web_inputs'])


@pytest.mark.parametrize('identifier', ['WEB-SITE-WAF-001', 'WEB-SITE-404-001'])
def test_actual_generic_detection_enters_existing_slack_message_contract(identifier):
    from ruleset_fixtures import positive
    from cloud_soc.pipeline.alerts import make_alert_id
    from cloud_soc.notifications.worker import event as notification
    selected = select(rule_ids=[identifier], retain_auth=False)[0]
    detection, = detect_rule(positive(identifier), selected)
    alert = build_security_alert(detection)
    item = notification('security-alerts', {'_id': make_alert_id(detection), '_source': alert},
                        portal_url='https://soc.example.test')
    assert item['kind'] == 'final' and identifier in item['payload']['text']
    assert selected['alert']['title'] in item['payload']['text']
    assert 'workbench.html' in json.dumps(item['payload'])
