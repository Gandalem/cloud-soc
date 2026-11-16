import pytest

from cloud_soc.portal.log_query import project_list_hit
from cloud_soc.processing.contract import normalize


STAMP = '2026-11-14T03:36:33Z'


def hit(**source):
    return {'_index': 'soc-host-raw-linux-fixture', '_id': 'test-audit',
            '_source': {'@timestamp': STAMP, 'event': {'ingested': STAMP},
                        'organization': {'id': 'fixture'}, **source}}


@pytest.mark.parametrize(('check', 'category'), [
    ('secure_configuration', 'A02'), ('dependency_provenance', 'A03'),
    ('cryptographic_policy', 'A04'), ('business_invariant', 'A06'),
    ('artifact_integrity', 'A08'), ('exception_fail_open', 'A10'),
])
def test_application_checks_require_a_validated_failed_observation(check, category):
    document = hit(labels={'log_source': 'application_security_audit'}, service={'id': 'site-1'},
                   application_security={'schema': 1, 'check': check, 'result': 'fail'})
    _, record, event = normalize(document, STAMP)
    assert record['status'] == 'normalized'
    assert [item['category'] for item in event['cloud_soc']['owasp']] == [category + ':2025']
    document['_source']['application_security']['result'] = 'pass'
    assert 'owasp' not in normalize(document, STAMP)[2]['cloud_soc']
    document['_source']['application_security']['schema'] = True
    assert normalize(document, STAMP)[1]['status'] == 'invalid'


def test_journal_service_activity_is_interpreted_without_an_owasp_signal():
    document = hit(labels={'log_source': 'linux_journald'}, systemd={'transport': 'audit'},
                   journald={'custom': {'audit_type': '1130'}},
                   message='SERVICE_START pid=1 msg=\'unit=private-unit res=success\'')
    row = project_list_hit(document)
    assert row['normalization']['action'] == 'linux_audit_service_start'
    _, record, event = normalize(document, STAMP)
    assert record['status'] == 'normalized'
    assert event['event']['outcome'] == 'success'
    assert 'owasp' not in event['cloud_soc']
    assert 'private-unit' not in str(event)
    document['_source']['systemd']['transport'] = 'stdout'
    assert project_list_hit(document)['normalization']['action'] is None


def test_journal_failed_authentication_and_windows_audit_clear_have_specific_evidence():
    document = hit(labels={'log_source': 'linux_journald'}, systemd={'transport': 'audit'},
                   journald={'custom': {'audit_type': 1100}},
                   message='USER_AUTH pid=10 msg=\'res=failed\'')
    event = normalize(document, STAMP)[2]
    assert event['cloud_soc']['owasp'][0]['category'] == 'A07:2025'
    document['_source']['message'] = 'SERVICE_START pid=10 res=failed'
    assert 'owasp' not in normalize(document, STAMP)[2]['cloud_soc']

    windows = hit(labels={'log_source': 'windows_event'}, winlog={
        'channel': 'Security', 'provider_name': 'Microsoft-Windows-Eventlog', 'event_id': 1102,
    })
    assert project_list_hit(windows)['normalization']['owasp'][0]['category'] == 'A09:2025'
    windows['_source']['winlog']['provider_name'] = 'unrelated'
    assert project_list_hit(windows)['normalization']['owasp'] == []


def test_owasp_signatures_require_a_validated_source_and_specific_metadata():
    from cloud_soc.portal.owasp import signals

    assert signals('security_mall_audit_v1', {'authorization_reason': 'not_owner'},
                   'order_view', 'failure')[0]['category'] == 'A01:2025'
    assert not signals('security_mall_audit_v1', {'authorization_reason': 'not_found'}, 'order_view', 'failure')
    assert signals('modsecurity_audit_v1', {'sqli': True},
                   'waf_rule_match', 'unknown')[0]['category'] == 'A05:2025'
    assert not signals('modsecurity_audit_v1', {'sqli': 'true'}, 'waf_rule_match', 'unknown')
    assert not signals('packetbeat_metadata_v1', {'sqli': True}, 'traffic_observed', 'unknown')
