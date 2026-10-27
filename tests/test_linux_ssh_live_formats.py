from copy import deepcopy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import json
import tempfile
from unittest.mock import Mock

import pytest
from cloud_soc.detection.engine import detect_rule, ssh_collection_mirror
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.processing.contract import normalize, NORMALIZED
from cloud_soc.processing.worker import run_once, READ_FIELDS
from cloud_soc.parsers.linux_security import parse_linux_ssh_source
from test_intake_detection import client_for

BASE = datetime(2026, 10, 12, 12, tzinfo=timezone.utc)
RULE = next(r for r in load_rules() if r['id'] == 'AUTH-001')


def raw(i=0, origin='journald', outcome='failure'):
    stamp = BASE + timedelta(seconds=i, microseconds=123456)
    body = (f'Failed password for fixture from 192.0.2.177 port {40000+i} ssh2' if outcome == 'failure'
            else f'Accepted password for fixture from 192.0.2.177 port {40000+i} ssh2')
    s = {'@timestamp': stamp.isoformat(timespec='milliseconds'), 'organization': {'id': 'team-a'},
         'host': {'id': 'fixture-host'}, 'event': {'ingested': (BASE+timedelta(seconds=20)).isoformat()},
         'labels': {'log_source': 'linux_journald' if origin == 'journald' else 'linux_file'}}
    if origin == 'journald':
        s.update(message=body, journald={'process': {'name': 'sshd'}, 'pid': 100+i})
    else:
        s.update(message=f'{stamp.isoformat()} fixture sshd[{100+i}]: {body}', log={'file': {'path': '/var/log/auth.log'}})
    return {'_index': 'soc-host-raw-demo', '_id': f'{origin}-{i}-{outcome}', '_source': s}


def event(hit):
    id, rec, body = normalize(hit, (BASE+timedelta(seconds=20)).isoformat())
    assert rec['status'] == 'normalized'
    body['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': id}
    return body


def test_modern_formats_real_time_lineage_and_no_message():
    a, b = event(raw()), event(raw(origin='rfc3339'))
    assert a['network']['protocol'] == b['network']['protocol'] == 'ssh'
    assert a['cloud_soc']['observation']['id'] == b['cloud_soc']['observation']['id']
    assert a['cloud_soc']['provenance']['raw']['id'] != b['cloud_soc']['provenance']['raw']['id']
    assert a['@timestamp'] == '2026-10-12T12:00:00.123000Z'
    assert b['@timestamp'] == '2026-10-12T12:00:00.123456Z'
    assert 'message' not in a and 'message' not in b
    assert {'journald.process.name', 'journald.pid'} <= set(READ_FIELDS)


@pytest.mark.parametrize('origin', ['journald', 'rfc3339'])
@pytest.mark.parametrize('algorithm', ['ED25519', 'RSA', 'ECDSA'])
def test_publickey_success_with_fingerprint_is_normalized_without_key_metadata(origin, algorithm):
    hit = raw(origin=origin, outcome='success')
    hit['_source']['message'] = hit['_source']['message'].replace('Accepted password', 'Accepted publickey')
    fingerprint = 'A' * 43
    hit['_source']['message'] += f': {algorithm} SHA256:{fingerprint}'
    before = deepcopy(hit)
    body = event(hit)
    assert body['event']['outcome'] == 'success'
    assert body['network']['protocol'] == 'ssh'
    assert body['cloud_soc']['detail']['fields']['auth_method'] == 'publickey'
    assert 'SHA256:' not in json.dumps(body) and fingerprint not in json.dumps(body)
    assert hit == before
    assert detect_rule([body] * 10, RULE) == []


@pytest.mark.parametrize('outcome,method,suffix', [
    ('failure', 'password', ': ED25519 SHA256:' + 'A' * 43),
    ('success', 'password', ': ED25519 SHA256:' + 'A' * 43),
    ('success', 'publickey', ': UNKNOWN SHA256:' + 'A' * 43),
    ('success', 'publickey', ': ED25519 SHA256:' + 'A' * 42),
    ('success', 'publickey', ': ED25519 SHA256:' + 'A' * 44),
    ('success', 'publickey', ': ED25519 SHA256:' + 'A' * 43 + ' extra'),
])
def test_fingerprint_suffix_does_not_accept_failure_or_ambiguous_extensions(outcome, method, suffix):
    hit = raw(outcome=outcome)
    hit['_source']['message'] = hit['_source']['message'].replace('Accepted password', 'Accepted ' + method)
    hit['_source']['message'] += suffix
    assert parse_linux_ssh_source(hit['_source']) is None


def test_nine_double_collected_failures_do_not_alert_and_tenth_does():
    runtime = {}
    nine = [event(raw(i, origin)) for i in range(9) for origin in ('journald','rfc3339')]
    assert detect_rule(nine, RULE, runtime=runtime) == []
    assert len(next(iter(runtime.values()))['window']) == 9
    found = detect_rule([event(raw(9, origin)) for origin in ('journald','rfc3339')], RULE, runtime=runtime)
    assert len(found) == 1 and found[0]['event_count'] == 10
    assert len(found[0]['evidence']) == 10
    assert all(r['complete'] for r in found[0]['evidence'])


def test_same_format_distinct_attempts_and_hosts_are_not_collapsed():
    samples = [raw(i) for i in range(10)]
    assert len(detect_rule([event(r) for r in samples], RULE)) == 1
    a, b = raw(), raw(origin='rfc3339')
    b['_source']['host']['id'] = 'other-host'
    assert event(a)['cloud_soc']['observation']['id'] != event(b)['cloud_soc']['observation']['id']
    same = []
    for i in range(10):
        distinct = raw()
        distinct['_id'] = f'same-format-distinct-attempt-{i}'
        same.append(event(distinct))
    assert len(detect_rule(same, RULE)) == 1
    assert detect_rule([event(raw())] * 10, RULE) == []
    assert detect_rule([event(raw(i, outcome='success')) for i in range(10)], RULE) == []


def test_real_rsyslog_millisecond_drift_does_not_double_count():
    samples=[]
    for i in range(9):
        journal=raw(i); file=raw(i,'rfc3339')
        file['_source']['message']=file['_source']['message'].replace('123456','124951')
        a,b=event(journal),event(file)
        assert a['cloud_soc']['observation']['id'] != b['cloud_soc']['observation']['id']
        assert ssh_collection_mirror(a,b)
        samples.extend((a,b))
    runtime={}
    assert detect_rule(samples,RULE,runtime=runtime)==[]
    assert len(next(iter(runtime.values()))['window'])==9
    assert len(detect_rule([event(raw(9)),event(raw(9,'rfc3339'))],RULE,runtime=runtime))==1
    later=raw(0,'rfc3339');later['_source']['message']=later['_source']['message'].replace('123456','130000')
    assert not ssh_collection_mirror(event(raw()),event(later))
    assert not ssh_collection_mirror(event(raw()),event(raw()))
    different=event(raw(0,'rfc3339'));different['source']['port']+=1
    assert not ssh_collection_mirror(event(raw()),different)


@pytest.mark.parametrize('mutation', [
    lambda s:s['journald']['process'].update(name='fixture'),
    lambda s:s['journald'].update(pid=True),
    lambda s:s['journald'].update(pid=2**32),
    lambda s:s.update({'@timestamp':'2026-10-12T12:00:00'}),
    lambda s:s.update({'@timestamp':'invalid'}),
    lambda s:s.update(message=s['message']+'\nPRIVATE_CANARY'),
    lambda s:s.update(message=s['message'].replace('40000','65536')),
    lambda s:s.update(message=s['message']+' PRIVATE_CANARY'),
    lambda s:s.update(message=s['message'].replace('fixture','--password=PRIVATE_CANARY')),
])
def test_ambiguous_or_sensitive_journal_metadata_is_rejected(mutation):
    s=raw()['_source'];mutation(s)
    assert parse_linux_ssh_source(s) is None


def test_cutoff_preserves_previous_interpretation_and_cannot_change():
    sample=raw(); cutoff=BASE+timedelta(seconds=21)
    before = normalize(sample, cutoff.isoformat(), ssh_v2_start=cutoff)[2]
    assert before is None or before.get('network', {}).get('protocol') != 'ssh'
    sample['_source']['event']['ingested']=cutoff.isoformat()
    assert normalize(sample, cutoff.isoformat(), ssh_v2_start=cutoff)[1]['status']=='normalized'
    c=Mock();c.options.return_value=c
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'state.sqlite';now=BASE+timedelta(minutes=5)
        run_once(c,p,BASE.isoformat(),now=now,scanner=lambda *_:[],ssh_v2_start=cutoff.isoformat())
        for value in (None,(cutoff+timedelta(seconds=1)).isoformat(),'naive'):
            with pytest.raises(ValueError):run_once(c,p,BASE.isoformat(),now=now,scanner=lambda *_:[],ssh_v2_start=value)


def test_incremental_duplicate_arrival_before_finalization_survives_restart():
    hits=[];c=client_for([]);c.field_caps.return_value={'fields':{'cloud_soc.normalized_at':{'date':{}}}};c.count.return_value={'count':0}
    def add(origin,receipt):
        for i in range(9):
            body=event(raw(i,origin));loc=body.pop('_cloud_soc_meta');body['cloud_soc']['normalized_at']=(BASE+timedelta(seconds=receipt)).isoformat()
            hits.append({'_index':NORMALIZED,'_id':loc['document_id'],'_source':body})
    def scan(client,**kw):
        r=kw['query']['range']['cloud_soc.normalized_at'];lo=datetime.fromisoformat(r['gte']);hi=datetime.fromisoformat(r['lt'])
        return deepcopy([h for h in hits if lo<=datetime.fromisoformat(h['_source']['cloud_soc']['normalized_at'])<hi])
    with tempfile.TemporaryDirectory() as d:
        p=Path(d)/'state.sqlite'
        def run(t):return run_incremental(c,state_path=p,start=BASE,now=BASE+timedelta(seconds=t),lateness_seconds=60,scanner=scan)
        add('journald',10);assert run(70)['created']==0
        add('rfc3339',60);result=run(100)
        assert result['created']==result['late']==0
        assert run(140)['created']==0
        assert not any(call.kwargs['index']=='security-alerts' for call in c.create.call_args_list)


def invalid_user_raw(i=0, origin='journald'):
    hit = raw(i, origin if origin != 'rfc3164' else 'rfc3339')
    body = f'Invalid user fixture from 192.0.2.177 port {40000+i}'
    if origin == 'journald':
        hit['_source']['message'] = body
    elif origin == 'rfc3339':
        stamp = BASE + timedelta(seconds=i, microseconds=123456)
        hit['_source']['message'] = f'{stamp.isoformat()} fixture sshd[{100+i}]: {body}'
    else:
        hit['_source']['message'] = f'Oct 12 21:00:{i:02d} fixture sshd[{100+i}]: {body}'
        hit['_source']['event']['timezone'] = '+09:00'
        hit['_id'] = f'rfc3164-{i}'
    return hit


@pytest.mark.parametrize('origin', ['journald', 'rfc3339', 'rfc3164'])
def test_invalid_user_is_failure_with_distinct_version_and_lineage(origin):
    hit = invalid_user_raw(origin=origin)
    original = deepcopy(hit)
    identifier, record, body = normalize(hit, BASE.isoformat())
    assert hit == original
    assert record['status'] == 'normalized'
    assert record['version'] == 'linux-ssh-invalid-user-v1'
    assert body['event']['action'] == 'ssh_invalid_user'
    assert body['event']['outcome'] == 'failure'
    assert body['network']['protocol'] == 'ssh'
    assert body['cloud_soc']['detail']['fields']['auth_method'] == 'unknown'
    assert body['cloud_soc']['provenance']['raw'] == {'index':hit['_index'],'id':hit['_id']}
    assert body['@timestamp'].startswith('2026-10-12T12:00:00')
    assert 'message' not in body
    assert identifier == normalize(hit, (BASE+timedelta(days=1)).isoformat())[0]


@pytest.mark.parametrize('file_origin', ['rfc3339', 'rfc3164'])
def test_invalid_user_mirrors_count_once_per_attempt(file_origin):
    def normalized_invalid(i, origin):
        body = event(invalid_user_raw(i, origin))
        return body
    runtime = {}
    nine = [normalized_invalid(i, origin) for i in range(9) for origin in ('journald', file_origin)]
    assert detect_rule(nine, RULE, runtime=runtime) == []
    assert len(next(iter(runtime.values()))['window']) == 9
    found = detect_rule([normalized_invalid(9, origin) for origin in ('journald', file_origin)], RULE, runtime=runtime)
    assert len(found) == 1
    assert found[0]['event_count'] == 10
    assert len(found[0]['evidence']) == 10
    a = normalized_invalid(0, 'journald')
    b = normalized_invalid(0, file_origin)
    assert ssh_collection_mirror(a,b)
    assert not ssh_collection_mirror(a,a)
    b['source']['port'] += 1
    assert not ssh_collection_mirror(a,b)


def test_invalid_user_requires_explicit_file_timezone_and_rejects_close_messages():
    hit = invalid_user_raw(origin='rfc3164')
    del hit['_source']['event']['timezone']
    assert normalize(hit, BASE.isoformat())[1]['reason'] == 'ssh_timezone_missing'
    for origin in ('journald','rfc3339','rfc3164'):
        hit = invalid_user_raw(origin=origin)
        hit['_source']['message'] = hit['_source']['message'].replace(
            'Invalid user fixture from', 'Connection closed by invalid user fixture from')
        assert parse_linux_ssh_source(hit['_source']) is None
    for suffix in (' ssh2',' EXTRA','\nPRIVATE_CANARY'):
        hit = invalid_user_raw()
        hit['_source']['message'] += suffix
        assert parse_linux_ssh_source(hit['_source']) is None
