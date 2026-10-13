"""Real normalizer/engines, durable local databases and portal; synthetic ES IO."""
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import sqlite3
import os
import subprocess
import sys
from unittest.mock import Mock, patch

import pytest
from elasticsearch import ConflictError
from cloud_soc.detection import early
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.worker import approved_rules
from cloud_soc.elastic.repository import SECURITY_ALERTS_MAPPING
from cloud_soc.portal.notices import NoticeReader, project
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.log_query import LogQueryError
from cloud_soc.processing.contract import normalize, NORMALIZED
from test_linux_ssh_live_formats import raw
from test_integration_security import session_portal as session_portal

BASE = datetime.now(timezone.utc).replace(microsecond=0) - timedelta(seconds=30)


def samples(count=10, *, seconds=0, org='team-a', ip='192.0.2.177', origin='journald'):
    hits = []
    for i in range(count):
        hit = raw(i, origin)
        stamp = BASE + timedelta(seconds=seconds+i)
        hit['_id'] += f'-{seconds}-{org}-{ip}'
        hit['_source']['@timestamp'] = stamp.isoformat()
        hit['_source']['organization']['id'] = org
        hit['_source']['event']['ingested'] = stamp.isoformat()
        hit['_source']['message'] = hit['_source']['message'].replace('192.0.2.177', ip)
        if origin != 'journald':
            hit['_source']['message'] = stamp.isoformat() + ' ' + hit['_source']['message'].split(' ', 1)[1]
        key, record, body = normalize(hit, (BASE+timedelta(seconds=seconds+i+1)).isoformat())
        assert record['status'] == 'normalized'
        hits.append({'_index': NORMALIZED, '_id': key, '_source': body})
    return hits


class Fixture:
    def __init__(self, hits):
        self.hits, self.docs = hits, {}
        self.client = Mock()
        c = self.client
        c.options.return_value = c
        c.indices.resolve_index.side_effect = lambda **kw: {'indices': [{'name': kw['name']}]}
        c.indices.get_mapping.side_effect = lambda **kw: {kw['index']: {'mappings': deepcopy(
            early.MAPPING if kw['index'] == early.NOTICES else SECURITY_ALERTS_MAPPING)}}
        c.field_caps.return_value = {'fields': {'cloud_soc.normalized_at': {'date': {'type': 'date'}}}}
        c.count.return_value = {'count': 0}
        c.create.side_effect = self.create
        c.get.side_effect = lambda **kw: {'found': True, '_source': deepcopy(self.docs[(kw['index'],kw['id'])])}
        c.search.side_effect = self.search

    def create(self, **kw):
        key = kw['index'], kw['id']
        if key in self.docs:
            raise ConflictError('exists', meta=Mock(status=409), body={})
        self.docs[key] = deepcopy(kw['document'])
        return {'result': 'created'}

    def scan(self, _client, **kw):
        bounds = kw['query']['range']['cloud_soc.normalized_at']
        return [deepcopy(hit) for hit in self.hits if early.utc(bounds['gte']) <=
                early.utc(hit['_source']['cloud_soc']['normalized_at']) < early.utc(bounds['lt'])]

    def search(self, **kw):
        assert kw['index'] == early.NOTICES
        filters = kw['query']['bool']['filter']
        rows = {}
        for (index, _), doc in self.docs.items():
            if index != early.NOTICES:
                continue
            if any('terms' in f and doc['organization']['id'] not in f['terms']['organization.id'] for f in filters):
                continue
            if any('term' in f and doc['notice']['id'] != f['term']['notice.id'] for f in filters):
                continue
            if any('range' in f and not early.utc(f['range']['notice.initial_at']['gte']) <=
                   early.utc(doc['notice']['initial_at']) < early.utc(f['range']['notice.initial_at']['lt']) for f in filters):
                continue
            key = doc['notice']['id']
            if key not in rows or rows[key]['notice']['revision'] < doc['notice']['revision']:
                rows[key] = doc
        return {'hits': {'hits': [{'inner_hits': {'current': {'hits': {'hits': [{'_source': deepcopy(doc)}]}}}}
                for doc in list(rows.values())[:kw['size']]]}}


def run(fixture, path, seconds=20, **kw):
    return early.run(fixture.client, path=path, rule=approved_rules()[0], identity='fixture',
        start=BASE, now=BASE+timedelta(seconds=seconds), frontier=BASE-timedelta(seconds=900),
        scanner=fixture.scan, **kw)


def bodies(path):
    with closing(sqlite3.connect(path)) as db:
        return [json.loads(row[0]) for row in db.execute('SELECT body FROM early_notices')]


def test_nine_then_ten_without_final_wait_replay_and_measured_latency(tmp_path, monkeypatch):
    # Start the measured fixture at execution, not test collection. Slower CI
    # suites must not count unrelated preceding tests as notice processing time.
    monkeypatch.setattr(sys.modules[__name__], 'BASE', datetime.now(timezone.utc).replace(microsecond=0)-timedelta(seconds=30))
    path = tmp_path/'early.sqlite'
    f = Fixture(samples(9))
    assert run(f,path)['early_initials'] == 0
    f.hits = samples(10)
    assert run(f,path,21)['early_initials'] == 1
    body = bodies(path)[0]
    assert body['observed_count'] == 10 and body['state'] == 'verifying'
    assert 0 <= body['normalization_to_initial_seconds'] < 60
    assert {d['notice']['state'] for d in f.docs.values()} == {'initial','verifying'}
    assert run(f,path,22)['early_initials'] == 0
    assert len(bodies(path)) == 1
    assert all(index == early.NOTICES for index,_ in f.docs)


@pytest.mark.parametrize('variant', ['org','ip','window','success','mirror'])
def test_no_false_tenth_from_split_window_success_or_mirrors(tmp_path,variant):
    hits = samples(9)
    extra = samples(1,seconds=10,org='other' if variant=='org' else 'team-a',
                    ip='192.0.2.178' if variant=='ip' else '192.0.2.177')
    if variant=='success': extra[0]['_source']['event']['outcome']='success'
    if variant=='window':
        hits = samples(9,seconds=-310)
        for h in hits: h['_source']['cloud_soc']['normalized_at']=(BASE+timedelta(seconds=11)).isoformat()
    if variant=='mirror': extra=samples(9,origin='rfc3339')
    assert run(Fixture(hits+extra),tmp_path/'early')['early_initials'] == 0


def test_partial_scan_commits_notice_but_only_own_cursor_and_resumes(tmp_path):
    f=Fixture(samples(30));path=tmp_path/'early'
    assert run(f,path,40,budget=10)['early_scan_pending'] == 1
    assert len(bodies(path)) == 1
    assert run(f,path,41,budget=10)['early_initials'] == 0
    assert run(f,path,42,budget=10)['early_scan_pending'] == 1
    assert run(f,path,43,budget=10)['early_scan_pending'] == 0
    assert len(bodies(path)) == 1


def test_outbox_failure_retry_conflict_integrity_and_capacity(tmp_path):
    f=Fixture(samples());path=tmp_path/'early'
    f.client.create.side_effect=RuntimeError('offline')
    assert run(f,path)['early_delivery_pending'] == 1
    assert bodies(path)[0]['state']=='verifying'
    f.client.create.side_effect=f.create
    assert early.flush(f.client,path)['early_delivered']==2
    with closing(early.connection(path)) as db:
        # Simulate crash after ES create, before SQLite acknowledgement.
        key, doc = next(iter(f.docs.items()))
        db.execute('INSERT INTO early_outbox VALUES(?,?)',(key[1],json.dumps(doc)));db.commit()
    assert early.flush(f.client,path)['early_delivered']==1
    with closing(early.connection(path)) as db:
        changed=deepcopy(doc);changed['body']['title']='different'
        db.execute('INSERT INTO early_outbox VALUES(?,?)',(key[1],json.dumps(changed)));db.commit()
    with pytest.raises(ValueError,match='immutable_notice_conflict'):early.flush(f.client,path)
    with pytest.raises(ValueError,match='capacity'):run(Fixture(samples()),tmp_path/'small',capacity=9)
    with pytest.raises(ValueError,match='scope_changed'):early.run(f.client,path=path,rule=approved_rules()[0],
        identity='changed',start=BASE,now=BASE+timedelta(seconds=21),frontier=BASE,scanner=f.scan)


def test_durable_final_link_confirmation_and_correction_are_idempotent(tmp_path):
    from cloud_soc.detection.engine import detect_rule
    f=Fixture(samples());path=tmp_path/'early';run(f,path)
    events=[{**deepcopy(h['_source']),'_cloud_soc_meta':{'index':NORMALIZED,'document_id':h['_id']}} for h in f.hits]
    match=detect_rule(events,approved_rules()[0])[0]
    with closing(sqlite3.connect(tmp_path/'final')) as db:
        early.queue_final(db,[(match,'a'*64)],(BASE+timedelta(seconds=20)).isoformat());db.commit()
        early.finalize(f.client,final_db=db,path=path)
        before=deepcopy(f.docs)
        early.finalize(f.client,final_db=db,path=path)
        assert f.docs==before
    assert bodies(path)[0]['state']=='confirmed' and bodies(path)[0]['final_alert_id']=='a'*64
    early.delayed(f.client,path)
    assert bodies(path)[0]['state']=='confirmed'
    other=tmp_path/'other';g=Fixture(samples());run(g,other)
    with closing(sqlite3.connect(tmp_path/'final2')) as db:
        early.queue_final(db,[],(BASE+timedelta(seconds=20)).isoformat());db.commit()
        early.finalize(g.client,final_db=db,path=other)
    assert bodies(other)[0]['state']=='corrected'
    assert 'not_a_benign' in bodies(other)[0]['reason']


def test_incremental_default_identity_preserved_and_900_frontier_independent(tmp_path):
    f=Fixture(samples());path=tmp_path/'final'
    kwargs=dict(state_path=path,start=BASE,source_id='fixture',scanner=f.scan)
    run_incremental(f.client,now=BASE+timedelta(seconds=70),**kwargs)
    with closing(sqlite3.connect(path)) as db:
        previous=json.loads(db.execute('SELECT body FROM runtime').fetchone()[0])
    result=run_incremental(f.client,now=BASE+timedelta(seconds=71),early_auth=True,**kwargs)
    assert result['early_initials']==1
    with closing(sqlite3.connect(path)) as db:
        current=json.loads(db.execute('SELECT body FROM runtime').fetchone()[0])
    assert previous['identity']==current['identity']
    assert early.utc(current['frontier']) <= BASE-timedelta(seconds=859)
    for seconds in (371,671,971,1271):
        run_incremental(f.client,now=BASE+timedelta(seconds=seconds),early_auth=True,**kwargs)
    finals=[d for (index,_),d in f.docs.items() if index=='security-alerts']
    assert len(finals)==1
    assert bodies(early.location(path))[0]['state']=='confirmed'
    assert len(finals[0]['cloud_soc']['provenance']['evidence'])==10
    assert all(h['_source']==samples()[i]['_source'] for i,h in enumerate(f.hits))
    with pytest.raises(ValueError,match='new_state'):
        run_incremental(f.client,now=BASE+timedelta(seconds=1272),include_patterns=True,**kwargs)


def test_final_failure_retains_checkpoint_and_delays_notice(tmp_path):
    f=Fixture(samples());path=tmp_path/'final'
    f.client.index.side_effect=RuntimeError('status offline')
    with pytest.raises(RuntimeError,match='checkpoint retained'):
        run_incremental(f.client,state_path=path,start=BASE,now=BASE+timedelta(seconds=70),
                        early_auth=True,scanner=f.scan)
    assert bodies(early.location(path))[0]['state']=='delayed'
    with closing(sqlite3.connect(path)) as db:
        assert db.execute('SELECT count(*) FROM runtime').fetchone()[0]==0
    f.client.index.side_effect=None
    run_incremental(f.client,state_path=path,start=BASE,now=BASE+timedelta(seconds=71),early_auth=True,scanner=f.scan)
    assert len(bodies(early.location(path)))==1


def test_portal_latest_revision_scoping_safe_projection_and_exact_evidence(tmp_path):
    f=Fixture(samples());run(f,tmp_path/'early')
    ops=Operations(f.client,organizations={'team-a'});reader=NoticeReader(ops)
    listing=reader.listing([])
    assert len(listing['rows'])==1 and listing['rows'][0]['state']=='verifying'
    assert 'evidence' not in listing['rows'][0]
    assert listing['count_basis']=='latest_visible_logical_notices_not_attack_count'
    assert NoticeReader(Operations(f.client,organizations={'other'})).listing([])['rows']==[]
    identifier=listing['rows'][0]['id']
    with patch.object(ops,'evidence',return_value={'state':'normalized_missing_or_expired'}) as proof:
        assert reader.detail([('id',identifier),('evidence','0')])['evidence']['state']=='normalized_missing_or_expired'
        assert proof.call_args.kwargs['organization']=='team-a'
    with pytest.raises(LogQueryError) as error:reader.detail([('id','b'*64)])
    assert error.value.status==404
    for pairs in ([('id',identifier),('id',identifier)], [('id',identifier),('evidence','10')], [('id','../../raw')]):
        with pytest.raises(LogQueryError):reader.detail(pairs)
    for pairs in ([('org','other')],[('start',BASE.isoformat()),('start',BASE.isoformat())]):
        with pytest.raises(LogQueryError):reader.listing(pairs)
    doc=next(iter(f.docs.values()));doc['body']['private']='PRIVATE_CANARY'
    assert 'PRIVATE_CANARY' not in json.dumps(project(doc))
    doc['body']['observed_count']=True
    with pytest.raises(LogQueryError):project(doc)
    f.client.search.return_value={'timed_out':True,'hits':{'hits':[]}};f.client.search.side_effect=None
    with pytest.raises(LogQueryError):reader.listing([])
    f.client.indices.resolve_index.return_value={'indices':[]};f.client.indices.resolve_index.side_effect=None
    assert reader.listing([])['state']=='not_configured'


def test_provenance_tamper_and_contract_fail_closed_without_final_writes(tmp_path):
    f=Fixture(samples());path=tmp_path/'early';run(f,path)
    f.hits[0]['_source']['user']['name']='different'
    with pytest.raises(ValueError,match='document_changed'):run(f,path,21)
    f.client.indices.get_mapping.side_effect=lambda **kw:{early.NOTICES:{'mappings':{'_meta':{'contract':early.NOTICES}}}}
    with pytest.raises(ValueError,match='explicit_setup'):run(f,tmp_path/'bad')
    assert not (tmp_path/'bad').exists()
    assert all(index==early.NOTICES for index,_ in f.docs)
    assert event_fingerprint(f.hits) != event_fingerprint(samples())


def test_notice_endpoints_require_session_and_scoped_roles(session_portal, tmp_path):
    from test_integration_security import login
    app, monitor, _, _ = session_portal
    f=Fixture(samples(org='synthetic'));run(f,tmp_path/'early')
    monitor.indices.resolve_index.side_effect=f.client.indices.resolve_index.side_effect
    monitor.indices.get_mapping.side_effect=f.client.indices.get_mapping.side_effect
    monitor.search.side_effect=f.search
    assert app.test_client().get('/api/alerts/notices').status_code==401
    identifier=bodies(tmp_path/'early')[0]['id']
    for user in ('admin','investigate','view'):
        http,_=login(app,user)
        assert http.get('/api/alerts/notices').status_code==200
        assert http.get('/api/alerts/notices/detail?id='+identifier).status_code==200
        for asset in ('alert-notices.js','alert-notices.css'):assert http.get('/'+asset).status_code==200
        assert http.post('/api/alerts/notices',json={}).status_code in (403,405)
        # Even a forged header cannot change the organization clause.
        if user!='admin':
            http.get('/api/alerts/notices',headers={'X-Organization':'other','X-Role':'admin'})
            assert {'terms':{'organization.id':['synthetic']}} in monitor.search.call_args.kwargs['query']['bool']['filter']


def test_explicit_notice_setup_and_role_do_not_expand_default_writes():
    from cloud_soc.detection.setup import detector_role, ROLE, prepare_early
    assert detector_role()==ROLE
    role=detector_role(early=True)
    assert role['indices'][:-1]==ROLE['indices']
    assert role['indices'][-1]['privileges']==['create_doc','read','view_index_metadata']
    f=Fixture([]);f.client.indices.exists.return_value=False
    prepare_early(f.client)
    assert f.client.indices.create.call_args.kwargs['mappings']==early.MAPPING
    f.client.indices.exists.return_value=True
    prepare_early(f.client)
    f.client.indices.get_mapping.side_effect=lambda **kw:{early.NOTICES:{'mappings':{}}}
    with pytest.raises(ValueError,match='conflict'):prepare_early(f.client)


def test_new_worker_process_reuses_committed_sidecar_without_duplicate(tmp_path):
    f=Fixture(samples());path=tmp_path/'early';run(f,path)
    payload=tmp_path/'synthetic.json';payload.write_text(json.dumps({'hits':f.hits,'start':BASE.isoformat()}),encoding='utf-8')
    script="""import json,sys
from datetime import timedelta
from test_early_notices import Fixture
from cloud_soc.detection import early
from cloud_soc.detection.worker import approved_rules
data=json.loads(open(sys.argv[2],encoding='utf-8').read());f=Fixture(data['hits']);start=early.utc(data['start'])
r=early.run(f.client,path=sys.argv[1],rule=approved_rules()[0],identity='fixture',start=start,now=start+timedelta(seconds=30),frontier=start-timedelta(seconds=900),scanner=f.scan)
assert r['early_initials']==0 and not f.docs
"""
    environment={**os.environ,'PYTHONPATH':str(__import__('pathlib').Path(__file__).resolve().parents[1]/'src')+os.pathsep+str(__import__('pathlib').Path(__file__).parent)}
    result=subprocess.run([sys.executable,'-c',script,str(path),str(payload)],env=environment,capture_output=True,text=True,timeout=15)
    assert result.returncode==0,result.stderr
    assert len(bodies(path))==1 and bodies(path)[0]['state']=='verifying'


def test_link_queue_overflow_delays_uncertain_notices_and_preserves_final_work(tmp_path):
    from cloud_soc.detection.engine import detect_rule
    f=Fixture(samples());path=tmp_path/'early';run(f,path)
    events=[{**deepcopy(h['_source']),'_cloud_soc_meta':{'index':NORMALIZED,'document_id':h['_id']}} for h in f.hits]
    match=detect_rule(events,approved_rules()[0])[0]
    foreign=deepcopy(match);foreign['group']['source.ip']='192.0.2.199'
    with closing(sqlite3.connect(tmp_path/'final')) as db:
        assert early.queue_final(db,[(foreign,f'{i:064x}') for i in range(1001)],(BASE+timedelta(seconds=20)).isoformat()) is False
        db.commit()
        assert early.finalize(f.client,final_db=db,path=path)['early_final_reconcile_required']==1
        assert bodies(path)[0]['state']=='delayed'
        assert db.execute('SELECT id FROM early_final_outbox').fetchall()==[('overflow',)]
        early.queue_final(db,[],(BASE+timedelta(seconds=40)).isoformat());db.commit()
        early.finalize(f.client,final_db=db,path=path)
        assert bodies(path)[0]['state']=='delayed'


def test_two_normalized_versions_of_one_raw_observation_do_not_make_a_tenth(tmp_path):
    hits=samples(9)
    duplicate=deepcopy(hits[0]);duplicate['_id']='new-normalizer-version'
    assert run(Fixture(hits+[duplicate]),tmp_path/'early')['early_initials']==0
