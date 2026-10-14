"""Reproduce the home/other-central split, real state adoption and permission failures."""
import base64
from contextlib import closing, nullcontext
from copy import deepcopy
from datetime import timedelta
import json
from pathlib import Path
import sqlite3
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from cloud_soc.deployment.contract import (ALL_WORKERS, WORKERS, build_contract, command, policy, resource_check, validate_rules)
from cloud_soc.deployment.host import backup_database, copy_adopted_state
from cloud_soc.deployment.migrations import additive_grants, prerequisites, state_compatible
from cloud_soc.deployment.worker import argv
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.retrospective import run_retrospective
from cloud_soc.processing.worker import run_once
from test_ruleset_integration import fixture_for, BASE

ROOT = Path(__file__).resolve().parents[1]
POLICY = policy(ROOT)
NOW = BASE + timedelta(days=1)
URL = 'https://elasticsearch:9200'


def seed(root, names):
    objects = {}
    contract, _ = build_contract(POLICY, {}, root, now=BASE + timedelta(seconds=60), initial_start=BASE.isoformat())
    for name in names:
        row = contract['workers'][name];o = deepcopy(row['options'])
        o.pop('--early-auth', None)
        folder = root / name;folder.mkdir(parents=True)
        path = folder / row['state_file'];key = root / 'secrets' / (name + '.key');key.parent.mkdir(exist_ok=True)
        key.write_text(base64.b64encode((name + ':PRIVATE_SYNTHETIC_KEY').encode()).decode())
        if name.startswith('normalizer'):
            c = Mock();c.options.return_value = c
            run_once(c, path, o['--start'], now=BASE+timedelta(seconds=600), scanner=lambda *_: [],
                     ssh_v2_start=o.get('--linux-ssh-v2-start'))
        else:
            f = fixture_for('AUTH-001')
            if name == 'detector-retrospective':
                run_retrospective(f.client, state_path=path, start=o['--start'], now=BASE+timedelta(seconds=600),
                    source_id=URL, scanner=lambda *_, **__: [], rule_ids=list(POLICY['verified_rules']))
            else:
                extra = {'additional_rule_ids': o['--additional-rules'].split(',')} if '--additional-rules' in o else {}
                run_incremental(f.client, state_path=path, start=o['--start'], now=BASE+timedelta(seconds=600),
                    scanner=lambda *_, **__: [], source_id=URL, status_id=o.get('--status-id'), **extra)
        path.chmod(0o600)
        objects[name] = {'Id': name+'-container', 'Config': {'Cmd': command(row['module'], o)},
            'Mounts': [{'Source': str(folder), 'Destination': '/data'}, {'Source': str(key), 'Destination': '/run/keys/worker.key'}]}
    return objects


def feature_signature(contract):
    return {n: {k: row['options'].get(k) for k in ('--priority', '--status-id', '--rules', '--additional-rules', '--early-auth', '--retrospective')}
            for n, row in contract['workers'].items()}


@pytest.mark.parametrize('legacy_names', [('normalizer','detector'),
    ('normalizer','normalizer-priority','detector','detector-additional','detector-retrospective')])
def test_home_and_other_central_converge_to_same_fresh_features_without_reset(tmp_path, legacy_names):
    state = tmp_path / 'server';old = seed(state, legacy_names)
    before = {name: Path(obj['Mounts'][0]['Source']) / ('checkpoint.sqlite' if name.startswith('normalizer') else 'runtime.sqlite') for name,obj in old.items()}
    hashes = {name: p.read_bytes() for name,p in before.items()}
    contract, adoption = build_contract(POLICY, old, state, now=NOW)
    fresh, _ = build_contract(POLICY, {}, tmp_path/'fresh', now=NOW)
    assert feature_signature(contract) == feature_signature(fresh)
    assert set(contract['workers']) == set(WORKERS)
    runtime = state/'runtime';runtime.mkdir()
    copy_adopted_state({'adoption':adoption,'state':str(state)}, runtime)
    for name in legacy_names:
        dest=runtime/'state'/name/contract['workers'][name]['state_file']
        state_compatible(contract['workers'][name],dest)
        with sqlite3.connect(before[name]) as src,sqlite3.connect(dest) as target:
            assert list(src.iterdump()) == list(target.iterdump())
        assert before[name].read_bytes() == hashes[name]
    contract['prepared']=True
    for name in WORKERS:
        assert argv(contract,name,POLICY)[1:3] == ['-m',contract['workers'][name]['module']]
    replay, second_adoption = build_contract(POLICY,old,state,now=NOW+timedelta(days=1),existing=contract)
    assert replay == contract and second_adoption == {}


def test_existing_identity_and_start_mismatch_are_refused_without_writes(tmp_path):
    old=seed(tmp_path,('detector',));c,a=build_contract(POLICY,old,tmp_path,now=NOW)
    path=Path(a['detector']['state_source']);before=path.read_bytes()
    c['workers']['detector']['options']['--start']=(BASE+timedelta(seconds=1)).isoformat()
    with pytest.raises(ValueError,match='identity mismatch'):state_compatible(c['workers']['detector'],path)
    assert path.read_bytes()==before


def test_unknown_legacy_command_and_unverified_rules_cannot_be_adopted(tmp_path):
    old=seed(tmp_path,('detector',));old['detector']['Config']['Cmd'] += ['--api-key','PRIVATE_CANARY']
    with pytest.raises(ValueError):build_contract(POLICY,old,tmp_path,now=NOW)
    c,_=build_contract(POLICY,{},tmp_path,now=NOW);c['prepared']=True
    c['workers']['detector-additional']['options']['--additional-rules']='AWS-IAM-001'
    with pytest.raises(ValueError,match='Unverified'):argv(c,'detector-additional',POLICY)
    changed=deepcopy(POLICY);changed['verified_rules']['AUTH-001']='0'*64
    with pytest.raises(ValueError,match='revision'):validate_rules(changed)


def test_reviewed_plan_survives_sorted_json_roundtrip_without_rule_scope_changes(tmp_path):
    contract,_=build_contract(POLICY,{},tmp_path,now=NOW)
    decoded=json.loads(json.dumps({'policy':POLICY,'contract':contract},sort_keys=True))
    replay,_=build_contract(decoded['policy'],{},tmp_path,now=NOW)
    assert replay==decoded['contract']


def test_version_one_to_two_preserves_every_pipeline_option_and_prepared_state(tmp_path):
    existing,_=build_contract(POLICY,{},tmp_path,now=NOW)
    existing.update(version=1,policy_sha256='cfe8183e7e8defe239ac6fc99c3cdb248963ac3df0eb7f6ccaa0ebbe2bf5b989',prepared=True)
    existing.pop('auxiliary_workers')
    before=deepcopy(existing)
    upgraded,adoption=build_contract(POLICY,{},tmp_path,now=NOW+timedelta(days=10),existing=existing)
    assert upgraded['workers']==before['workers'] and upgraded['created_at']==before['created_at']
    assert upgraded['prepared'] and upgraded['version']==2 and upgraded['migrated_from']==1 and not adoption
    assert existing==before


def test_resources_include_all_workers_backup_space_and_kibana_headroom():
    hardware={'cpus':4,'memory_bytes':8277540864,'free_bytes':4*1024**3,'map_count':1048576,
              'available_memory_bytes':3700000000,'managed_working_set_bytes':3900000000}
    assert resource_check(POLICY,hardware,fresh=False,database_bytes=140693504)['ok']
    for field,value in [('cpus',1),('memory_bytes',6*1024**3),('free_bytes',1024**3),('map_count',65530)]:
        assert not resource_check(POLICY,{**hardware,field:value},fresh=False)['ok']
    assert not resource_check(POLICY,hardware,fresh=True)['ok']
    busy={**hardware,'available_memory_bytes':512*1024**2,'managed_working_set_bytes':2*1024**3}
    assert 'available_memory_budget_exceeded' in resource_check(POLICY,busy,fresh=False)['issues']


def test_additive_permissions_preserve_unrelated_grants_and_refuse_dls_fls():
    old={'cluster':['monitor'],'indices':[{'names':['existing'],'privileges':['read']}], 'metadata':{'owner':'user'}}
    required={'indices':[{'names':['soc-alert-notices-v1'],'privileges':['read','view_index_metadata']}]}
    result=additive_grants(old,required)
    assert result['indices'][:-1]==old['indices'] and result['metadata']==old['metadata'] and result['cluster']==['monitor']
    for restriction in [{'query':{'term':{'organization.id':'a'}}},{'field_security':{'grant':['@timestamp']}}]:
        blocked={'indices':[{'names':['soc-*'],'privileges':['read'],**restriction}]}
        with pytest.raises(ValueError,match='Restricted'):additive_grants(blocked,required)


class FakeSecurity:
    def __init__(self):
        self.roles={'cloud_soc_agent_monitor':{'cluster':[],'indices':[{'names':['soc-host-raw-*'],'privileges':['read']}]},
                    'cloud_soc_normalizer':{'cluster':[],'indices':[]}}
        self.keys={};self.events=[];self.fail=False
    def get_role(self,name):return SimpleNamespace(body={k:deepcopy(v) for k,v in self.roles.items() if k in name.split(',')})
    def put_role(self,name,body):self.events.append(('role',name));self.roles[name]=deepcopy(body)
    def get_api_key(self,id):return SimpleNamespace(body={'api_keys':[deepcopy(self.keys[id])]})
    def update_api_key(self,id,role_descriptors):
        if self.fail:raise RuntimeError('isolated write interruption')
        self.events.append(('key_update',id));self.keys[id]['role_descriptors']=deepcopy(role_descriptors)
    def create_api_key(self,name,expiration,role_descriptors):
        identifier='new-'+str(len(self.keys));self.keys[identifier]={'id':identifier,'invalidated':False,'role_descriptors':deepcopy(role_descriptors)}
        self.events.append(('key_create',identifier))
        return SimpleNamespace(body={'id':identifier,'encoded':base64.b64encode((identifier+':PRIVATE_NEW').encode()).decode()})
    def invalidate_api_key(self,ids):self.events.append(('invalidate',ids))


class FakeSetup:
    def __init__(self):
        self.maps={};self.security=FakeSecurity();self.indices=Mock()
        self.indices.exists.side_effect=lambda index:index in self.maps
        self.indices.create.side_effect=lambda index,mappings,**kw:self.maps.setdefault(index,deepcopy(mappings))
        self.indices.get_mapping.side_effect=lambda index:{index:{'mappings':deepcopy(self.maps[index])}}
        def merge(old,new):
            for k,v in new.items():
                if isinstance(v,dict):merge(old.setdefault(k,{}),v)
                else:old[k]=v
        self.indices.put_mapping.side_effect=lambda index,properties:merge(self.maps[index].setdefault('properties',{}),properties)


@pytest.mark.parametrize('existing', [False,True])
def test_new_and_upgrade_migrations_prepare_same_scopes_without_changing_existing_keys(tmp_path,existing):
    client=FakeSetup();c,_=build_contract(POLICY,{},tmp_path,now=NOW);keys={}
    if existing:
        for name in WORKERS:
            identifier='old-'+name;keys[name]=base64.b64encode((identifier+':PRIVATE_ORIGINAL').encode()).decode()
            client.security.keys[identifier]={'id':identifier,'invalidated':False,'role_descriptors':{'original':{'cluster':[],'indices':[]}}}
    first=prerequisites(client,POLICY,c,tmp_path,keys)
    saved={p.name:p.read_bytes() for p in (tmp_path/'keys').iterdir()}
    events=len(client.security.events)
    second=prerequisites(client,POLICY,c,tmp_path,{})
    assert first==second and second['version']==2
    assert saved=={p.name:p.read_bytes() for p in (tmp_path/'keys').iterdir()}
    assert len(client.security.events)==events
    assert 'soc-alert-notices-v1' in client.maps
    if existing:
        assert sum(e[0]=='key_create' for e in client.security.events)==1  # New read-only notifier key only.
        assert all((tmp_path/'keys'/(n+'.key')).read_text().strip()==v for n,v in keys.items())
    assert all(json.loads((tmp_path/'migrations.json').read_text())['migrations'][n]['state']=='applied' for n in POLICY['migrations'])


def test_migration_write_interruption_records_failure_and_resumes_without_reset(tmp_path):
    client=FakeSetup();c,_=build_contract(POLICY,{},tmp_path,now=NOW)
    identifier='old';encoded=base64.b64encode(b'old:PRIVATE_ORIGINAL').decode()
    client.security.keys[identifier]={'id':identifier,'invalidated':False,'role_descriptors':{'original':{'cluster':[],'indices':[]}}}
    client.security.fail=True
    with pytest.raises(RuntimeError):prerequisites(client,POLICY,c,tmp_path,{'normalizer':encoded})
    ledger=json.loads((tmp_path/'migrations.json').read_text());assert ledger['version']==0
    assert ledger['migrations'][POLICY['migrations'][0]]['state']=='failed'
    client.security.fail=False
    prerequisites(client,POLICY,c,tmp_path,{'normalizer':encoded})
    assert (tmp_path/'keys/normalizer.key').read_text().strip()==encoded


def test_future_ledger_and_expired_keys_are_never_reissued(tmp_path):
    client=FakeSetup();c,_=build_contract(POLICY,{},tmp_path,now=NOW)
    (tmp_path/'migrations.json').write_text(json.dumps({'version':3,'migrations':{}}))
    with pytest.raises(ValueError,match='Future'):prerequisites(client,POLICY,c,tmp_path,{})
    assert not client.security.events


def test_priority_auth_has_independent_status_and_same_immutable_alert_ids(tmp_path):
    f=fixture_for('AUTH-001');a=tmp_path/'auth.sqlite';b=tmp_path/'priority.sqlite'
    args=dict(start=BASE,now=BASE+timedelta(seconds=600),lateness_seconds=60,scanner=f.scan)
    run_incremental(f.client,state_path=a,**args)
    alerts=deepcopy({k:v for k,v in f.docs.items() if k[0]=='security-alerts'})
    assert alerts
    run_incremental(f.client,state_path=b,status_id='detector-priority',**args)
    assert {k:v for k,v in f.docs.items() if k[0]=='security-alerts'}==alerts
    ids={call.kwargs['id'] for call in f.client.index.call_args_list if call.kwargs['index']=='soc-pipeline-status'}
    assert {'detector','detector-priority'}<=ids


def test_backup_restore_preserves_wal_commits_and_refuses_overwrite(tmp_path):
    source=tmp_path/'live.sqlite';target=tmp_path/'backup.sqlite'
    with sqlite3.connect(source) as db:
        db.execute('pragma journal_mode=wal');db.execute('create table checkpoints (value text)')
        db.execute("insert into checkpoints values ('unchanged')");db.commit()
        backup_database(source,target)
    with sqlite3.connect(target) as restored:assert restored.execute('select * from checkpoints').fetchall()==[('unchanged',)]
    with pytest.raises(ValueError):backup_database(source,target)


def test_managed_portal_contract_is_admin_only_and_missing_workers_fail_closed(tmp_path):
    from test_integration_security import make_session_portal,login
    app,monitor,settings,_=make_session_portal(tmp_path)
    contract,_=build_contract(POLICY,{},tmp_path,now=NOW);contract['prepared']=True
    path=tmp_path/'contract.json';path.write_text(json.dumps(contract));settings['RUNTIME_CONTRACT_FILE']=str(path)
    admin,_=login(app,'admin');view,_=login(app,'view')
    assert admin.get('/api/runtime').json['required_workers']==list(ALL_WORKERS)
    assert view.get('/api/runtime').status_code==403
    with patch('cloud_soc.portal.operations.Operations.worker_status',side_effect=lambda _: {'state':'not_started'}):
        r=admin.get('/api/operations/status')
    assert r.status_code==200 and r.json['realtime_coverage']['state']=='blocked'
    assert set(r.json['runtime_missing_workers'])==set(WORKERS)


def test_no_input_or_partial_live_search_cannot_pass_runtime_acceptance():
    from cloud_soc.deployment.verify import evidence
    client=Mock();client.options.return_value=client
    client.search.return_value={'hits':{'hits':[],'total':{'value':0}},'_shards':{'failed':0}}
    result=evidence(client,BASE.isoformat(),now=NOW)
    assert not result['verified'] and 'new_live_normalization_absent' in result['issues']
    client.search.return_value={'timed_out':True}
    with pytest.raises(ValueError,match='Incomplete'):evidence(client,BASE.isoformat(),now=NOW)


@pytest.mark.parametrize('fault', ['none','migration','activation','interrupt','receipt','stale','modified_site','disk'])
def test_coordinator_stale_plan_failure_and_retry_preserve_live_databases(tmp_path,monkeypatch,fault):
    from cloud_soc.deployment import host
    state=tmp_path/'server';old=seed(state,('normalizer','detector'))
    c,adopt=build_contract(POLICY,old,state,now=NOW)
    original={n:(Path(a['state_source'])).read_bytes() for n,a in adopt.items() if 'state_source' in a}
    (state/'compose.env').write_text('SOC_STATE_DIR=protected')
    (state/'secrets/elastic_password').write_text('PRIVATE_PASSWORD')
    plan={'workspace':str(tmp_path),'state':str(state),'image':'fixture:verified','image_id':'sha256:verified',
        'project':'cloud-soc-central','policy':POLICY,'contract':c,'adoption':adopt,'resources':{'ok':True},
        'fingerprint':'reviewed','observed':{},'protected_sha256':{},'previous_compose':['--project-name','cloud-soc-central','-f','protected-old.json'],
        'source':{},'source_sha256':'verified','site':{},'fresh':False,'new_workers':[n for n in WORKERS if n not in old],
        'compose_environment':{'SOC_STATE_DIR':str(state)}}
    current=deepcopy(plan)
    if fault=='stale':current['fingerprint']='different'
    if fault=='modified_site':plan['site']={'services':{'gateway':{'ports':['0.0.0.0:9999:9999']}}}
    if fault=='disk':current['resources']['ok']=False
    monkeypatch.setattr(host,'snapshot',lambda *_:deepcopy(current))
    runtime=state/'runtime';runtime.mkdir()
    monkeypatch.setattr(host,'lock',lambda _:nullcontext())
    actual_atomic=host.atomic_json
    def atomic(path,value,**kw):
        actual_atomic(path,value,**kw)
        if fault=='receipt' and path.name=='current.json':raise RuntimeError('interrupted after receipt write')
    monkeypatch.setattr(host,'atomic_json',atomic)
    class Engine:
        phase='old'
        def __init__(self):self.calls=[]
        def json(self,args,**kw):
            self.calls.append(args)
            if 'config' in args:return {'services':{n:{'image':plan['image']} for n in host.SERVICES}}
            if 'cloud_soc.deployment.migrations' in args:
                if fault=='migration':raise RuntimeError('isolated migration interruption')
                return {'version':1}
            raise AssertionError(args)
        def run(self,args,**kw):
            self.calls.append(args)
            if 'up' in args and 'site.json' in ' '.join(args):
                self.phase='new'
                if fault=='activation':raise RuntimeError('isolated activation interruption')
                if fault=='interrupt':raise KeyboardInterrupt()
            elif 'up' in args:self.phase='old'
            return ''
    engine=Engine()
    def objects(*_):
        if engine.phase=='old':return old
        return {n:{'State':{'Running':True},'Image':plan['image_id']} for n in host.SERVICES}
    monkeypatch.setattr(host,'containers',objects)
    monkeypatch.setattr(host,'worker_inventory',lambda *_,stopped=False: {} if stopped else {n:n for n in ALL_WORKERS})
    monkeypatch.setattr(host,'immutable_documents',lambda *_,**__: {'existing_immutable_documents_preserved':2})
    if fault=='none':
        result=host.apply(engine,plan)
        assert result['runtime_ready'] and result['live_ingestion_acceptance']=='not_yet_verified'
        assert (runtime/'current.json').is_file()
    else:
        with pytest.raises((ValueError,RuntimeError,KeyboardInterrupt)):host.apply(engine,plan)
        assert not (runtime/'current.json').exists()
        if fault in ('stale','modified_site','disk'):
            assert not engine.calls
        else:
            assert engine.phase=='old'
            assert not (runtime/'contract.json').exists()
            # A retry preserves each unactivated copy, instead of deleting state.
            copy_adopted_state({'adoption':adopt,'state':str(state)},runtime)
            assert list((runtime/'state/normalizer').glob('*.unactivated-*'))
    assert all(Path(adopt[n]['state_source']).read_bytes()==b for n,b in original.items())
    assert 'PRIVATE_PASSWORD' not in json.dumps(engine.calls)


def test_docker_coordinator_drops_inherited_endpoints_and_state(monkeypatch):
    from cloud_soc.deployment.host import Docker
    for name in ('DOCKER_HOST','DOCKER_CONTEXT','COMPOSE_FILE','SOC_STATE_DIR','SOC_PUBLIC_HOST'):
        monkeypatch.setenv(name,'UNTRUSTED_ENDPOINT')
    engine=Docker()
    assert not any(k.startswith(('DOCKER_','COMPOSE_','SOC_')) for k in engine.env)
    assert engine.prefix==['docker','--host','unix:///var/run/docker.sock']


def test_preflight_container_only_sees_standalone_readonly_copies(tmp_path):
    from cloud_soc.deployment.host import inspect_prerequisites
    state=tmp_path/'server';old=seed(state,('normalizer','detector'))
    (state/'tls').mkdir();(state/'tls/ca.crt').write_text('PUBLIC_SYNTHETIC_CA')
    (state/'secrets/elastic_password').write_text('PRIVATE_PASSWORD')
    c,a=build_contract(POLICY,old,state,now=NOW)
    original={n:Path(row['state_source']).read_bytes() for n,row in a.items() if 'state_source' in row}
    mounts=[]
    class Engine:
        def json(self,args,**kw):
            payload=json.loads(kw['input'])
            for i,arg in enumerate(args[:-1]):
                if arg!='-v':continue
                source,target,mode=args[i+1].rsplit(':',2)
                assert mode=='ro'
                if target.startswith('/adopted/'):
                    folder=Path(source);mounts.append(folder)
                    assert folder.is_relative_to(state.parent) and 'runtime-preflight-' in str(folder)
                    name=target.split('/')[-1];db=folder/c['workers'][name]['state_file']
                    with closing(sqlite3.connect('file:'+str(db)+'?mode=ro',uri=True)) as conn:
                        assert conn.execute('pragma journal_mode').fetchone()[0]=='delete'
                    assert folder!=Path(a[name]['state_source']).parent
            assert 'PRIVATE_PASSWORD' not in json.dumps(args)
            assert set(payload['states'])=={'normalizer','detector'}
            return {'read_only_copies_verified':True}
    result=inspect_prerequisites(Engine(),state,'fixture:verified','cloud-soc-central',POLICY,c,a)
    assert result['read_only_copies_verified'] and mounts
    assert all(not p.exists() for p in mounts)
    assert all(Path(a[n]['state_source']).read_bytes()==b for n,b in original.items())


def test_wal_backup_includes_committed_frames_without_checkpoint_or_live_mutation(tmp_path):
    source=tmp_path/'operating.sqlite';copy=tmp_path/'standalone.sqlite'
    with closing(sqlite3.connect(source)) as writer:
        writer.execute('pragma journal_mode=wal');writer.execute('pragma wal_autocheckpoint=0')
        writer.execute('create table checkpoint (seq integer)');writer.commit()
        writer.execute('pragma wal_checkpoint(truncate)')
        original_main=source.read_bytes()
        writer.execute('insert into checkpoint values (731)');writer.commit()
        wal=Path(str(source)+'-wal');assert wal.stat().st_size>0
        frames=wal.read_bytes()
        assert source.read_bytes()==original_main  # Latest committed checkpoint exists only in WAL.
        backup_database(source,copy)
        assert wal.read_bytes()==frames and source.read_bytes()==original_main
        with closing(sqlite3.connect('file:'+str(copy)+'?mode=ro',uri=True)) as restored:
            assert restored.execute('select seq from checkpoint').fetchall()==[(731,)]
            assert restored.execute('pragma journal_mode').fetchone()==('delete',)
        assert writer.execute('pragma journal_mode').fetchone()==('wal',)


@pytest.mark.parametrize('variant',['manual','other_project','replica','renamed','canonical'])
def test_manual_override_and_scaled_workers_cannot_duplicate_common_workers(variant):
    from cloud_soc.deployment.host import worker_inventory
    labels={'com.docker.compose.project':'cloud-soc-central','com.docker.compose.service':'detector'}
    row={'Id':'old-worker','Name':'/cloud-soc-central-detector-1',
         'Config':{'Cmd':['python','-m','cloud_soc.detection','--run'],'Labels':labels}}
    if variant=='manual':row['Config']['Labels']={}
    if variant=='other_project':labels['com.docker.compose.project']='manual-overlay'
    if variant=='replica':row['Name']='/cloud-soc-central-detector-2'
    if variant=='renamed':row['Name']='/custom-auth-detector'
    engine=Mock();engine.run.return_value='old-worker';engine.json.return_value=[row]
    if variant=='canonical':
        assert worker_inventory(engine,'cloud-soc-central')=={'detector':'old-worker'}
        with pytest.raises(ValueError):worker_inventory(engine,'cloud-soc-central',stopped=True)
    else:
        with pytest.raises(ValueError,match='duplicate'):worker_inventory(engine,'cloud-soc-central')


@pytest.mark.parametrize('fresh',[False,True])
def test_process_kill_journal_recovers_execution_without_restoring_any_database(tmp_path,monkeypatch,fresh):
    from cloud_soc.deployment import host
    state=tmp_path/'server';runtime=state/'runtime';run=runtime/'upgrades/interrupted';run.mkdir(parents=True)
    db=runtime/'operating.sqlite'
    with closing(sqlite3.connect(db)) as c:c.execute('create table progress(value)');c.execute('insert into progress values(42)');c.commit()
    original=db.read_bytes()
    old=['--project-name','cloud-soc-central','-f',str(state/'old-compose.json')]
    previous={'version':1,'prepared':True,'preserved':'checkpoint'}
    (runtime/'contract.json').write_text(json.dumps({'version':1,'prepared':False,'pinned_start':'unchanged'}))
    (runtime/'pending.json').write_text(json.dumps({'run':str(run)}))
    (run/'recovery.json').write_text(json.dumps({'previous_compose':None if fresh else old,
       'old_names':['portal','detector'],'old_contract':None if fresh else previous,'old_current':None,
       'canonical':['compose','--project-name','cloud-soc-central','-f','missing-after-kill.json'],'environment':{}}))
    monkeypatch.setattr(host,'lock',lambda _:nullcontext())
    monkeypatch.setattr(host,'containers',lambda *_:{'portal':{},'detector':{}})
    engine=Mock();result=host.recover(engine,state)
    assert result['databases_rewound'] is False and result['old_execution_restored']==(not fresh)
    assert db.read_bytes()==original and not (runtime/'pending.json').exists()
    assert json.loads((runtime/'contract.json').read_text())==(previous if not fresh else {'version':1,'prepared':False,'pinned_start':'unchanged'})
    assert host.recover(engine,state)=={'recovery_required':False}


def test_site_snapshot_repository_and_compose_numeric_strings_are_supported():
    from cloud_soc.deployment.host import site_overlay
    from cloud_soc.deployment.contract import SERVICES,APP_SERVICES,validate_rendered
    old={'services':{'elasticsearch':{'environment':{'path.repo':'/snapshots','ES_JAVA_OPTS':'old-heap'},'volumes':[]}}}
    assert site_overlay(old,{})['services']['elasticsearch']['environment']=={'path.repo':'/snapshots'}
    rendered={'services':{n:{} for n in SERVICES}}
    for n in APP_SERVICES:rendered['services'][n]['image']='verified:tag'
    for n,limit in POLICY['resources']['limits_mib'].items():rendered['services'][n]['mem_limit']=str(limit*1024**2)
    for n in WORKERS:rendered['services'][n]['command']=['python','-m','cloud_soc.deployment.worker','--service',n]
    rendered['services']['kibana']['environment']={'NODE_OPTIONS':'--max-old-space-size=1024'}
    rendered['services']['bootstrap']={'profiles':['initialization']}
    rendered['services']['slack-notifier']['command']=['python','-m','cloud_soc.notifications.worker']
    assert validate_rendered(POLICY,rendered,'verified:tag')['resource_limits_match_policy']


def test_existing_alert_and_notice_hashes_refuse_deletion_mutation_and_partial_reply():
    from cloud_soc.deployment.preservation import check
    from cloud_soc.deployment.contract import digest
    client=Mock();doc={'organization':{'id':'existing'},'proof':['immutable']}
    before={'security-alerts':{'old':digest(doc)}}
    client.mget.return_value={'docs':[{'_id':'old','found':True,'_source':doc}]}
    assert check(client,before)=={'existing_immutable_documents_preserved':1}
    for response in ({'docs':[]},{'docs':[{'_id':'old','found':False}]},
                     {'docs':[{'_id':'old','found':True,'_source':{'changed':True}}]}):
        client.mget.return_value=response
        with pytest.raises(ValueError):check(client,before)


def test_saved_case_dashboard_rows_are_guarded_using_online_snapshots(tmp_path):
    from cloud_soc.deployment.host import portal_rows
    portal=tmp_path/'portal';portal.mkdir()
    with closing(sqlite3.connect(portal/'dashboards.sqlite')) as writer:
        writer.execute('pragma journal_mode=wal');writer.execute('create table dashboards(id integer primary key,value text)')
        writer.execute("insert into dashboards values(1,'USER_SAVED_SETTING')");writer.commit()
        before=portal_rows(tmp_path)
        writer.execute("insert into dashboards values(2,'NEW_SETTING')");writer.commit()
        after=portal_rows(tmp_path)
        assert set(before['dashboards.sqlite'])<set(after['dashboards.sqlite'])
        writer.execute("update dashboards set value='BAD_REPLACEMENT' where id=1");writer.commit()
        assert not set(before['dashboards.sqlite'])<=set(portal_rows(tmp_path)['dashboards.sqlite'])


@pytest.mark.parametrize('fault',['none','bootstrap','migration','activation'])
def test_fresh_common_install_and_retry_preserve_pinned_start_and_state(tmp_path,monkeypatch,fault):
    from cloud_soc.deployment import host
    state=tmp_path/'fresh';(state/'secrets').mkdir(parents=True)
    (state/'compose.env').write_text('');(state/'secrets/elastic_password').write_text('PRIVATE')
    c,_=build_contract(POLICY,{},state,now=NOW)
    plan={'workspace':str(tmp_path),'state':str(state),'image':'fixture:verified','image_id':'sha256:verified',
        'project':'cloud-soc-central','policy':POLICY,'contract':c,'adoption':{},'resources':{'ok':True},
        'fingerprint':'reviewed','observed':{},'protected_sha256':{},'previous_compose':None,
        'source':{},'source_sha256':'verified','site':{},'fresh':True,'new_workers':list(WORKERS),
        'compose_environment':{'SOC_STATE_DIR':str(state)}}
    monkeypatch.setattr(host,'lock',lambda _:nullcontext())
    monkeypatch.setattr(host,'snapshot',lambda *_:deepcopy(plan))
    monkeypatch.setattr(host,'immutable_documents',lambda *_,**__: {'existing_immutable_documents_preserved':0})
    class Engine:
        phase='initial';fail=fault
        def run(self,args,**kw):
            if 'bootstrap' in args and self.fail=='bootstrap':raise RuntimeError('interrupted bootstrap')
            if 'up' in args and 'portal' in args:
                self.phase='active'
                if self.fail=='activation':raise RuntimeError('interrupted activation')
            if 'stop' in args:self.phase='stopped'
            return ''
        def json(self,args,**kw):
            if 'config' in args:return {'services':{n:{'image':plan['image']} for n in host.SERVICES}}
            if 'cloud_soc.deployment.migrations' in args:
                checkpoint=state/'runtime/state/detector/runtime.sqlite'
                if not checkpoint.exists():
                    with closing(sqlite3.connect(checkpoint)) as db:
                        db.execute('create table preserved(value)');db.execute('insert into preserved values(73)');db.commit()
                if self.fail=='migration':raise RuntimeError('interrupted migration')
                return {'version':1}
            raise AssertionError(args)
    engine=Engine()
    monkeypatch.setattr(host,'containers',lambda *_: {} if engine.phase!='active' else {
        n:{'State':{'Running':True},'Image':plan['image_id']} for n in host.SERVICES})
    monkeypatch.setattr(host,'worker_inventory',lambda *_,stopped=False: {} if stopped else {n:n for n in ALL_WORKERS})
    if fault!='none':
        with pytest.raises(RuntimeError):host.apply(engine,plan)
        assert not (state/'runtime/pending.json').exists() and not (state/'runtime/current.json').exists()
        pinned=json.loads((state/'runtime/contract.json').read_text())
        assert pinned['workers']==c['workers']
        plan['contract']=pinned  # Retry reviews a new plan, preserving the pinned initial scope.
        engine.fail='none';engine.phase='initial'
    assert host.apply(engine,plan)['runtime_ready']
    with closing(sqlite3.connect(state/'runtime/state/detector/runtime.sqlite')) as db:
        assert db.execute('select value from preserved').fetchall()==[(73,)]
