"""Coordinator failure matrix with real SQLite/state/key migrations, synthetic Docker IO."""
from contextlib import closing, nullcontext
from copy import deepcopy
import json
from pathlib import Path
import sqlite3

import pytest

from cloud_soc.deployment import host, migrations
from cloud_soc.deployment.contract import ALL_WORKERS, APP_SERVICES, SERVICES, WORKERS, build_contract, digest
from test_deployment_parity import FakeSetup, NOW, POLICY, seed
from test_school_runtime_compat import service


def coordinator(tmp_path, monkeypatch, *, fresh=False):
    state = tmp_path/'server';state.mkdir();runtime = state/'runtime';runtime.mkdir()
    old = {} if fresh else seed(state, ('normalizer', 'normalizer-priority', 'detector', 'detector-additional', 'detector-retrospective'))
    if not fresh:
        old.update({name: service(name) for name in ('elasticsearch', 'kibana', 'portal', 'gateway', 'enrollment-cleanup')})
        for obj in old.values(): obj.setdefault('Image', 'old')
    (state/'compose.env').write_text('SOC_ENROLLMENT_ENABLED=0')
    (state/'secrets').mkdir(exist_ok=True);(state/'secrets/elastic_password').write_text('SYNTHETIC')
    (state/'tls').mkdir();(state/'tls/ca.crt').write_bytes(b'SYNTHETIC CA');(state/'tls/server.key').write_bytes(b'SYNTHETIC PRIVATE')
    portal = state/'portal';portal.mkdir()
    with closing(sqlite3.connect(portal/'dashboards.sqlite')) as db:
        db.execute('create table dashboards(id integer primary key,revision integer)');db.execute('insert into dashboards values(1,15)');db.commit()
    contract, adopt = build_contract(POLICY, old, state, now=NOW)
    plan = {'plan_version': 2, 'workspace': str(tmp_path), 'state': str(state), 'image': 'candidate:tag',
        'image_id': 'sha256:new', 'project': 'cloud-soc-central', 'policy': POLICY, 'contract': contract, 'adoption': adopt,
        'resources': {'ok': True}, 'fingerprint': 'reviewed', 'observed': {}, 'protected_sha256': host.protected_hashes(state),
        'previous_compose': ['--project-name', 'cloud-soc-central', '-f', str(tmp_path/'old.json')] if not fresh else None,
        'source': {}, 'source_sha256': 'new source', 'site': {}, 'fresh': fresh, 'new_workers': list(set(ALL_WORKERS)-set(old)),
        'compose_environment': {}, 'backup_root': None, 'ingress_reserve_bytes': 1024**3,
        'service_classification': {'stop': [name for name in APP_SERVICES if name in old]},
        'previous_execution': {'services': {name: {'image': 'old'} for name in old}} if old else {}}
    actual = deepcopy(old);client = FakeSetup()
    for name, row in adopt.items():
        if 'key_source' in row:
            identifier = migrations.key_id(Path(row['key_source']).read_text().strip())
            client.security.keys[identifier] = {'id': identifier, 'invalidated': False,
                'role_descriptors': {'original': {'cluster': [], 'indices': []}}}
    class Engine:
        fault = None;failed_recovery = False;calls = [];bootstrap = 0
        def run(self, args, **kwargs):
            self.calls.append(args)
            if args[0] == 'stop':
                for name, obj in actual.items():
                    if 'cloud-soc-central-'+name+'-1' in args: obj['State']['Running'] = False
            elif 'stop' in args:
                for name in plan['service_classification']['stop']:
                    assert name in args;actual[name]['State']['Running'] = False
                # A legitimate authenticated save was committed before quiescence.
                with closing(sqlite3.connect(portal/'dashboards.sqlite')) as db:
                    db.execute('update dashboards set revision=16');db.commit()
            elif 'bootstrap' in args:
                self.bootstrap += 1
            elif 'up' in args:
                assert '--no-deps' in args and 'bootstrap' not in args
                if 'previous.compose.json' in ' '.join(args):
                    if self.failed_recovery: raise RuntimeError('isolated recovery fault')
                    for name in old:
                        if name in args: actual[name] = deepcopy(old[name])
                else:
                    for name in SERVICES:
                        if name in args:
                            actual[name] = service(name, 'sha256:new')
                            if name in WORKERS:
                                actual[name]['Config']['Cmd'] = ['python', '-m', 'cloud_soc.deployment.worker', '--service', name]
                                actual[name]['Mounts'] = [{'Source': str(runtime/'state'/name), 'Destination': '/data'},
                                    {'Source': str(runtime/'keys'/(name+'.key')), 'Destination': '/run/keys/worker.key'}]
                    if self.fault == 'activation': raise RuntimeError('isolated activation fault')
                    if self.fault == 'row_loss' and 'portal' not in args:
                        with closing(sqlite3.connect(portal/'dashboards.sqlite')) as db:
                            db.execute('delete from dashboards');db.commit()
                    if 'portal' in args:
                        with closing(sqlite3.connect(portal/'dashboards.sqlite')) as db:
                            db.execute('update dashboards set revision=17');db.commit()
            return ''
        def json(self, args, **kwargs):
            if 'config' in args: return {'services': {name: {'image': plan['image_id']} for name in SERVICES}}
            if 'cloud_soc.deployment.migrations' in args:
                value = migrations.prerequisites(client, POLICY, plan['contract'], runtime,
                    {name: Path(row['key_source']).read_text().strip() for name, row in plan['adoption'].items() if 'key_source' in row},
                    notification_directory=state/'notifications')
                if self.fault == 'migration': raise RuntimeError('isolated post-migration interruption')
                return value
            raise AssertionError(args)
    engine = Engine();engine.calls = []
    monkeypatch.setattr(host, 'snapshot', lambda *_, **__: deepcopy(plan))
    monkeypatch.setattr(host, 'hardware', lambda *_: {'cpus': 4, 'memory_bytes': 32*1024**3,
        'available_memory_bytes': 20*1024**3, 'free_bytes': 100*1024**3, 'map_count': 262144})
    monkeypatch.setattr(host, 'storage_budget', lambda *_, **__: {'ok': engine.fault != 'space_after_backup', 'es_policy_source': 'actual_cluster'})
    monkeypatch.setattr(host, 'containers', lambda *_: deepcopy(actual))
    monkeypatch.setattr(host, 'lock', lambda _: nullcontext())
    def inventory(*_, stopped=False):
        result = {name: obj['Id'] for name, obj in actual.items() if name in ALL_WORKERS and obj['State']['Running']}
        if stopped and result: raise ValueError('duplicate worker')
        return result
    monkeypatch.setattr(host, 'worker_inventory', inventory)
    def immutable(*_, **kwargs):
        if kwargs.get('before') is not None and engine.fault == 'immutable_guard': raise ValueError('isolated evidence loss')
        return {'existing_immutable_documents_preserved': 21}
    monkeypatch.setattr(host, 'immutable_documents', immutable)
    def poll(engine, name, project):
        if engine.fault == 'readiness_'+name: raise RuntimeError('isolated '+name+' readiness failure')
    return state, runtime, plan, engine, client, actual, poll


@pytest.mark.parametrize('fault', ['none', 'online_backup', 'space_after_backup', 'stopped_backup', 'migration', 'activation',
                                 'readiness_kibana', 'readiness_portal', 'row_loss', 'immutable_guard', 'power_cut'])
def test_school_partial_upgrade_fault_matrix_preserves_originals_and_retries(tmp_path, monkeypatch, ownership_calls, fault):
    state, runtime, plan, engine, client, actual, poll = coordinator(tmp_path, monkeypatch)
    original = {Path(row['state_source']): Path(row['state_source']).read_bytes() for row in plan['adoption'].values() if 'state_source' in row}
    original.update({path: path.read_bytes() for path in (state/'tls').iterdir()})
    write = host.backup_database
    def backup(source, target):
        if (fault == 'online_backup' and 'online' in target.parts
                or fault == 'stopped_backup' and 'stopped' in target.parts):
            raise OSError('isolated backup disk full')
        write(source, target)
    monkeypatch.setattr(host, 'backup_database', backup)
    engine.fault = fault
    atomic = host.atomic_json
    def checkpoint(path, value, **kwargs):
        atomic(path, value, **kwargs)
        if fault == 'power_cut' and isinstance(value, dict) and value.get('stage') == 'background_readiness': raise KeyboardInterrupt()
    monkeypatch.setattr(host, 'atomic_json', checkpoint)
    if fault == 'none':
        assert host.apply(engine, plan, poll=poll)['runtime_ready']
        first_calls = len(engine.calls)
        assert host.apply(engine, plan, poll=poll)['unchanged']
        assert len(engine.calls) == first_calls and engine.bootstrap == 0
    else:
        with pytest.raises((RuntimeError, OSError, ValueError, KeyboardInterrupt)):
            host.apply(engine, plan, poll=poll)
        runs = sorted((runtime/'upgrades').iterdir());run = runs[-1]
        assert (run/'failed.json').exists() and not (runtime/'pending.json').exists()
        assert all(actual[name]['State']['Running'] for name in plan['service_classification']['stop'])
        assert all(path.read_bytes() == data for path, data in original.items())
        if fault in ('online_backup', 'space_after_backup'):
            assert not any('stop' in call or 'up' in call for call in engine.calls)
        if fault in ('migration', 'activation', 'readiness_kibana', 'readiness_portal', 'row_loss', 'immutable_guard', 'power_cut'):
            keys = {path.name: path.read_bytes() for path in (runtime/'keys').glob('*.key')}
            count = len(client.security.keys)
            engine.fault = None;monkeypatch.setattr(host, 'backup_database', write);monkeypatch.setattr(host, 'atomic_json', atomic)
            if fault in ('row_loss', 'immutable_guard'):
                assert (runtime/'preservation-failed.json').exists()
                with pytest.raises(ValueError, match='reconciliation'): host.apply(engine, plan, poll=poll)
                return
            assert host.apply(engine, plan, poll=poll)['runtime_ready']
            assert len(client.security.keys) == count
            assert all((runtime/'keys'/name).read_bytes() == value for name, value in keys.items())
    assert all(path.read_bytes() == data for path, data in original.items())
    assert engine.bootstrap == 0


def test_recovery_fails_twice_retains_journal_then_succeeds_without_bootstrap(tmp_path, monkeypatch, ownership_calls):
    state, runtime, plan, engine, client, actual, poll = coordinator(tmp_path, monkeypatch)
    engine.fault = 'activation';engine.failed_recovery = True
    with pytest.raises(RuntimeError): host.apply(engine, plan, poll=poll)
    pending = (runtime/'pending.json').read_bytes()
    with pytest.raises(RuntimeError): host.recover(engine, state)
    assert (runtime/'pending.json').read_bytes() == pending
    engine.failed_recovery = False
    assert host.recover(engine, state)['old_execution_restored']
    assert not (runtime/'pending.json').exists() and engine.bootstrap == 0


def test_fresh_install_bootstraps_exactly_once_and_converges_to_same_workers(tmp_path, monkeypatch, ownership_calls):
    state, runtime, plan, engine, client, actual, poll = coordinator(tmp_path, monkeypatch, fresh=True)
    assert host.apply(engine, plan, poll=poll)['runtime_ready']
    assert engine.bootstrap == 1 and set(actual) >= set(SERVICES)
    assert set(json.loads((runtime/'contract.json').read_text())['workers']) == set(WORKERS)
    assert host.apply(engine, plan, poll=poll)['unchanged'] and engine.bootstrap == 1
    assert json.loads((runtime/'current.json').read_text())['execution_sha256'] == digest({name: host.service_signature(obj) for name, obj in actual.items()})
