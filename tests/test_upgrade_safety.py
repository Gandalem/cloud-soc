"""Pure disk policy, real WAL snapshots and interruption-safe key issuance."""
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloud_soc.deployment import backups, execution, host, migrations, resources
from cloud_soc.deployment.contract import build_contract, resource_check
from test_deployment_parity import FakeSetup, NOW, POLICY, seed

GIB = 1024**3


def settings():
    return {'defaults': {resources.DISK+'threshold_enabled': 'true',
        **{resources.DISK+'watermark.'+name: value for name, value in zip(resources.LEVELS, ('85%', '90%', '95%'))},
        **{resources.DISK+'watermark.'+name+'.max_headroom': value for name, value in zip(resources.LEVELS, ('200gb', '150gb', '100gb'))}}}


@pytest.mark.parametrize('value,expected', [('85%', '0.85'), ('0.85', '0.85'), ('.85', '0.85')])
def test_real_ratio_watermark_units(value, expected):
    assert resources.watermark(value) == {'kind': 'used_ratio', 'value': expected}


@pytest.mark.parametrize('value', ['NaN%', 'inf%', '100%', '0%', '1.0', '-1', 'bad', '2XB'])
def test_unknown_or_invalid_watermarks_fail_closed(value):
    with pytest.raises(ValueError):
        resources.watermark(value)


def test_settings_precedence_and_explicit_ratio_disables_implicit_headroom():
    data = settings();key = resources.DISK+'watermark.low'
    data['persistent'] = {key: '80%'};data['transient'] = {key: '82%'}
    observed = resources.disk_policy(data, {key: '81%'})
    assert observed['low']['value'] == '0.82' and observed['low']['max_headroom_bytes'] is None
    assert resources.free_floor(observed['low'], 2000*GIB) == 360*GIB
    data['transient'][key+'.max_headroom'] = '20gb'
    assert resources.free_floor(resources.disk_policy(data)['low'], 2000*GIB) == 20*GIB


@pytest.mark.parametrize('change', ['disabled', 'missing', 'mixed', 'inverted'])
def test_unverified_es_protection_is_never_bypassed(change):
    data = settings();default = data['defaults'];key = resources.DISK+'watermark.low'
    if change == 'disabled': default[resources.DISK+'threshold_enabled'] = 'false'
    if change == 'missing': del default[key]
    if change == 'mixed': default[key] = '20gb'
    if change == 'inverted': default[key] = '99%'
    with pytest.raises(ValueError): resources.disk_policy(data)


def locations(free=10*GIB, external=False):
    row = {'device': 'root', 'total_bytes': 50*GIB, 'free_bytes': free}
    result = {name: deepcopy(row) for name in ('state', 'scratch', 'backup', 'docker', 'elasticsearch')}
    if external: result['backup'] = {'device': 'backup', 'total_bytes': 100*GIB, 'free_bytes': 40*GIB}
    return result


def budget(paths, **overrides):
    options = dict(online_bytes=2*GIB, stopped_bytes=2*GIB, adoption_bytes=GIB, preflight_bytes=2*GIB,
                   build_bytes=0, ingress_bytes=GIB, safety_bytes=512*1024**2, es_policy=resources.disk_policy(settings()))
    return resources.disk_budget(paths, **(options | overrides))


def test_peak_fails_before_flood_and_does_not_double_count_existing_data():
    result = budget(locations())
    assert not result['ok']
    failure = next(row for row in result['issues'] if row['stage'] == 'state_adoption')
    assert failure['shortfall_bytes'] == int(3.5*GIB)
    assert result['stages']['state_adoption']['root']['additional_bytes'] == 6*GIB
    assert result['stages']['state_adoption']['root']['free_floors']['low'] == int(7.5*GIB)
    assert not result['existing_data_counted_as_additional']
    assert budget(locations(free=11*GIB, external=True))['ok']


def test_build_cost_is_retained_through_backup_peak_and_shared_device_charged_once():
    result = budget(locations(free=20*GIB), build_bytes=4*GIB)
    assert result['stages']['candidate_build']['root']['additional_bytes'] == 5*GIB
    assert result['stages']['state_adoption']['root']['additional_bytes'] == 10*GIB
    assert len(result['filesystems']) == 1 and result['ok']


def test_actual_byte_watermarks_and_missing_observation():
    data = settings()
    for name, value in zip(resources.LEVELS, ('8gb', '5gb', '2gb')):
        data['defaults'][resources.DISK+'watermark.'+name] = value
    result = budget(locations(), es_policy=resources.disk_policy(data))
    assert result['stages']['online_backup']['root']['free_floors']['low'] == 8*GIB
    with pytest.raises(ValueError, match='Actual ES'): budget(locations(), es_policy=None)


def test_external_backup_must_be_a_separate_device_even_if_directory_is_different(tmp_path):
    state = tmp_path/'state';other = tmp_path/'backups';state.mkdir();other.mkdir(mode=0o700)
    with pytest.raises(ValueError, match='same storage device'):
        resources.validate_backup_root(other, state, state, [])


def test_memory_shortage_reports_restore_peak_before_service_stop():
    machine = {'cpus': 4, 'memory_bytes': 8*GIB, 'available_memory_bytes': GIB,
               'managed_working_set_bytes': 7*GIB, 'free_bytes': 40*GIB, 'map_count': 262144}
    result = resource_check(POLICY, machine, fresh=False, backup_memory_bytes=2*GIB)
    assert 'backup_restore_memory_budget_exceeded' in result['issues']
    assert 'available_memory_budget_exceeded' not in result['issues']


def test_live_database_inventory_excludes_historical_and_unactivated_backups(tmp_path):
    objects = seed(tmp_path, ('normalizer', 'detector'))
    contract, adoption = build_contract(POLICY, objects, tmp_path, now=NOW)
    for relative in ('runtime/upgrades/failed/online/big.sqlite', 'copy/archive.sqlite',
                     'normalizer/checkpoint.sqlite.unactivated-01'):
        target = tmp_path/relative;target.parent.mkdir(parents=True, exist_ok=True);target.write_bytes(b'preserved')
    result = backups.inventory(tmp_path, contract, adoption)
    assert {row['relative'] for row in result} == {'normalizer/checkpoint.sqlite', 'detector/runtime.sqlite'}
    assert (tmp_path/'runtime/upgrades/failed/online/big.sqlite').read_bytes() == b'preserved'


def test_online_and_stopped_sets_deduplicate_only_verified_unchanged_wal_snapshots(tmp_path):
    state = tmp_path/'state';(state/'portal').mkdir(parents=True)
    source = state/'portal/dashboards.sqlite'
    with closing(sqlite3.connect(source)) as writer:
        writer.execute('pragma journal_mode=wal');writer.execute('pragma wal_autocheckpoint=0')
        writer.execute('create table dashboards(value)');writer.execute("insert into dashboards values('committed')");writer.commit()
        before = {path: path.read_bytes() for path in (source, Path(str(source)+'-wal'))}
        rows = backups.inventory(state, {'workers': {}}, {})
        online = backups.snapshot_set(rows, tmp_path/'online', host.backup_database)
        stopped = backups.snapshot_set(rows, tmp_path/'stopped', host.backup_database, previous=online)
        assert stopped['complete'] and stopped['physical_bytes'] == 0
        assert stopped['entries'][0]['shared_with_online'] == online['entries'][0]['path']
        assert all(path.read_bytes() == data for path, data in before.items())
        writer.execute("insert into dashboards values('later committed')");writer.commit()
        changed = backups.snapshot_set(rows, tmp_path/'changed', host.backup_database, previous=online)
        assert changed['physical_bytes'] > 0 and not changed['entries'][0]['shared_with_online']
        for receipt in (online, stopped, changed):
            with closing(sqlite3.connect(receipt['entries'][0]['path'])) as restored:
                assert restored.execute('pragma integrity_check').fetchall() == [('ok',)]


def test_backup_failure_keeps_incomplete_manifest_and_original_bytes(tmp_path):
    source = tmp_path/'source.sqlite'
    with closing(sqlite3.connect(source)) as db: db.execute('create table checkpoint(value)')
    before = source.read_bytes()
    def interrupt(source, destination):
        destination.write_bytes(b'incomplete');raise OSError('isolated disk full')
    with pytest.raises(OSError):
        backups.snapshot_set([{'path': str(source), 'relative': 'source.sqlite'}], tmp_path/'set', interrupt)
    assert source.read_bytes() == before
    assert not json.loads((tmp_path/'set/manifest.json').read_text())['complete']
    assert (tmp_path/'set/source.sqlite.partial').read_bytes() == b'incomplete'


@pytest.mark.parametrize('version', ['2.20.0', 'v2.24.7', '2.39.4-desktop.1'])
def test_supported_compose_versions(version):
    engine = Mock();engine.run.return_value = version
    assert execution.compose_capabilities(engine)['recovery_no_deps']


@pytest.mark.parametrize('version', ['1.29.2', '2.19.9', 'unknown', '3.0.0'])
def test_unsupported_compose_versions_fail_before_stop(version):
    engine = Mock();engine.run.return_value = version
    with pytest.raises(ValueError): execution.compose_capabilities(engine)


def test_active_definition_distinguishes_stopped_residue_and_running_unknown():
    active = {'services': {'portal': {}, 'detector': {}, 'bootstrap': {}}}
    objects = {'portal': {'State': {'Running': True}}, 'detector-priority': {'State': {'Running': False}}}
    result = execution.classify(active, objects)
    assert result['stop'] == ['portal'] and result['residual_stopped'] == ['detector-priority']
    objects['detector-priority']['State']['Running'] = True
    with pytest.raises(ValueError, match='outside active Compose'): execution.classify(active, objects)


def test_frozen_recipe_pins_image_and_preserves_literals_and_bootstrap_dependencies(tmp_path):
    path = tmp_path/'old.json';path.write_text('{}')
    obj = {'Image': 'sha256:old', 'State': {'Running': True}, 'Mounts': [],
        'Config': {'Cmd': ['python', 'portal.py'], 'Entrypoint': None, 'Env': ['PASSWORD=$literal'],
            'Labels': {'com.docker.compose.project': 'soc-test', 'com.docker.compose.project.config_files': str(path)}}}
    image = {'Id': obj['Image'], 'Config': {'Cmd': obj['Config']['Cmd'], 'Entrypoint': None, 'Env': obj['Config']['Env']}}
    rendered = {'services': {'portal': {'image': 'old:tag', 'depends_on': {'bootstrap': {'condition': 'service_completed_successfully'}}},
                              'bootstrap': {'image': 'old:tag'}}}
    engine = Mock();engine.json.return_value = [image]
    classification, frozen = execution.verify_previous(engine, ['-f', str(path)], rendered, {'portal': obj}, 'soc-test')
    assert classification['running'] == ['portal'] and frozen['services']['portal']['image'] == 'sha256:old'
    assert 'bootstrap' in frozen['services']['portal']['depends_on']
    assert execution.literal_config({'environment': {'PASSWORD': '$literal'}})['environment']['PASSWORD'] == '$$literal'


def test_uncertain_key_creation_never_reissues_on_retry(tmp_path):
    key = tmp_path/'worker.key';client = FakeSetup()
    original = client.security.create_api_key
    def lost_response(**kwargs):
        original(**kwargs);raise KeyboardInterrupt()
    client.security.create_api_key = lost_response
    with pytest.raises(KeyboardInterrupt): migrations.issue_key(client, key, name='isolated', role_descriptors={})
    assert len(client.security.keys) == 1 and not key.exists()
    with pytest.raises(ValueError, match='uncertain'): migrations.issue_key(client, key, name='isolated', role_descriptors={})
    with pytest.raises(ValueError, match='uncertain'): migrations.reusable_key(key)
    assert len(client.security.keys) == 1


def test_durable_issued_key_resumes_after_interruption_without_new_secret(tmp_path, monkeypatch, ownership_calls):
    key = tmp_path/'worker.key';client = FakeSetup();write = migrations.atomic_json
    def interrupt(path, value, **kwargs):
        write(path, value, **kwargs)
        if value.get('state') == 'persisted': raise KeyboardInterrupt()
    monkeypatch.setattr(migrations, 'atomic_json', interrupt)
    with pytest.raises(KeyboardInterrupt): migrations.issue_key(client, key, name='isolated', role_descriptors={})
    encoded = migrations.reusable_key(key)
    monkeypatch.setattr(migrations, 'atomic_json', write)
    assert migrations.issue_key(client, key, name='isolated', role_descriptors={}) == encoded
    assert len(client.security.keys) == 1 and key.stat().st_nlink == 1
    assert migrations.issue_key(client, key, name='isolated', role_descriptors={}) == encoded
    assert len(client.security.keys) == 1


def test_partial_key_publication_and_drift_never_pass_preflight(tmp_path, ownership_calls):
    key = tmp_path/'worker.key';client = FakeSetup()
    migrations.issue_key(client, key, name='isolated', role_descriptors={})
    key.write_text('partial')
    with pytest.raises(ValueError): migrations.reusable_key(key)
    with pytest.raises(ValueError): migrations.issue_key(client, key, name='isolated', role_descriptors={})
    assert len(client.security.keys) == 1


def test_es_disk_observation_is_read_only_and_rejects_incomplete_remote_topology():
    client = Mock();client.cluster.get_settings.return_value = SimpleNamespace(body=settings())
    client.nodes.info.return_value = SimpleNamespace(body={'nodes': {'one': {'settings': {}}}})
    client.nodes.stats.return_value = SimpleNamespace(body={'nodes': {'one': {'fs': {'data': [
        {'path': '/data', 'total_in_bytes': 50*GIB, 'available_in_bytes': 10*GIB}]}}}})
    assert resources.es_disk_observation(client)['policy']['low']['configured_value'] == '85%'
    assert not client.cluster.put_settings.called
    client.nodes.stats.return_value.body['_nodes'] = {'failed': 1}
    with pytest.raises(ValueError, match='Partial'): resources.es_disk_observation(client)


def test_allocated_backup_inventory_counts_hardlinks_once(tmp_path):
    original = tmp_path/'one';original.write_bytes(b'x'*4096);os.link(original, tmp_path/'two')
    assert backups.allocated_bytes(tmp_path) == getattr(original.stat(), 'st_blocks', 8)*512


@pytest.mark.parametrize('kill_at', ['remote_success', 'local_persisted'])
def test_process_exit_during_api_issuance_leaves_durable_recoverable_evidence(tmp_path, ownership_calls, kill_at):
    root = Path(__file__).resolve().parents[1]
    program = '''import json,os,sys
from pathlib import Path
from cloud_soc.deployment import migrations
from test_deployment_parity import FakeSetup
root=Path(sys.argv[1]);client=FakeSetup();kind=sys.argv[2]
create=client.security.create_api_key;atomic=migrations.atomic_json
def remote(**kw):
    result=create(**kw)
    migrations.atomic_json(root/'remote.json',{'id':result.body['id']})
    if kind=='remote_success':os._exit(23)
    return result
def persist(path,value,**kw):
    atomic(path,value,**kw)
    if value.get('state')=='persisted':os._exit(23)
client.security.create_api_key=remote;migrations.atomic_json=persist
migrations.issue_key(client,root/'worker.key',name='synthetic',role_descriptors={})
'''
    result = subprocess.run([sys.executable, '-c', program, str(tmp_path), kill_at],
        env={**os.environ, 'PYTHONPATH': os.pathsep.join([str(root/'src'), str(root/'tests')])},
        capture_output=True, timeout=15)
    assert result.returncode == 23, result.stderr.decode(errors='replace')
    assert json.loads((tmp_path/'remote.json').read_text())['id'] == 'new-0'
    client = FakeSetup()
    if kill_at == 'remote_success':
        with pytest.raises(ValueError, match='uncertain'): migrations.issue_key(client, tmp_path/'worker.key', name='synthetic', role_descriptors={})
    else:
        encoded = migrations.reusable_key(tmp_path/'worker.key')
        assert migrations.issue_key(client, tmp_path/'worker.key', name='synthetic', role_descriptors={}) == encoded
    assert not client.security.events  # A second remote API call never occurred.


def test_committed_concurrent_dashboard_transaction_becomes_quiesced_baseline(tmp_path):
    portal = tmp_path/'portal';portal.mkdir();path = portal/'dashboards.sqlite'
    with closing(sqlite3.connect(path)) as db:
        db.execute('pragma journal_mode=wal');db.execute('create table dashboard(id,revision)')
        db.execute('insert into dashboard values(1,15)');db.commit()
    pending = threading.Event();commit = threading.Event();failures = []
    def writer():
        try:
            with closing(sqlite3.connect(path)) as db:
                db.execute('update dashboard set revision=16');pending.set()
                assert commit.wait(10);db.commit()
        except BaseException as error: failures.append(error)
    thread = threading.Thread(target=writer);thread.start()
    try:
        assert pending.wait(10)
        online = host.portal_rows(tmp_path)  # Does not see the uncommitted revision.
        commit.set();thread.join(10);assert not thread.is_alive() and not failures
        quiesced = host.portal_rows(tmp_path)
        assert online != quiesced
        assert host.portal_rows(tmp_path) == quiesced
        with closing(sqlite3.connect(path)) as db: db.execute('delete from dashboard');db.commit()
        assert not set(quiesced['dashboards.sqlite']) <= set(host.portal_rows(tmp_path)['dashboards.sqlite'])
    finally:
        commit.set();thread.join(10)


@pytest.mark.parametrize('name', ['normalizer', 'slack-notifier'])
def test_key_ownership_failure_resumes_same_issued_key_without_rotation(tmp_path, ownership_calls, name):
    client = FakeSetup();contract, _ = build_contract(POLICY, {}, tmp_path, now=NOW)
    def denied(path, uid, gid):
        ownership_calls.record(path, uid, gid)
        if Path(path).name == name+'.key': raise PermissionError('isolated publication failure')
    ownership_calls.chown.side_effect = denied
    with pytest.raises(PermissionError): migrations.prerequisites(client, POLICY, contract, tmp_path, {})
    key = tmp_path/'keys'/(name+'.key');encoded = key.read_bytes();identifier = migrations.key_id(encoded.decode().strip())
    ownership_calls.chown.side_effect = ownership_calls.record
    migrations.prerequisites(client, POLICY, contract, tmp_path, {})
    assert key.read_bytes() == encoded and identifier in client.security.keys
    assert sum(event == ('key_create', identifier) for event in client.security.events) == 1
    assert not any(event[0] == 'invalidate' for event in client.security.events)


def snapshot_without_containers(tmp_path, monkeypatch):
    (tmp_path/'compose.env').write_text('')
    monkeypatch.setattr(host, 'containers', lambda *_: {})
    monkeypatch.setattr(host, 'worker_inventory', lambda *_: {})
    monkeypatch.setattr(execution, 'compose_capabilities', lambda *_: {'version': '2.40.3'})
    return Mock(), Path(__file__).resolve().parents[1]


def test_deleted_containers_do_not_turn_managed_data_into_a_fresh_install(tmp_path, monkeypatch):
    engine, root = snapshot_without_containers(tmp_path, monkeypatch)
    runtime = tmp_path/'runtime';runtime.mkdir();(runtime/'current.json').write_text('{}')
    contract, _ = build_contract(POLICY, {}, tmp_path, now=NOW)
    (runtime/'contract.json').write_text(json.dumps(contract))
    monkeypatch.setattr(host, 'hardware', lambda *_: {})
    def inspect_storage(*_, **kwargs):
        assert kwargs['fresh'] is False
        raise ValueError('existing installation requires storage and recovery inspection')
    monkeypatch.setattr(host, 'storage_budget', inspect_storage)
    with pytest.raises(ValueError, match='existing installation'): host.snapshot(engine, root, tmp_path, 'fixture')
    engine.run.assert_not_called()


def test_unrecorded_existing_databases_never_bootstrap_as_fresh(tmp_path, monkeypatch):
    engine, root = snapshot_without_containers(tmp_path, monkeypatch)
    portal = tmp_path/'portal';portal.mkdir()
    with closing(sqlite3.connect(portal/'cases.sqlite')) as db: db.execute('create table saved(value)')
    with pytest.raises(ValueError, match='fresh bootstrap refused'): host.snapshot(engine, root, tmp_path, 'fixture')
    engine.run.assert_not_called()


def test_active_receipt_can_use_a_separate_candidate_source_and_rejects_actions(tmp_path):
    state = tmp_path/'data/site/state';runtime = state/'runtime';runtime.mkdir(parents=True)
    source = tmp_path/'releases/candidate/compose.json';source.parent.mkdir(parents=True);source.write_text('{}')
    args = ['docker', 'compose', '--project-name', 'soc-test', '-f', str(source)]
    (runtime/'compose.active.json').write_text(json.dumps(args))
    objects = {'portal': {'Config': {'Labels': {'com.docker.compose.project.config_files': str(source)}}}}
    assert host.active_command(state, objects) == args[2:]
    (runtime/'compose.active.json').write_text(json.dumps(args+['run', 'bootstrap']))
    with pytest.raises(ValueError, match='global options'): host.active_command(state, objects)


@pytest.mark.parametrize('command', [None, ['python', 'portal.py'], []])
def test_compose_null_command_inherits_image_but_empty_list_suppresses_it(tmp_path, command):
    path = tmp_path/'compose.json';path.write_text('{}')
    default = ['python', 'portal.py'];actual = default if command is None else command
    config = {'Cmd': actual, 'Entrypoint': ['tini', '--'], 'Env': [], 'Labels': {
        'com.docker.compose.project': 'soc-test', 'com.docker.compose.project.config_files': str(path)}}
    obj = {'Image': 'old', 'Config': config, 'State': {'Running': True}, 'Mounts': []}
    engine = Mock();engine.json.return_value = [{'Id': 'old', 'Config': {'Cmd': default, 'Entrypoint': ['tini', '--'], 'Env': []}}]
    row = {'services': {'portal': {'image': 'old', 'command': command, 'entrypoint': None}}}
    _, frozen = execution.verify_previous(engine, ['-f', str(path)], row, {'portal': obj}, 'soc-test')
    assert frozen['services']['portal']['image'] == 'old'
    obj['Config']['Cmd'] = ['unexpected']
    with pytest.raises(ValueError, match='command differs'):
        execution.verify_previous(engine, ['-f', str(path)], row, {'portal': obj}, 'soc-test')


@pytest.mark.parametrize('filesystem', ['btrfs', 'zfs', 'nfs', 'cifs', 'overlay', 'tmpfs'])
def test_shared_remote_or_volatile_allocation_pools_are_not_mistaken_for_independent_devices(filesystem):
    mountinfo = '1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 0:45 / /state rw - '+filesystem+' shared rw\n'
    with pytest.raises(ValueError, match='allocation accounting'):
        resources.allocation_filesystem(Path('/state/data'), mountinfo)


def test_native_filesystem_mount_identity_is_reported_and_bind_paths_share_capacity():
    mountinfo = '1 0 8:1 / / rw - ext4 /dev/root rw\n2 1 8:1 /backup /separate\\040folder rw - ext4 /dev/root rw\n'
    result = resources.allocation_filesystem(Path('/separate folder/backup'), mountinfo)
    assert result == {'filesystem': 'ext4', 'mount_source': '/dev/root', 'mount_device': '8:1'}


def test_fresh_large_disk_cannot_use_only_the_small_install_free_space_floor():
    paths = locations(free=20*GIB)
    for row in paths.values(): row['total_bytes'] = 1000*GIB
    result = budget(paths, online_bytes=0, stopped_bytes=0, adoption_bytes=0,
                    preflight_bytes=0, es_policy=resources.initial_disk_policy())
    assert not result['ok']
    assert result['stages']['candidate_build']['root']['free_floors']['low'] == 150*GIB


def test_docker_mount_order_does_not_make_an_unchanged_plan_stale_but_mount_changes_do():
    from cloud_soc.deployment.contract import digest
    mounts = [{'Destination': '/data', 'Source': '/state/database', 'RW': True, 'Type': 'bind'},
              {'Destination': '/key', 'Source': '/state/key', 'RW': False, 'Type': 'bind'}]
    obj = {'Id': 'same', 'Image': 'same', 'Config': {'Cmd': ['python', 'worker'], 'Env': []}, 'Mounts': mounts}
    before = digest(host.observed_services({'worker': obj}))
    obj['Mounts'] = list(reversed(mounts))
    assert digest(host.observed_services({'worker': obj})) == before
    obj['Mounts'][0]['RW'] = True
    assert digest(host.observed_services({'worker': obj})) != before
