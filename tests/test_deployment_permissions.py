"""Permission denial must propagate; only explicitly scoped unit doubles change ownership IO."""
import json
import os
from pathlib import Path
from unittest.mock import Mock

import pytest

from cloud_soc.deployment import host, migrations
from cloud_soc.deployment.contract import WORKERS, build_contract
from deployment_ownership import DeploymentOS, OwnershipCalls
from test_deployment_parity import FakeSetup, POLICY, NOW


def test_ownership_double_is_scoped_and_checks_targets_ids_and_modes(tmp_path, ownership_calls):
    assert host.os is not os and migrations.os is not os and host.os.name == 'posix'
    target = tmp_path/'private';target.mkdir(mode=0o700)
    host.os.chown(target, 1000, 1000)
    ownership_calls.expect(target)
    with pytest.raises(AssertionError):
        host.os.chown(target, 0, 0)
    with pytest.raises(AssertionError):
        host.os.chown(tmp_path.parent, 1000, 1000)
    if os.name == 'posix':
        target.chmod(0o755)
        with pytest.raises(AssertionError):
            host.os.chown(target, 1000, 1000)


def test_real_os_is_used_without_opt_in_fixture():
    assert host.os is os and migrations.os is os
    assert DeploymentOS(Mock()).name == 'posix'


def test_atomic_contract_ownership_failure_preserves_original_and_removes_temporary(tmp_path, monkeypatch):
    target = tmp_path/'contract.json';target.write_bytes(b'original contract')
    deny = Mock(side_effect=PermissionError('isolated ownership denial'))
    monkeypatch.setattr(migrations, 'os', DeploymentOS(deny))
    with pytest.raises(PermissionError):
        migrations.atomic_json(target, {'prepared': True}, uid=1000)
    assert target.read_bytes() == b'original contract'
    assert sorted(p.name for p in tmp_path.iterdir()) == ['contract.json']
    deny.assert_called_once()
    assert deny.call_args.args[1:] == (1000, 1000)


@pytest.mark.parametrize('fail_on', ['file', 'directory'])
def test_state_adoption_ownership_denial_preserves_live_wal_and_stops(tmp_path, monkeypatch, fail_on):
    import sqlite3
    source = tmp_path/'legacy';source.mkdir()
    db = source/'checkpoint.sqlite'
    with sqlite3.connect(db) as writer:
        writer.execute('pragma journal_mode=wal');writer.execute('pragma wal_autocheckpoint=0')
        writer.execute('create table checkpoint(value)');writer.execute('insert into checkpoint values(73)');writer.commit()
        before = {p: p.read_bytes() for p in (db, Path(str(db)+'-wal'))}
        calls = OwnershipCalls(tmp_path)
        def deny(path, uid, gid):
            calls.record(path, uid, gid)
            if Path(path).is_dir() == (fail_on == 'directory'):
                raise PermissionError('isolated ownership denial')
        monkeypatch.setattr(host, 'os', DeploymentOS(deny))
        runtime = tmp_path/'runtime'
        with pytest.raises(PermissionError):
            host.copy_adopted_state({'adoption': {'normalizer': {'state_source': str(db)}},
                                     'state': str(tmp_path)}, runtime)
        assert all(p.read_bytes() == data for p, data in before.items())
        assert not (runtime/'state'/WORKERS[1]).exists()  # Refuses to continue to the next worker.


@pytest.mark.parametrize('name', ['normalizer', 'slack-notifier'])
def test_key_ownership_failure_is_failed_migration_not_success(tmp_path, ownership_calls, name):
    def deny(path, uid, gid):
        ownership_calls.record(path, uid, gid)
        if Path(path).name == name+'.key':
            raise PermissionError('isolated ownership denial')
    ownership_calls.chown.side_effect = deny
    contract, _ = build_contract(POLICY, {}, tmp_path, now=NOW)
    with pytest.raises(PermissionError):
        migrations.prerequisites(FakeSetup(), POLICY, contract, tmp_path, {})
    ledger = json.loads((tmp_path/'migrations.json').read_text())
    assert ledger['version'] == 0
    step = POLICY['migrations'][0 if name == 'normalizer' else 2]
    assert ledger['migrations'][step]['state'] == 'failed'
    assert ledger['migrations'][step]['error_type'] == 'PermissionError'


@pytest.mark.parametrize('target', ['directory', 'database', 'encryption_key'])
def test_notification_ownership_denial_preserves_config_and_fails(tmp_path, ownership_calls, target):
    from test_slack_notifications import configured
    store, _ = configured(tmp_path)
    before_key = (store.directory/'slack.key').read_bytes()
    before_config = store.status()
    (tmp_path/'keys').mkdir()
    path = {'directory': store.directory, 'database': store.path,
            'encryption_key': store.directory/'slack.key'}[target]
    def deny(p, uid, gid):
        ownership_calls.record(p, uid, gid)
        if Path(p) == path:
            raise PermissionError('isolated ownership denial')
    ownership_calls.chown.side_effect = deny
    with pytest.raises(PermissionError):
        migrations.notification_prerequisites(FakeSetup(), tmp_path, notification_directory=store.directory)
    assert store.status() == before_config and (store.directory/'slack.key').read_bytes() == before_key
