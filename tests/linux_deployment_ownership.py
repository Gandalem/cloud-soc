"""Explicit root-container acceptance; not an automatically skipped pytest test.

No fixtures or ownership mocks are loaded. The container has no host mounts/network.
"""
import inspect
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import tempfile

from cloud_soc.deployment import host, migrations
from cloud_soc.deployment.contract import ALL_WORKERS, WORKERS, build_contract
from cloud_soc.notifications.store import SlackStore
from test_deployment_parity import FakeSetup, POLICY, NOW
from test_slack_notifications import URL


def owned(path, *, uid=1000, mode=0o600):
    info = path.stat()
    assert (info.st_uid, info.st_gid, stat.S_IMODE(info.st_mode)) == (uid, uid, mode), str(path)


def access(path, uid, allowed):
    # Enter the bind-equivalent directory before dropping privileges. No inherited file handle bypasses access.
    program = '''import os,sys
os.chdir(sys.argv[1]);os.setgroups([]);os.setgid(int(sys.argv[3]));os.setuid(int(sys.argv[3]))
try:
    with open(sys.argv[2], 'rb') as f:f.read(1)
except PermissionError:
    assert sys.argv[4]=='deny'
else:
    assert sys.argv[4]=='allow'
'''
    subprocess.run([sys.executable, '-c', program, str(path.parent), path.name, str(uid),
                    'allow' if allowed else 'deny'], check=True, timeout=10)


def main():
    assert os.name == 'posix' and os.geteuid() == 0, 'Explicit root Linux container is required'
    assert host.os is os and migrations.os is os and inspect.isbuiltin(os.chown), 'Real ownership IO required'
    checked = 0
    with tempfile.TemporaryDirectory(prefix='soc-ownership-') as temporary:
        root = Path(temporary)
        root.chmod(0o711)  # Only a disposable parent; child probes may traverse to their private targets.
        contract = root/'contract.json'
        migrations.atomic_json(contract, {'prepared': True}, uid=1000)
        owned(contract);access(contract, 1000, True);access(contract, 1001, False);checked += 1
        # An unprivileged writer can create a temp file but cannot assign UID/GID1000.
        denied = root/'denied';denied.mkdir(mode=0o700);os.chown(denied, 1001, 1001)
        old = denied/'contract.json';old.write_bytes(b'preserved');old.chmod(0o600);os.chown(old, 1001, 1001)
        program = '''import os,sys
from pathlib import Path
from cloud_soc.deployment.migrations import atomic_json
os.chdir(sys.argv[1]);os.setgroups([]);os.setgid(1001);os.setuid(1001)
try:atomic_json(Path('contract.json'), {'prepared':True}, uid=1000)
except PermissionError:pass
else:raise AssertionError('Ownership failure was ignored')
assert Path('contract.json').read_bytes()==b'preserved'
assert [p.name for p in Path('.').iterdir()]==['contract.json']
'''
        subprocess.run([sys.executable, '-c', program, str(denied)], check=True, timeout=10)
        owned(old, uid=1001);checked += 1
        state = root/'state';source = state/'legacy';source.mkdir(parents=True, mode=0o700)
        database = source/'checkpoint.sqlite';runtime = state/'runtime'
        with sqlite3.connect(database) as writer:
            writer.execute('pragma journal_mode=wal');writer.execute('pragma wal_autocheckpoint=0')
            writer.execute('create table checkpoint(value)');writer.execute('insert into checkpoint values(73)');writer.commit()
            before = {p: p.read_bytes() for p in (database, Path(str(database)+'-wal'))}
            host.copy_adopted_state({'adoption': {'normalizer': {'state_source': str(database)}},
                                     'state': str(state)}, runtime)
            assert all(p.read_bytes() == data for p, data in before.items())
        copied = runtime/'state/normalizer/checkpoint.sqlite'
        owned(copied);access(copied, 1000, True);access(copied, 1001, False);checked += 1
        with sqlite3.connect(copied) as connection:
            assert connection.execute('select value from checkpoint').fetchall() == [(73,)]
        for name in WORKERS:
            owned(runtime/'state'/name, mode=0o700);checked += 1
        # Real ownership for all worker keys and notifier directory/DB/encryption key.
        directory = root/'migration';directory.mkdir(mode=0o700)
        folder = root/'notifications';store = SlackStore(folder)
        store.save({'revision': 0, 'webhook_url': URL, 'enabled': True, 'minimum_severity': 'high'},
                   check_address=lambda: None)
        store.test()  # Queued synthetic payload only. No transport/Slack request is called.
        key_bytes = (folder/'slack.key').read_bytes()
        with store.connect() as db:
            original = [tuple(row) for row in db.execute('select * from outbox')]
            cfg = tuple(db.execute('select * from config').fetchone())
        client = FakeSetup();value, _ = build_contract(POLICY, {}, directory, now=NOW)
        first = migrations.prerequisites(client, POLICY, value, directory, {}, notification_directory=folder)
        keys = {name: (directory/'keys'/(name+'.key')).read_bytes() for name in ALL_WORKERS}
        for name in ALL_WORKERS:
            owned(directory/'keys'/(name+'.key'));checked += 1
        for path in (folder/'slack.key', store.path):
            owned(path);access(path, 1000, True);access(path, 1001, False);checked += 1
        owned(folder, mode=0o700);checked += 1
        again = migrations.prerequisites(client, POLICY, value, directory, {}, notification_directory=folder)
        assert first == again and (folder/'slack.key').read_bytes() == key_bytes
        assert all((directory/'keys'/(name+'.key')).read_bytes() == data for name, data in keys.items())
        with store.connect() as db:
            assert [tuple(row) for row in db.execute('select * from outbox')] == original
            assert tuple(db.execute('select * from config').fetchone()) == cfg
    print(json.dumps({'result': 'passed', 'real_uid_gid_mode_checks': checked,
                      'application_uid_gid': [1000, 1000], 'unrelated_uid_denied': 1001,
                      'unprivileged_atomic_chown': 'PermissionError; original preserved; temp removed',
                      'wal_keys_config_outbox_preserved': True, 'os_chown_mocked': False}))


if __name__ == '__main__':
    main()
