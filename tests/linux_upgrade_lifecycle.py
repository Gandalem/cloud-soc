"""Explicit real Docker/Compose acceptance on disposable local Linux resources.

Infrastructure probes are synthetic processes, not a claim of Elasticsearch or
live detection acceptance. Cleanup OFF executes the unmodified production entry.
Only containers carrying this invocation's project label are ever removed.
"""
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import time
import uuid

from cloud_soc.deployment import execution, host, migrations
from cloud_soc.deployment.contract import ALL_WORKERS, SERVICES, digest


IMAGE = 'cloud-soc:ci'


def wait(engine, project, names):
    deadline = time.monotonic()+45
    while time.monotonic() < deadline:
        objects = host.containers(engine, project)
        if all(name in objects and host.service_running(objects[name]) for name in names): return objects
        time.sleep(0.2)
    raise AssertionError('Disposable services did not become ready')


def main():
    assert os.name == 'posix' and os.geteuid() == 0
    engine = host.Docker();capabilities = execution.compose_capabilities(engine)
    image = engine.json(['image', 'inspect', IMAGE])[0]['Id']
    results = []
    for kind in ('managed', 'legacy', 'fresh'):
        project = 'soc-isolated-'+uuid.uuid4().hex[:10]
        with tempfile.TemporaryDirectory(prefix='soc-isolated-') as temporary:
            root = Path(temporary);runtime = root/'runtime';run = runtime/'upgrades/isolated';run.mkdir(parents=True)
            db = root/'preserved.sqlite'
            with sqlite3.connect(db) as connection:
                connection.execute('pragma journal_mode=wal');connection.execute('pragma wal_autocheckpoint=0')
                connection.execute('create table checkpoint(value)');connection.execute('insert into checkpoint values(73)');connection.commit()
                before = {p: p.read_bytes() for p in (db, Path(str(db)+'-wal'))}
                key = root/'synthetic.key';key.write_bytes(b'SYNTHETIC ONLY');key.chmod(0o600)
                secret_before = key.read_bytes()
                def recipe(names, phase):
                    rows = {}
                    for name in names:
                        row = {'image': IMAGE, 'user': '1000:1000', 'network_mode': 'none', 'mem_limit': '128m',
                            'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'],
                            'restart': 'unless-stopped', 'environment': {'PHASE': phase},
                            'command': ['python', '-c', 'import time;time.sleep(3600)',
                                        'cloud_soc.deployment.worker' if name in ALL_WORKERS else 'synthetic infrastructure'],
                            'healthcheck': {'test': ['CMD', 'python', '-c', 'print("ready")'], 'interval': '1s', 'timeout': '2s', 'retries': 20}}
                        if name == 'enrollment-cleanup':
                            row['environment']['SOC_ENROLLMENT_ENABLED'] = '0'
                            row['command'] = ['python', '/app/deploy/server/enrollment-maintenance.py']
                        if kind == 'legacy' and name in ('portal', 'detector'):
                            row['depends_on'] = {'bootstrap': {'condition': 'service_completed_successfully'}}
                        rows[name] = row
                    if kind == 'legacy':
                        rows['bootstrap'] = {'image': IMAGE, 'command': ['python', '-c', 'raise SystemExit("BOOTSTRAP MUST NEVER RUN")']}
                    return {'name': project, 'services': rows}
                old_names = list(SERVICES) if kind == 'managed' else ['elasticsearch', 'portal', 'gateway', 'kibana', 'detector', 'enrollment-cleanup']
                if kind == 'fresh': old_names = ['elasticsearch']
                old_path = root/'legacy.json';migrations.atomic_json(old_path, recipe(old_names, 'old'))
                active = ['--project-name', project, '-f', str(old_path)]
                new_path = root/'candidate.json';migrations.atomic_json(new_path, recipe(SERVICES, 'candidate'))
                canonical = ['compose', '--project-name', project, '-f', str(new_path)]
                try:
                    engine.run(['compose', *active, 'up', '-d', '--no-deps', '--no-build', '--pull', 'never', *old_names])
                    old = wait(engine, project, old_names)
                    rendered = engine.json(['compose', *active, 'config', '--format', 'json'])
                    classification, frozen = execution.verify_previous(engine, active, rendered, old, project)
                    frozen_path = run/'previous.compose.json';migrations.atomic_json(frozen_path, execution.literal_config(frozen))
                    # Only a subset is replaced; ES and a healthy worker must survive recovery.
                    changed = ['portal', 'kibana', 'enrollment-cleanup', 'detector-priority', 'slack-notifier']
                    engine.run(canonical+['up', '-d', '--no-deps', '--no-build', '--pull', 'never', *changed])
                    wait(engine, project, changed)
                    saved = {'previous_compose': active, 'recovery_compose': ['--project-name', project, '-f', str(frozen_path)],
                        'recovery_compose_sha256': host.backups.sha256(frozen_path),
                        'old_names': old_names, 'old_services': {name: host.service_signature(obj) for name, obj in old.items()},
                        'old_contract': None, 'old_current': None, 'canonical': canonical, 'environment': {}}
                    migrations.atomic_json(run/'recovery.json', saved)
                    migrations.atomic_json(runtime/'pending.json', {'run': str(run)})
                    assert host.recover(engine, root)['old_execution_restored']
                    restored = wait(engine, project, old_names)
                    assert restored['elasticsearch']['Id'] == old['elasticsearch']['Id']
                    if 'detector' in old: assert restored['detector']['Id'] == old['detector']['Id']
                    assert all(digest(host.service_signature(restored[name])) == digest(host.service_signature(old[name])) for name in old_names)
                    assert 'bootstrap' not in restored
                    assert all(path.read_bytes() == value for path, value in before.items()) and key.read_bytes() == secret_before
                    engine.run(canonical+['up', '-d', '--no-deps', '--no-build', '--pull', 'never', *SERVICES])
                    converged = wait(engine, project, SERVICES)
                    identifiers = {name: converged[name]['Id'] for name in SERVICES}
                    counters = {name: converged[name]['RestartCount'] for name in SERVICES}
                    engine.run(canonical+['up', '-d', '--no-deps', '--no-build', '--pull', 'never', *SERVICES])
                    time.sleep(3)
                    stable = wait(engine, project, SERVICES)
                    assert all(stable[name]['Id'] == identifiers[name] and stable[name]['RestartCount'] == counters[name]
                               and not stable[name]['State']['OOMKilled'] for name in SERVICES)
                    assert set(host.worker_inventory(engine, project)) == set(ALL_WORKERS)
                    assert len(SERVICES) == 12 and len(ALL_WORKERS) == 7
                    assert all(path.read_bytes() == value for path, value in before.items())
                    results.append({'type': kind, 'services': len(SERVICES), 'workers': len(ALL_WORKERS),
                        'bootstrap_executed': False, 'cleanup_off_stable': True, 'database_wal_key_preserved': True,
                        'healthy_es_not_recreated': True, 'same_config_reapply_recreates': False})
                finally:
                    # Only this random isolated project; never global prune or volume deletion.
                    identifiers = engine.run(['ps', '-aq', '--filter', 'label=com.docker.compose.project='+project]).split()
                    if identifiers: engine.run(['rm', '-f', *identifiers])
    print(json.dumps({'passed': True, 'real_docker': True, 'compose': capabilities, 'image_id': image,
                      'environments': results, 'backend': 'synthetic lifecycle probes; no live ES or Slack'}))


if __name__ == '__main__':
    main()
