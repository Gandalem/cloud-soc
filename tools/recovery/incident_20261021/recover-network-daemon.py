"""Quarantine damaged network metadata; keep all containers and data volumes."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import sys


def run(args, timeout=20):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def atomic(path, data):
    st = path.stat()
    fd, temporary = tempfile.mkstemp(prefix='.recovery-', dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.chown(temporary, st.st_uid, st.st_gid)
        os.chmod(temporary, st.st_mode & 0o777)
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def main():
    if sys.argv[1:] != ['--disable-restart-only']:
        raise SystemExit('Use --disable-restart-only; network replacement is disabled in this step.')
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo python3.')
    os.umask(0o077)
    marker = Path('/var/tmp/cloud-soc-network-recovery-active.json')
    if marker.exists():
        raise SystemExit('Recovery already recorded; do not rerun. Report marker exists.')
    plans = []
    for p in Path('/var/tmp').glob('cloud-soc-network-plan-*/plan.json'):
        d = json.loads(p.read_text())
        if d.get('ready_for_network_rebuild') and not d.get('issues'):
            plans.append(p)
    if not plans:
        raise SystemExit('No successful preparation plan found.')
    plan = max(plans, key=lambda p: p.stat().st_mtime_ns)
    if run(['systemctl', 'stop', 'docker.socket', 'docker.service']).returncode:
        raise SystemExit('Could not stop Docker units.')
    if run(['pgrep', '-x', 'dockerd']).returncode == 0:
        raise SystemExit('dockerd still running.')
    if run(['systemctl', 'is-active', '--quiet', 'containerd.service']).returncode:
        raise SystemExit('containerd is not active.')
    live = Path('/var/lib/docker/network/files/local-kv.db')
    if live.is_symlink() or not live.is_file():
        raise SystemExit('Expected regular network database missing.')
    root = Path(tempfile.mkdtemp(prefix='cloud-soc-network-recovery-', dir='/var/tmp'))
    shutil.copytree(live.parent, root / 'network-files', copy_function=shutil.copy2)
    digest = hashlib.sha256(live.read_bytes()).hexdigest()
    if hashlib.sha256((root / 'network-files/local-kv.db').read_bytes()).hexdigest() != digest:
        raise SystemExit('Backup hash mismatch.')
    saved = []
    configs = list(Path('/var/lib/docker/containers').glob('*/hostconfig.json'))
    if len(configs) != 14:
        raise SystemExit('Unexpected container count; no policies changed.')
    for p in configs:
        c = json.loads((p.parent / 'config.v2.json').read_text())
        h = json.loads(p.read_text())
        folder = root / 'containers' / p.parent.name
        folder.mkdir(parents=True)
        shutil.copy2(p, folder / p.name)
        shutil.copy2(p.parent / 'config.v2.json', folder / 'config.v2.json')
        saved.append({'id': p.parent.name, 'name': c.get('Name'),
                      'restart_policy': h.get('RestartPolicy')})
    receipt = {'backup_directory': str(root), 'plan_directory': str(plan.parent),
               'network_db_sha256': digest, 'containers': saved,
               'stage': 'backed_up'}
    marker.write_text(json.dumps(receipt, indent=2))
    for p in configs:
        h = json.loads(p.read_text())
        h['RestartPolicy'] = {'Name': 'no', 'MaximumRetryCount': 0}
        atomic(p, h)
    receipt['stage'] = 'restart_policies_disabled'
    atomic(marker, receipt)
    print(json.dumps({'restart_policies_disabled': len(saved),
                      'backup_directory': str(root), 'network_db_changed': False,
                      'docker_started': False, 'receipt': str(marker)}))
    return
    # Move instead of deleting: both the verified backup and exact original remain.
    live.rename(root / 'local-kv.original.db')
    receipt['stage'] = 'network_db_quarantined'
    atomic(marker, receipt)
    run(['systemctl', 'reset-failed', 'docker.socket', 'docker.service'])
    started = run(['systemctl', 'start', '--no-block', 'docker.socket', 'docker.service'])
    if started.returncode:
        raise RuntimeError('start_request_failed')
    ready = False
    deadline = time.monotonic() + 45
    while time.monotonic() < deadline:
        try:
            if run(['docker', 'info', '--format', '{{.ServerVersion}}'], timeout=3).returncode == 0:
                ready = True
                break
        except subprocess.TimeoutExpired:
            pass
        if run(['systemctl', 'is-failed', '--quiet', 'docker.service']).returncode == 0:
            break
        time.sleep(2)
    receipt['stage'] = 'docker_ready' if ready else 'docker_start_failed'
    atomic(marker, receipt)
    print(json.dumps({'docker_ready': ready, 'backup_directory': str(root),
                      'plan_directory': str(plan.parent), 'restart_policies_disabled': len(saved),
                      'application_containers_recreated': False}))
    if not ready:
        run(['systemctl', 'stop', 'docker.socket', 'docker.service'])
        log = run(['journalctl', '-u', 'docker.service', '-b', '-n', '100', '--no-pager', '-o', 'cat'])
        (root / 'docker-start-private.log').write_text(log.stdout + log.stderr)
        print('Docker stopped after failed startup. Keep the snapshot and report this output.')
        return
    status = run(['docker', 'ps', '-a', '--format', 'table {{.Names}}\t{{.Status}}'], timeout=15)
    if status.returncode:
        raise RuntimeError('status_query_failed')
    print(status.stdout)
    print('Do not run compose up yet. Application data and existing containers were retained.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'recovery_stopped': type(error).__name__,
                          'receipt': '/var/tmp/cloud-soc-network-recovery-active.json'}))
        raise SystemExit(1)
