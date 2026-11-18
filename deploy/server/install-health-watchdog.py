"""Install/update the independent monitor only; never restart the SOC workload."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess


def docker_info(name):
    return json.loads(subprocess.check_output(['docker', 'inspect', name]))[0]


def install(workspace, state, *, apply=False):
    workspace, state = workspace.resolve(), state.resolve()
    portal = docker_info('cloud-soc-central-portal-1')
    es = docker_info('cloud-soc-central-elasticsearch-1')
    mounts = {m['Destination']: m['Source'] for m in portal['Mounts']}
    if Path(mounts['/data']).resolve() != state / 'portal':
        raise ValueError('Existing Portal state required')
    networks = set(portal['NetworkSettings']['Networks']) & set(es['NetworkSettings']['Networks'])
    if len(networks) != 1:
        raise ValueError('Exact existing ES network required')
    directory = state / 'health-watchdog'
    sources = {'host.py': workspace / 'deploy/server/health-watchdog-host.py',
               'probe.py': workspace / 'src/cloud_soc/health/watchdog.py'}
    hashes = {k: hashlib.sha256(v.read_bytes()).hexdigest() for k, v in sources.items()}
    cfg = {'image': portal['Image'], 'network': next(iter(networks)), 'state': str(directory),
           'probe': str(directory / 'probe.py'), 'disk_path': str(state),
           'ca': mounts['/run/certs/ca.crt'], 'password': mounts['/run/secrets/monitor_password'],
           'notifications': mounts['/notifications']}
    for key in ('ca', 'password', 'notifications'):
        p = Path(cfg[key])
        if not p.exists() or p.is_symlink() or ',' in str(p):
            raise ValueError('Existing private mounts required')
    if not apply:
        return {'apply': False, 'image': cfg['image'], 'files': hashes, 'interval_seconds': 60}
    directory.mkdir(mode=0o700, exist_ok=True)
    if directory.is_symlink():
        raise ValueError('Unsafe state directory')
    os.chmod(directory, 0o700)
    for name, source in sources.items():
        target = directory / name
        if target.is_symlink():
            raise ValueError('Unsafe monitor file')
        temp = target.with_suffix('.new')
        if temp.is_symlink():
            raise ValueError('Unsafe staged file')
        shutil.copyfile(source, temp)
        os.chmod(temp, 0o600)
        os.replace(temp, target)
    config = directory / 'config.json'
    if config.is_symlink():
        raise ValueError('Unsafe configuration')
    config.write_text(json.dumps(cfg))
    os.chmod(config, 0o600)
    # Paths with whitespace cannot safely be interpolated into systemd ExecStart.
    if any(c.isspace() for c in str(directory)):
        raise ValueError('Monitor path must not contain whitespace')
    service = '[Unit]\nDescription=Cloud SOC independent pipeline watchdog\nAfter=docker.service network-online.target\n\n[Service]\nType=oneshot\nUMask=0077\nTimeoutStartSec=180\nExecStart=/usr/bin/python3 ' + str(directory / 'host.py') + ' --config ' + str(config) + '\n'
    timer = '[Unit]\nDescription=Check Cloud SOC pipeline every minute\n\n[Timer]\nOnBootSec=60\nOnUnitInactiveSec=60\nAccuracySec=5\nUnit=cloud-soc-health-watchdog.service\n\n[Install]\nWantedBy=timers.target\n'
    for name, text in [('cloud-soc-health-watchdog.service', service), ('cloud-soc-health-watchdog.timer', timer)]:
        path = Path('/etc/systemd/system') / name
        if path.is_symlink():
            raise ValueError('Unsafe unit file')
        path.write_text(text)
        os.chmod(path, 0o644)
    subprocess.run(['systemctl', 'daemon-reload'], check=True)
    # Validate a complete metrics read before enabling the recurring job.
    probe = subprocess.run(['/usr/bin/python3', str(directory / 'host.py'), '--config', str(config), '--dry-run'],
                           capture_output=True, text=True, timeout=170)
    if probe.returncode:
        raise ValueError('Monitor preflight failed; timer not enabled')
    report = json.loads(probe.stdout)
    metrics = report['sample']
    if metrics['input'] is None or metrics['workers'] is None:
        raise ValueError('Monitor read permissions/metrics unavailable; timer not enabled')
    if not report['notification_configured']:
        raise ValueError('Existing Slack destination must be enabled; timer not enabled')
    subprocess.run(['systemctl', 'enable', '--now', 'cloud-soc-health-watchdog.timer'], check=True,
                   capture_output=True)
    return {'apply': True, 'image': cfg['image'], 'files': hashes, 'metrics': metrics,
            'timer_enabled': True, 'notification_destination': 'existing_enabled_slack_only'}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--apply', action='store_true')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('Approved host root required')
    print(json.dumps(install(args.workspace, args.state, apply=args.apply)))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('health_watchdog_install_failed; existing SOC services unchanged; protected details omitted') from None
