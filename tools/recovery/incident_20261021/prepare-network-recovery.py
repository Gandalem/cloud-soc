"""Render and validate a recovery configuration. Never contact/start Docker daemon."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import traceback

BASE = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent')
STATE = Path('/home/lyn/cloud-soc/state/server')
PROJECT = 'cloud-soc-central'


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo python3.')
    for p in Path('/proc').glob('[0-9]*/comm'):
        try:
            if p.read_text().strip() == 'dockerd':
                raise SystemExit('Docker must remain stopped.')
        except (FileNotFoundError, ProcessLookupError):
            pass
    os.umask(0o077)
    target = Path(tempfile.mkdtemp(prefix='cloud-soc-network-plan-', dir='/var/tmp'))
    actual = {}
    for p in Path('/var/lib/docker/containers').glob('*/config.v2.json'):
        c = json.loads(p.read_text())
        labels = c.get('Config', {}).get('Labels') or {}
        if labels.get('com.docker.compose.project') == PROJECT:
            service = labels['com.docker.compose.service']
            if service in actual:
                raise ValueError('Duplicate service')
            actual[service] = c
    expected = {'elasticsearch', 'kibana', 'gateway', 'portal', 'normalizer',
                'normalizer-priority', 'detector', 'detector-priority',
                'detector-additional', 'detector-retrospective', 'slack-notifier',
                'enrollment-cleanup'}
    if set(actual) != expected:
        raise ValueError('Unexpected service inventory')
    overlay = {'services': {}, 'volumes': {}}
    for service, c in actual.items():
        config = c['Config']
        overlay['services'][service] = {
            'image': c['Image'],
            'environment': dict(v.split('=', 1) for v in config.get('Env', []) if '=' in v),
            'command': config.get('Cmd') or [],
            'entrypoint': config.get('Entrypoint') or [],
        }
        if service == 'enrollment-cleanup':
            overlay['services'][service].update(restart='no', profiles=['disabled-enrollment'])
        for mount in (c.get('MountPoints') or {}).values():
            source = Path(mount['Source'])
            if not source.exists():
                raise ValueError('Missing mount source for ' + service)
            if mount.get('Type') == 'volume':
                name = mount['Name']
                prefix = PROJECT + '_'
                if not name.startswith(prefix):
                    raise ValueError('Unexpected volume name')
                overlay['volumes'][name[len(prefix):]] = {'name': name, 'external': True}
                if not any(source.iterdir()):
                    raise ValueError('Empty existing volume for ' + service)
    pins = target / 'preserve.json'
    pins.write_text(json.dumps(overlay))
    command = ['docker', 'compose', '--project-name', PROJECT, '--env-file',
               str(STATE / 'compose.env'), '-f', str(BASE / 'outputs/cloud-soc/deploy/server/compose.yaml'),
               '-f', str(STATE / 'runtime/site.json'), '-f', str(pins)]
    env = {k: v for k, v in os.environ.items() if not k.startswith(('SOC_', 'COMPOSE_', 'DOCKER_'))}
    env['SOC_STATE_DIR'] = str(STATE)
    # Include the disabled service in rendering only, without enabling its profile
    # in the saved command used for a future recovery operation.
    r = subprocess.run(command + ['--profile', 'disabled-enrollment', 'config', '--format', 'json'], env=env,
                       capture_output=True, text=True, timeout=30)
    (target / 'render-private.log').write_text(r.stderr)
    if r.returncode:
        print(json.dumps({'plan_directory': str(target), 'render_ok': False,
                          'diagnostic': str(target / 'render-private.log')}))
        return
    rendered = json.loads(r.stdout)
    (target / 'rendered-private.json').write_text(r.stdout)
    problems = []
    for service, c in actual.items():
        desired = rendered['services'][service]
        mounts = {}
        for m in desired.get('volumes', []):
            source = m.get('source')
            if m['type'] == 'volume':
                source = '/var/lib/docker/volumes/' + rendered['volumes'][source]['name'] + '/_data'
            mounts[m['target']] = (source, not m.get('read_only', False))
        for secret in desired.get('secrets', []):
            key = secret['source']
            destination = secret.get('target') or key
            if not destination.startswith('/'):
                destination = '/run/secrets/' + destination
            mounts[destination] = (rendered['secrets'][key].get('file'), False)
        old = {m['Destination']: (m['Source'], m.get('RW', False))
               for m in (c.get('MountPoints') or {}).values()}
        if mounts != old:
            problems.append({'service': service, 'issue': 'mount_difference',
                             'destinations': sorted(k for k in set(old) | set(mounts) if old.get(k) != mounts.get(k))})
        if desired.get('image') != c['Image']:
            problems.append({'service': service, 'issue': 'image_difference'})
    receipt = {'plan_directory': str(target), 'render_ok': True,
               'service_count': len(actual), 'existing_volumes_only': sorted(overlay['volumes']),
               'excluded_service': 'enrollment-cleanup', 'issues': problems,
               'ready_for_network_rebuild': not problems}
    (target / 'plan.json').write_text(json.dumps(receipt, indent=2))
    (target / 'command-private.json').write_text(json.dumps({'command': command, 'environment': {'SOC_STATE_DIR': str(STATE)}}))
    print(json.dumps(receipt, ensure_ascii=False))
    print('Preparation only: Docker, live databases, volumes and containers were not changed.')


if __name__ == '__main__':
    try:
        main()
    except Exception as e:
        print(json.dumps({'preparation_failed': type(e).__name__,
                          'frames': [{'function': f.name, 'line': f.lineno}
                                     for f in traceback.extract_tb(e.__traceback__)],
                          'missing_field': str(e.args[0])[:80] if isinstance(e, KeyError) else None}))
        raise SystemExit(1)
