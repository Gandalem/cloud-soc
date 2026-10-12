"""Run a public test archive in disposable, internal Docker containers only."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import secrets
import shutil
import subprocess
import tarfile
import tempfile
import uuid

DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
ES_IMAGE = 'docker.elastic.co/elasticsearch/elasticsearch:9.5.2'
CENTRAL = ('cloud-soc-central-portal-1', 'cloud-soc-central-gateway-1',
           'cloud-soc-central-kibana-1', 'cloud-soc-central-elasticsearch-1')


def command(*args, check=True, timeout=90):
    result = subprocess.run([*DOCKER, *args], capture_output=True, text=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError('Disposable Docker operation failed; details withheld')
    return result


def central_state():
    rows = json.loads(command('inspect', *CENTRAL).stdout)
    return {r['Name']: {'id': r['Id'], 'started_at': r['State']['StartedAt'],
                        'running': r['State']['Running'], 'restarts': r['RestartCount']} for r in rows}


def extract(archive, target):
    with tarfile.open(archive, 'r:gz') as bundle:
        members = bundle.getmembers()
        if len(members) > 2000 or sum(m.size for m in members) > 64 * 1024 * 1024:
            raise ValueError('Public fixture archive too large')
        for member in members:
            relative = PurePosixPath(member.name)
            if relative.is_absolute() or '..' in relative.parts or not relative.parts or not (
                    member.isfile() or member.isdir()):
                raise ValueError('Unsafe fixture archive member')
            path = target.joinpath(*relative.parts)
            if member.isdir():
                path.mkdir(parents=True, exist_ok=True, mode=0o755)
            else:
                path.parent.mkdir(parents=True, exist_ok=True, mode=0o755)
                with bundle.extractfile(member) as source, path.open('xb') as output:
                    shutil.copyfileobj(source, output)
                path.chmod(0o644)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    parser.add_argument('--run', action='store_true')
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0 or not args.run:
        raise ValueError('Explicit root disposable-test execution required')
    source = args.archive
    if source.is_symlink() or not source.is_file() or source.stat().st_size > 8 * 1024 * 1024:
        raise ValueError('Invalid public archive')
    descriptor = os.open(source, os.O_RDONLY | os.O_NOFOLLOW)
    root = Path(tempfile.mkdtemp(prefix='cloud-soc-p5-fixture-', dir='/var/tmp'))
    suffix = uuid.uuid4().hex
    name = 'cloud-soc-p5-test-' + suffix
    names = [name + '-es', name + '-runner']
    network_created = False
    before = None
    report = {'passed': False, 'operational_deployment': False}
    try:
        archive = root / 'public.tar.gz'
        with os.fdopen(descriptor, 'rb') as input_file, archive.open('xb') as output:
            shutil.copyfileobj(input_file, output)
        if hashlib.sha256(archive.read_bytes()).hexdigest() != args.sha256:
            raise ValueError('Public source hash mismatch')
        memory = dict(line.split(':', 1) for line in Path('/proc/meminfo').read_text().splitlines())
        if int(memory['MemAvailable'].split()[0]) < 3 * 1024 * 1024 or shutil.disk_usage(root).free < 2 * 1024**3:
            raise ValueError('Insufficient spare memory or disk; central stack untouched')
        before = central_state()
        if not all(r['running'] for r in before.values()):
            raise ValueError('Existing stack not running; no test containers created')
        runner_image = json.loads(command('inspect', CENTRAL[0]).stdout)[0]['Image']
        command('image', 'inspect', ES_IMAGE)
        payload = root / 'public'
        payload.mkdir(mode=0o755)
        extract(archive, payload)
        command('network', 'create', '--internal', name)
        network_created = True
        password = secrets.token_urlsafe(32)
        expected = 'p5-fixture-' + suffix
        command('run', '--detach', '--rm', '--pull=never', '--name', names[0],
                '--network', name, '--network-alias', 'p5-test-es', '--memory=1536m', '--cpus=1',
                '--env', 'discovery.type=single-node', '--env', 'cluster.name=' + expected,
                '--env', 'xpack.security.enabled=true', '--env', 'xpack.security.http.ssl.enabled=false',
                '--env', 'ES_JAVA_OPTS=-Xms512m -Xmx512m', '--env', 'ELASTIC_PASSWORD=' + password, ES_IMAGE)
        result = command('run', '--rm', '--pull=never', '--name', names[1], '--network', name,
            '--memory=512m', '--cpus=1', '--read-only', '--cap-drop=ALL', '--security-opt=no-new-privileges',
            '--tmpfs', '/tmp:rw,nosuid,size=256m', '--mount', 'type=bind,src=' + str(payload) + ',dst=/fixture,readonly',
            '--env', 'PYTHONPATH=/fixture/src:/fixture/tests', '--env', 'PYTHONDONTWRITEBYTECODE=1',
            '--env', 'SOC_P5_DISPOSABLE_FIXTURE=1', '--env', 'SOC_P5_FIXTURE_CLUSTER=' + expected,
            '--env', 'SOC_P5_FIXTURE_PASSWORD=' + password, '--entrypoint', 'python', runner_image,
            '/fixture/tests/p5_03_live_checks.py', check=False, timeout=240)
        lines = result.stdout.strip().splitlines()
        if not lines:
            raise RuntimeError('Fixture runner returned no report')
        report = json.loads(lines[-1])
        if result.returncode or not report.get('passed'):
            report['passed'] = False
        report['runner_exit'] = result.returncode
        report['existing_stack_unchanged'] = central_state() == before
    except Exception as error:
        report.update(passed=False, error_type=type(error).__name__, details_withheld=True)
    finally:
        for container in names:
            command('rm', '--force', '--volumes', container, check=False)
        if network_created:
            command('network', 'rm', name, check=False)
        remaining = command('ps', '--all', '--filter', 'name=' + name, '--format', '{{.Names}}').stdout.splitlines()
        cleanup = not any(item in names for item in remaining)
        report['test_containers_removed'] = cleanup
        report['test_network_removed'] = command('network', 'inspect', name, check=False).returncode != 0
        if before is not None:
            report['existing_stack_unchanged'] = central_state() == before
        # root is an owned mkdtemp directory, never a caller-supplied cleanup path.
        if root.parent == Path('/var/tmp') and root.name.startswith('cloud-soc-p5-fixture-') and not root.is_symlink():
            shutil.rmtree(root)
        report['passed'] = bool(report.get('passed') and report.get('existing_stack_unchanged')
                                and cleanup and report['test_network_removed'])
        print(json.dumps(report, sort_keys=True))
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
