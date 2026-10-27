"""Common central install/upgrade entry point. Only explicit apply changes a server."""
import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from cloud_soc.deployment.contract import SERVICES
from cloud_soc.deployment.dependencies import DependencyError, check as check_dependencies
from cloud_soc.deployment.host import Docker, DockerCommandError, apply, containers, recover, snapshot, summary, worker_inventory
from cloud_soc.deployment.migrations import atomic_json
from cloud_soc.deployment.verify import portal


def ready(engine, name, project):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            obj = engine.json(['inspect', project + '-' + name + '-1'])[0]
        except RuntimeError:
            time.sleep(2)
            continue
        if obj['State']['Running'] and obj['State'].get('Health', {}).get('Status', 'healthy') == 'healthy':
            return
        time.sleep(2)
    raise ValueError('필수 서비스의 기동 대기 시간이 초과됐습니다')


def prepare_install_images(engine, workspace, state, environment):
    """Prepare registry images before activation, retaining cached versions."""
    print('[설치] Elasticsearch·Kibana·게이트웨이 이미지를 준비합니다. 다운로드 진행은 아래에 표시됩니다.', flush=True)
    for service, image in (
        ('Elasticsearch', 'docker.elastic.co/elasticsearch/elasticsearch:9.5.2'),
        ('Kibana', 'docker.elastic.co/kibana/kibana:9.5.2'), ('게이트웨이', 'caddy:2.11.4-alpine'),
    ):
        present = engine.run(['image', 'ls', '--filter', 'reference=' + image, '--format', '{{.ID}}']).strip()
        if present:
            print('[설치] ' + service + ': 검증된 호환 이미지가 있어 재사용합니다.', flush=True)
        else:
            print('[설치] ' + service + ': 검증 버전 이미지가 필요해 다운로드합니다. 다른 버전은 자동 대체하지 않습니다.', flush=True)
    engine.run(['compose', '--project-name', 'cloud-soc-central', '--env-file', str(state / 'compose.env'),
                '-f', str(workspace / 'deploy/server/compose.yaml'),
                'pull', '--policy', 'missing', 'elasticsearch', 'kibana', 'gateway'],
               env=environment, timeout=1800, stream=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'install', 'recover', 'verify'))
    parser.add_argument('--workspace', type=Path, default=ROOT)
    parser.add_argument('--state', type=Path, default=ROOT / 'state/server')
    parser.add_argument('--image', default='cloud-soc-central-runtime:local')
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--startup-only', action='store_true', help='Structure only; never claims ingestion/detection acceptance')
    parser.add_argument('--portal-origin')
    parser.add_argument('--password-stdin', action='store_true', help='Read a JSON password object from stdin, never argv/environment')
    parser.add_argument('--probe', type=Path, help='Receipt from an explicit local SSH exercise')
    parser.add_argument('--wait-seconds', type=int, default=0)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run on the approved Linux Docker host with sudo')
    if args.state.is_symlink() or args.wait_seconds < 0 or args.wait_seconds > 3600:
        raise ValueError('Invalid state path or verification deadline')
    engine = Docker();state = args.state.resolve()
    if args.action == 'recover':
        print(json.dumps(recover(engine, state)))
        return 0
    if args.action == 'plan':
        p = snapshot(engine, args.workspace, state, args.image)
        output = args.plan or state / 'runtime-plan.json'
        atomic_json(output, p)
        print(json.dumps(summary(p)))
        return int(not p['resources']['ok'])
    if args.action in ('apply', 'install'):
        if args.action == 'install':
            check_dependencies(engine)
        if args.build:
            if args.action != 'install':
                raise ValueError('Build the upgrade candidate before reviewing its plan')
            print('[설치] Cloud SOC 이미지를 빌드합니다. 최초 설치는 몇 분 걸릴 수 있습니다.', flush=True)
            engine.run(['build', '--progress=plain', '--pull=false', '-f', str(args.workspace / 'deploy/server/Dockerfile'), '-t', args.image,
                        str(args.workspace)], timeout=600, stream=True)
        print('[설치] 소스·설정·서버 자원을 확인합니다.', flush=True)
        p = (snapshot(engine, args.workspace, state, args.image) if args.action == 'install'
             else json.loads(args.plan.read_text()) if args.plan else None)
        if not p or (args.action == 'install' and not p['fresh']):
            raise ValueError('Use a reviewed plan to upgrade an existing server')
        if not p['resources']['ok']:
            raise ValueError('Server resource preflight failed; no activation performed')
        if args.action == 'install':
            prepare_install_images(engine, args.workspace, state, p['compose_environment'])
        print(json.dumps(apply(engine, p, poll=ready)))
        return 0
    runtime = state / 'runtime';current = json.loads((runtime / 'current.json').read_text())
    objects = containers(engine, 'cloud-soc-central')
    from cloud_soc.deployment.contract import ALL_WORKERS
    if set(worker_inventory(engine, 'cloud-soc-central')) != set(ALL_WORKERS):
        raise ValueError('Missing or duplicate common worker')
    if any(n not in objects or not objects[n]['State']['Running'] for n in SERVICES):
        raise ValueError('A required runtime service is missing')
    from cloud_soc.deployment.contract import APP_SERVICES
    if any(objects[n]['Image'] != current['image_id'] for n in APP_SERVICES):
        raise ValueError('Mixed application versions cannot pass verification')
    if args.startup_only:
        print(json.dumps({'runtime_ready': True, 'live_acceptance': 'not_verified', 'version': current['version']}))
        return 0
    password = None
    if args.portal_origin:
        password = json.load(sys.stdin)['password'] if args.password_stdin else getpass.getpass('Portal admin password: ')
    probe = json.loads(args.probe.read_text()) if args.probe else None
    deadline = time.monotonic() + args.wait_seconds
    while True:
        result = engine.json(['exec', '-i', 'cloud-soc-central-portal-1', 'python', '-m', 'cloud_soc.deployment.verify'],
                             input=json.dumps({'since': current['utc'], 'probe': probe}))
        if result['policy_sha256'] != current['policy_sha256']:
            raise ValueError('Live runtime policy differs from the applied version')
        if result['verified'] or time.monotonic() >= deadline:
            break
        time.sleep(min(10, max(0, deadline - time.monotonic())))
    if args.portal_origin:
        result['portal'] = portal(args.portal_origin, state / 'tls/ca.crt', password)
    else:
        result['verified'] = False;result['issues'].append('actual_portal_authentication_not_verified')
    result['checked_at'] = datetime.now(timezone.utc).isoformat()
    atomic_json(runtime / 'acceptance.json', result)
    print(json.dumps(result))
    return int(not result['verified'])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except (DockerCommandError, DependencyError) as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        code = getattr(error, 'sqlite_errorname', None)
        safe_code = (' sqlite=' + code if isinstance(code, str) and code.startswith('SQLITE_')
                     and all(c.isupper() or c == '_' or c.isdigit() for c in code) else '')
        raise SystemExit('서버 작업이 중단됐습니다 (' + type(error).__name__ + safe_code
                         + '). 기존 설정은 보존됐으며 인증 정보는 출력하지 않습니다.') from None
