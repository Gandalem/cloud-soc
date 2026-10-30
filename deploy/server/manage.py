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
from cloud_soc.deployment.compose_review import ComposeReviewError
from cloud_soc.deployment.dependencies import DependencyError, check as check_dependencies
from cloud_soc.deployment.downloads import build_runtime_image, public_operation
from cloud_soc.deployment.host import Docker, DockerCommandError, apply, containers, recover, snapshot, summary, worker_inventory
from cloud_soc.deployment.migrations import atomic_json
from cloud_soc.deployment import image_safety
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
    """Let Compose resolve image references and cache policy from the release."""
    compose = ['compose', '--project-name', 'cloud-soc-central',
        '--env-file', str(state / 'compose.env'), '-f', str(workspace / 'deploy/server/compose.yaml'),
    ]
    rendered = engine.json([*compose, 'config', '--format', 'json'], env=environment)
    images = image_safety.infrastructure_images(engine, rendered, allow_missing=True)
    if any(row['image_id'] is None for row in images.values()):
        image_safety.check_disk_budget(engine, workspace, 'download')
    print('[설치] Elasticsearch·Kibana·게이트웨이 이미지를 준비합니다. 다운로드 진행은 아래에 표시됩니다.', flush=True)
    for service, label in (('elasticsearch', 'Elasticsearch'), ('kibana', 'Kibana'), ('gateway', '게이트웨이')):
        print('[설치] ' + label + ': 배포 설정에 지정된 이미지를 확인합니다. 이미 있으면 재사용합니다.', flush=True)
        public_operation(engine, [*compose, 'pull', '--policy', 'missing', service],
                         env=environment, timeout=1800,
                         before_attempt=(lambda: image_safety.check_disk_budget(engine, workspace, 'reserve'))
                         if images[service]['image_id'] is None else None)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('build', 'prepare-images', 'review-compose', 'plan', 'apply', 'install', 'recover', 'verify'))
    parser.add_argument('--workspace', type=Path, default=ROOT)
    parser.add_argument('--state', type=Path, default=ROOT / 'state/server')
    parser.add_argument('--image', help='후보 이미지 태그 (build에서 필수)')
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--access', type=Path, help='대표/수신 주소를 유지하는 추가 Portal DNS/IP 설정 JSON')
    parser.add_argument('--compose-file', action='append', type=Path, default=[],
                        help='review-compose: explicit existing Compose files in their applied order')
    parser.add_argument('--compose-review', type=Path,
                        help='plan: protected review.json from review-compose, rechecked before apply')
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--startup-only', action='store_true', help='Structure only; never claims ingestion/detection acceptance')
    parser.add_argument('--portal-origin')
    parser.add_argument('--password-stdin', action='store_true', help='Read a JSON password object from stdin, never argv/environment')
    parser.add_argument('--probe', type=Path, help='Receipt from an explicit local SSH exercise')
    parser.add_argument('--wait-seconds', type=int, default=0)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run on the approved Linux Docker host with sudo')
    if args.action == 'build':
        if not args.image:
            raise ValueError('업데이트 후보 태그를 --image로 지정하세요')
        if (args.build or args.plan or args.access or args.compose_file or args.compose_review
                or args.startup_only or args.portal_origin or args.password_stdin or args.probe or args.wait_seconds):
            raise ValueError('build에서는 --workspace와 --image만 지정하세요. 적용은 별도 배포 계획으로 진행합니다')
        engine = Docker()
        print('[빌드] 업데이트 후보 이미지를 준비합니다. 실행 중인 서비스는 변경하지 않습니다.', flush=True)
        build_runtime_image(engine, args.workspace, args.image)
        image_id = engine.json(['image', 'inspect', args.image])[0]['Id']
        print(json.dumps({'built': True, 'image': args.image, 'image_id': image_id, 'activation_performed': False}))
        return 0
    args.image = args.image or 'cloud-soc-central-runtime:local'
    if args.state.is_symlink() or args.wait_seconds < 0 or args.wait_seconds > 3600:
        raise ValueError('Invalid state path or verification deadline')
    engine = Docker();state = args.state.resolve()
    if args.access and args.action not in ('plan', 'install'):
        raise ComposeReviewError('추가 주소 파일은 plan 또는 install에서 지정하세요')
    if args.compose_file and args.action != 'review-compose' or args.compose_review and args.action != 'plan':
        raise ValueError('Compose review options do not apply to this action')
    if args.action == 'prepare-images':
        if (args.build or args.plan or args.startup_only or args.portal_origin or args.password_stdin
                or args.probe or args.wait_seconds):
            raise image_safety.DeploymentSafetyError('prepare-images에서는 이미지 준비만 수행할 수 있습니다')
        check_dependencies(engine)
        from cloud_soc.deployment.host import compose_environment
        prepare_install_images(engine, args.workspace, state,
                               compose_environment(state, args.image, containers(engine, 'cloud-soc-central')))
        print(json.dumps({'images_prepared': True, 'activation_performed': False}))
        return 0
    if args.action == 'review-compose':
        from cloud_soc.deployment.compose_review import create
        if len(args.compose_file) < 3:
            raise ValueError('Specify the original two Compose files and the additional site overrides in order')
        from cloud_soc.deployment.host import lock
        with lock(state / 'runtime'):
            if (state / 'runtime/pending.json').exists():
                raise ValueError('Recover the interrupted deployment before reviewing Compose configuration')
            result = create(engine, state, args.compose_file, containers(engine, 'cloud-soc-central'))
        print(json.dumps(result))
        return 0
    if args.action == 'recover':
        print(json.dumps(recover(engine, state)))
        return 0
    if args.action == 'plan':
        p = snapshot(engine, args.workspace, state, args.image,
                     **({'compose_review': args.compose_review} if args.compose_review else {}),
                     **({'access_path': args.access} if args.access else {}))
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
            build_runtime_image(engine, args.workspace, args.image)
        print('[설치] 소스·설정·서버 자원을 확인합니다.', flush=True)
        p = (snapshot(engine, args.workspace, state, args.image, allow_missing_images=True,
                      **({'access_path': args.access} if args.access else {})) if args.action == 'install'
             else json.loads(args.plan.read_text()) if args.plan else None)
        if not p or (args.action == 'install' and not p['fresh']):
            raise ValueError('Use a reviewed plan to upgrade an existing server')
        if not p['resources']['ok']:
            raise ValueError('Server resource preflight failed; no activation performed')
        if args.action == 'install':
            prepare_install_images(engine, args.workspace, state, p['compose_environment'])
            p = snapshot(engine, args.workspace, state, args.image,
                         **({'access_path': args.access} if args.access else {}))
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
    except (DockerCommandError, DependencyError, image_safety.DeploymentSafetyError) as error:
        raise SystemExit(str(error)) from None
    except ComposeReviewError as error:
        raise SystemExit(str(error)) from None
    except Exception as error:
        code = getattr(error, 'sqlite_errorname', None)
        safe_code = (' sqlite=' + code if isinstance(code, str) and code.startswith('SQLITE_')
                     and all(c.isupper() or c == '_' or c.isdigit() for c in code) else '')
        raise SystemExit('서버 작업이 중단됐습니다 (' + type(error).__name__ + safe_code
                         + '). 기존 설정은 보존됐으며 인증 정보는 출력하지 않습니다.') from None
