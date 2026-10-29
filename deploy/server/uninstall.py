"""Ubuntu Cloud SOC 제거. 기본은 미리보기이며 실행은 --apply로 명시한다."""
from contextlib import ExitStack
import json
import os
import re
from pathlib import Path
import shutil
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/server'))
sys.path.insert(0, str(ROOT / 'src'))
from server_cli import KoreanParser

PROJECT = 'cloud-soc-central'
STOP_TIMEOUT = 90
SERVICES = {'elasticsearch', 'kibana', 'gateway', 'portal', 'bootstrap', 'enrollment-cleanup',
            'normalizer', 'normalizer-priority', 'detector', 'detector-priority',
            'detector-additional', 'detector-retrospective', 'slack-notifier'}
VOLUMES = {PROJECT + '_' + name for name in ('es-data', 'caddy-data', 'caddy-config')}
AGENTS = {
    'cloud-soc-filebeat.service': '/opt/cloud-soc-agent',
    'cloud-soc-discovery.service': '/opt/cloud-soc-agent',
    'cloud-soc-discovery.timer': '/opt/cloud-soc-agent',
    'cloud-soc-packetbeat.service': '/opt/cloud-soc-network',
}
DOCKER_PACKAGES = ('docker-ce', 'docker-ce-cli', 'containerd.io', 'docker-buildx-plugin', 'docker-compose-plugin')
KERNEL_FILE = Path('/etc/sysctl.d/90-cloud-soc.conf')


class RemovalError(RuntimeError):
    pass


def run(args):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_', 'SOC_'))}
    p = subprocess.run(args, capture_output=True, text=True, env=env, timeout=300)
    if p.returncode:
        # Do not copy potentially sensitive command output into the terminal.
        raise RemovalError('제거 명령에 실패했습니다: ' + Path(args[0]).name + '. 남은 상태는 보존했습니다.')
    return p.stdout


def docker(*args):
    return run(['docker', '--host', 'unix:///var/run/docker.sock', *args])


def objects(kind):
    if kind == 'container':
        ids = docker('ps', '-aq').split()
        return json.loads(docker('inspect', *ids)) if ids else []
    names = docker(kind, 'ls', '--filter', 'label=com.docker.compose.project=' + PROJECT,
                   '--format', '{{.Name}}').split()
    return json.loads(docker(kind, 'inspect', *names)) if names else []


def safe_path(path):
    path = Path(path).absolute()
    if path == Path('/') or any(p.is_symlink() for p in (path, *path.parents)):
        raise RemovalError('심볼릭 링크 또는 허용되지 않은 삭제 경로입니다.')
    return path


def managed_external_files(workspace, rows):
    """Only a protected, currently applied release may share this state root."""
    own = [r for r in rows if (r.get('Config', {}).get('Labels') or {}).get('com.docker.compose.project') == PROJECT]
    base = workspace / 'deploy/server/compose.yaml'
    if not any(Path((r.get('Config', {}).get('Labels') or {}).get(
            'com.docker.compose.project.config_files', '').split(',')[0]) != base for r in own):
        return None
    portals = [r for r in own if (r.get('Config', {}).get('Labels') or {}).get('com.docker.compose.service') == 'portal']
    if len(portals) != 1:
        raise RemovalError('기존 릴리스의 Portal을 식별할 수 없어 중단했습니다.')
    try:
        from cloud_soc.deployment.host import active_command
        command = active_command(workspace / 'state/server', {'portal': portals[0]}, workspace=workspace)
        files = [command[i+1] for i, v in enumerate(command[:-1]) if v == '-f']
        if len(files) != 2 or files[1] != str(workspace / 'state/server/runtime/site.json'):
            raise ValueError('Only the canonical release pair may share state')
        return files
    except (ValueError, OSError, KeyError, TypeError):
        raise RemovalError('기존 릴리스의 보호된 배포 기록이 일치하지 않아 중단했습니다.') from None


def owned_configuration(workspace, files, external):
    return bool(files and (Path(files[0]) == workspace / 'deploy/server/compose.yaml'
                           or external is not None and files == external))


def plan(args):
    workspace = safe_path(args.workspace)
    if not (workspace / 'deploy/server/install-ubuntu.sh').is_file():
        raise RemovalError('Cloud SOC 저장소의 루트 경로를 지정하세요.')
    state = safe_path(workspace / 'state/server')
    result = {'containers': [], 'volumes': [], 'networks': [], 'units': [], 'paths': [], 'images': [],
              'docker_packages': [], 'data_preserved': not args.purge_data}
    has_docker = shutil.which('docker') is not None
    central = args.component in ('central', 'all')
    containers = objects('container') if central and has_docker else []
    if central and has_docker:
        external = managed_external_files(workspace, containers)
        for row in containers:
            labels = row.get('Config', {}).get('Labels') or {}
            if labels.get('com.docker.compose.project') != PROJECT:
                continue
            files = labels.get('com.docker.compose.project.config_files', '').split(',')
            if (labels.get('com.docker.compose.service') not in SERVICES or
                    not owned_configuration(workspace, files, external)):
                raise RemovalError('같은 프로젝트 이름의 다른 설치가 있습니다. 자동 제거하지 않습니다.')
            result['containers'].append(row['Id'])
        for kind, key, allowed in (
            ('volume', 'volumes', VOLUMES if args.purge_data else set()),
            ('network', 'networks', {PROJECT + '_default'}),
        ):
            if kind == 'volume' and not args.purge_data:
                continue
            for row in objects(kind):
                if row['Name'] not in allowed:
                    raise RemovalError('예상하지 못한 Cloud SOC 리소스가 있어 중단했습니다.')
                users = [c for c in containers if c['Id'] not in result['containers'] and (
                    any(m.get('Name') == row['Name'] for m in c.get('Mounts', [])) if kind == 'volume' else
                    row['Name'] in c.get('NetworkSettings', {}).get('Networks', {}))]
                if users:
                    raise RemovalError('다른 컨테이너가 Cloud SOC 리소스를 사용하고 있어 제거하지 않습니다.')
                if not result['containers'] and not (state / 'compose.env').is_file():
                    raise RemovalError('해당 저장소의 설정이 없어 기존 Docker 리소스의 소유 관계를 확인할 수 없습니다.')
                result[key].append(row['Name'])
        if args.remove_images:
            tags = ['cloud-soc-central-runtime:local']
            tags += docker('image', 'ls', '--filter', 'reference=cloud-soc-recovery:*',
                           '--format', '{{.Repository}}:{{.Tag}}').split()
            for tag in sorted(set(tags)):
                if tag.startswith('cloud-soc-recovery:') and not re.fullmatch(r'cloud-soc-recovery:[0-9a-f]{64}', tag):
                    raise RemovalError('예상하지 못한 복구 이미지 태그가 있어 제거하지 않습니다.')
                images = docker('image', 'ls', '--filter', 'reference=' + tag, '--format', '{{.ID}}').split()
                if not images:
                    continue
                image = json.loads(docker('image', 'inspect', tag))[0]
                if tag.startswith('cloud-soc-recovery:') and tag.split(':')[1] != image['Id'].removeprefix('sha256:'):
                    raise RemovalError('복구 이미지 태그와 실제 식별자가 달라 제거하지 않습니다.')
                if any(c.get('Image') == image['Id'] and c['Id'] not in result['containers'] for c in containers):
                    raise RemovalError('다른 컨테이너가 공통 이미지를 사용하고 있어 제거하지 않습니다.')
                result['images'].append(tag)
    if central and args.purge_data and state.exists():
        if not (state / 'compose.env').is_file() or (state / 'compose.env').is_symlink():
            raise RemovalError('서버 설정의 소유 관계를 확인할 수 없어 데이터 삭제를 중단했습니다.')
        result['paths'].append(str(state))
    if central and args.purge_data:
        kernel_file = safe_path(KERNEL_FILE)
        if kernel_file.exists():
            if kernel_file.read_text().strip() != 'vm.max_map_count=1048576':
                raise RemovalError('변경된 Cloud SOC 커널 설정이 있어 자동 제거하지 않습니다.')
            result['paths'].append(str(kernel_file))
    if args.component in ('agent', 'all'):
        for name, directory in AGENTS.items():
            unit = safe_path(Path('/etc/systemd/system') / name)
            if unit.exists():
                content = unit.read_text()
                marker = 'Unit=cloud-soc-discovery.service' if name.endswith('.timer') else directory + '/'
                if marker not in content:
                    raise RemovalError('동일 이름의 다른 서비스가 있어 제거하지 않습니다: ' + name)
                result['units'].append(name)
        if args.purge_data:
            for directory in sorted(set(AGENTS.values())):
                path = safe_path(directory)
                if path.exists():
                    if not (path / 'filebeat.yml').is_file() and not (path / 'packetbeat.yml').is_file():
                        raise RemovalError('에이전트 설정을 확인할 수 없어 삭제하지 않습니다.')
                    result['paths'].append(str(path))
    if args.remove_docker:
        if not central:
            raise RemovalError('Docker 삭제는 중앙 서버 제거와 함께 지정하세요.')
        if any(c['Id'] not in result['containers'] for c in containers):
            raise RemovalError('다른 컨테이너가 있어 Docker 프로그램은 제거할 수 없습니다.')
        if has_docker:
            foreign = docker('volume', 'ls', '--format', '{{.Name}}').split()
            if any(name not in VOLUMES for name in foreign):
                raise RemovalError('다른 Docker 볼륨이 있어 Docker 프로그램은 제거할 수 없습니다.')
            for name in docker('network', 'ls', '--format', '{{.Name}}').split():
                if name not in ('bridge', 'host', 'none', PROJECT + '_default'):
                    raise RemovalError('다른 Docker 네트워크가 있어 Docker 프로그램은 제거할 수 없습니다.')
        for package in DOCKER_PACKAGES:
            p = subprocess.run(['dpkg-query', '-W', '-f=${Status}', package], capture_output=True, text=True)
            if p.returncode == 0 and p.stdout == 'install ok installed':
                result['docker_packages'].append(package)
        if has_docker and not result['docker_packages']:
            raise RemovalError('공식 Docker CE APT 설치가 아니므로 Docker 프로그램은 자동 제거하지 않습니다.')
    for key in ('containers', 'volumes', 'networks', 'units', 'paths', 'images', 'docker_packages'):
        result[key].sort()
    return result


def remove_path(path):
    path = safe_path(path)
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def inspect_owned(args, identifiers):
    rows = json.loads(docker('inspect', *identifiers)) if identifiers else []
    if not isinstance(rows, list) or {r.get('Id') for r in rows} != set(identifiers):
        raise RemovalError('종료 대상 조회 결과가 다릅니다. 삭제하지 않았습니다.')
    needs_external = any(Path((r.get('Config', {}).get('Labels') or {}).get(
        'com.docker.compose.project.config_files', '').split(',')[0]) != args.workspace / 'deploy/server/compose.yaml' for r in rows)
    external = managed_external_files(args.workspace, objects('container')) if needs_external else None
    for row in rows:
        labels = row.get('Config', {}).get('Labels') or {}
        files = labels.get('com.docker.compose.project.config_files', '').split(',')
        if (labels.get('com.docker.compose.project') != PROJECT
                or labels.get('com.docker.compose.service') not in SERVICES or not files
                or not owned_configuration(args.workspace, files, external)
                or type(row.get('State', {}).get('Running')) is not bool
                or str(row.get('Config', {}).get('StopSignal', '')).upper() in ('9', 'SIGKILL', 'KILL', '19', 'SIGSTOP', 'STOP')):
            raise RemovalError('종료 대상의 소유 관계나 상태가 바뀌었습니다. 삭제하지 않았습니다.')
    return rows


def stop_containers(args, expected):
    """Use the configured graceful stop signal; bound only the CLI wait.

    `docker stop -t -1` also suppresses restart-policy restarts. A client
    timeout does not prove container exit and never authorizes data removal.
    """
    identifiers = expected['containers']
    rows = inspect_owned(args, identifiers)
    order = {'gateway': 0, 'portal': 2, 'kibana': 2, 'elasticsearch': 3}
    deadline = time.monotonic() + STOP_TIMEOUT
    for phase in range(4):
        current = plan(args)
        if current != expected:
            raise RemovalError('삭제 대상이 바뀌었습니다. 변경된 대상을 다시 확인하세요.')
        rows = inspect_owned(args, identifiers)
        targets = [row['Id'] for row in rows if row['State']['Running'] and
                   order.get(row['Config']['Labels']['com.docker.compose.service'], 1) == phase]
        if not targets:
            continue
        if any(row['Id'] in targets and row['State'].get('Paused') for row in rows):
            raise RemovalError('일시 정지된 컨테이너가 있습니다. 상태를 확인하세요. 데이터는 삭제하지 않았습니다.')
        # Floating-point deadline arithmetic can round slightly above the original budget.
        remaining = min(STOP_TIMEOUT, deadline - time.monotonic())
        if remaining <= 0:
            raise RemovalError('종료 대기 시간이 지났습니다. 남은 서비스와 데이터는 삭제하지 않았습니다.')
        print(f'서버 종료 중 · 대기 한도 {STOP_TIMEOUT}초')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_', 'SOC_'))}
        try:
            reply = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'stop',
                '-t', '-1', *targets], capture_output=True, text=True,
                env=env, timeout=remaining)
        except subprocess.TimeoutExpired:
            raise RemovalError('종료 대기 시간이 지났습니다. 강제 종료하지 않았습니다. soc status로 남은 상태를 확인하세요.') from None
        if reply.returncode:
            raise RemovalError('서버 종료 결과를 확인하지 못했습니다. 데이터는 삭제하지 않았습니다.')
        after = inspect_owned(args, targets)
        if any(r['State']['Running'] or r['State'].get('Restarting') or r['State'].get('OOMKilled')
               or r['State'].get('ExitCode') == 137 for r in after):
            raise RemovalError('정상 종료를 확인하지 못했습니다. 데이터는 삭제하지 않았습니다.')
    if any(r['State']['Running'] or r['State'].get('Restarting') or r['State'].get('OOMKilled')
           or r['State'].get('ExitCode') == 137 for r in inspect_owned(args, identifiers)):
        raise RemovalError('종료 상태를 확인하세요. 강제 종료·메모리 오류·실행 중인 서비스가 있으면 데이터는 삭제하지 않습니다.')


def apply(args, expected):
    # Recheck ownership and sharing after confirmation, before the first removal.
    current = plan(args)
    if current != expected:
        raise RemovalError('미리보기 이후 설치 상태가 바뀌었습니다. 다시 실행해 확인하세요.')
    if current['containers']:
        stop_containers(args, current)
        if plan(args) != current:
            raise RemovalError('종료 중 삭제 대상이 바뀌었습니다. 변경된 대상을 다시 확인하세요.')
    for name in current['units']:
        run(['systemctl', 'disable', '--now', name])
    for name in current['units']:
        safe_path(Path('/etc/systemd/system') / name).unlink()
    if current['units']:
        run(['systemctl', 'daemon-reload'])
    if current['containers']:
        docker('rm', *current['containers'])
    for kind, key in (('volume', 'volumes'), ('network', 'networks')):
        if current[key]:
            docker(kind, 'rm', *current[key])
    for image in current['images']:
        docker('image', 'rm', image)
    for path in current['paths']:
        remove_path(path)
    if current['docker_packages']:
        run(['apt-get', 'purge', '-y', *current['docker_packages']])
    # No autoremove, global prune, external API calls, checkout or Apache deletion.
    remaining = plan(args)
    if any(remaining[key] for key in ('containers', 'volumes', 'networks', 'units', 'paths', 'images', 'docker_packages')):
        raise RemovalError('제거 후 남은 항목이 있습니다. 상태를 확인하세요.')
    print('Cloud SOC 제거를 완료했습니다.')
    if not args.purge_data:
        print('인증서·비밀번호·로그 데이터와 에이전트 파일은 보존했습니다.')
    else:
        print('대상 데이터와 인증서·비밀번호를 제거했습니다. 현재 커널 값은 다른 서비스 보호를 위해 낮추지 않습니다.')
    if args.remove_docker:
        print('Docker 프로그램을 제거했습니다. /var/lib/docker 등 공용 저장소는 자동 삭제하지 않습니다.')
    if args.component in ('agent', 'all'):
        print('발급 키는 중앙 Portal에서 별도로 폐기하세요. 중앙 서버의 키를 자동 폐기하지 않습니다.')


def describe(args, expected):
    print('\n서버 삭제 대상\n저장소: ' + str(args.workspace))
    for key, title in (('containers','컨테이너'), ('volumes','데이터 볼륨'), ('networks','네트워크'),
                       ('units','서비스 등록'), ('paths','자료 경로'), ('images','이미지'), ('docker_packages','Docker 패키지')):
        if expected[key]:
            print('  ' + title + ': ' + str(len(expected[key])) + '개')
    for path in expected['paths']:
        print('  삭제 경로: ' + path)
    if expected['data_preserved']:
        print('보존: 서버 데이터·설정·인증서·자격 증명')
        print('서비스 제거 뒤 기존 자료로 신규 설치를 덮어쓰지 않습니다. 재사용은 기존 서버 복구 절차를 따르세요.')
    else:
        print('삭제: 해당 설치의 데이터·설정·인증서·자격 증명')
        print('기존 장치는 새 서버에 자동으로 다시 연결되지 않습니다.')
    print('다른 프로젝트·저장소 소스·공용 Docker는 선택한 삭제 대상에 포함되지 않습니다.'
          if not args.remove_docker else 'Docker 프로그램도 삭제 대상으로 선택했습니다.')


def select_mode(args, ask):
    print('\n서버 삭제\n  keep    서비스 제거 · 데이터·설정·인증서 보존\n  purge   서버 데이터·설정·인증서까지 삭제\n  cancel  취소')
    while True:
        value = ask('삭제 방식 [cancel]: ').strip().lower() or 'cancel'
        if value == 'cancel':
            print('삭제를 취소했습니다.')
            return False
        if value in ('keep', 'purge'):
            args.purge_data = value == 'purge'
            return True
        print('keep, purge, cancel 중 하나를 입력하세요.')


def main(*, ask=input):
    parser = KoreanParser(description='Ubuntu Cloud SOC 제거 · 기본 동작은 삭제 대상 조회')
    parser.add_argument('--workspace', type=Path, default=ROOT, help='Cloud SOC 저장소 루트')
    parser.add_argument('--component', choices=('central', 'agent', 'all'), default='central', help='제거 대상 (기본: central)')
    parser.add_argument('--purge-data', action='store_true', help='대상 데이터·인증서·비밀번호도 삭제')
    parser.add_argument('--remove-images', action='store_true', help='Cloud SOC 공통 이미지 태그도 삭제')
    parser.add_argument('--remove-docker', action='store_true', help='다른 사용처가 없을 때 공식 Docker 프로그램도 삭제')
    parser.add_argument('--apply', action='store_true', help='미리보기 후 실제 제거')
    parser.add_argument('--yes', action='store_true', help='실제 제거 시 확인 입력 생략')
    parser.add_argument('--select-mode', action='store_true', help='데이터 보존 또는 완전 삭제를 선택')
    args = parser.parse_args()
    args.workspace = safe_path(args.workspace)
    if args.select_mode and (not args.apply or args.component != 'central' or args.purge_data
                             or args.yes or args.remove_images or args.remove_docker):
        raise RemovalError('--select-mode는 중앙 서버의 --apply와 함께 사용하세요. 다른 삭제 옵션은 지정하지 마세요.')
    if os.name != 'posix' or os.geteuid() != 0:
        raise RemovalError('Ubuntu에서 sudo로 실행하세요. 기본 동작은 제거 계획 표시입니다.')
    if not Path('/run/systemd/system').is_dir():
        raise RemovalError('systemd가 실행 중인 Ubuntu에서 실행하세요.')
    if 'ID=ubuntu' not in Path('/etc/os-release').read_text().splitlines():
        raise RemovalError('이 제거 스크립트는 Ubuntu 전용입니다.')
    os.umask(0o077)
    with ExitStack() as stack:
        if args.apply:
            import fcntl
            for path in (Path('/run/lock/cloud-soc-central-install.lock'),
                         args.workspace / 'state/server/runtime/upgrade.lock'):
                if not path.parent.exists():
                    continue
                safe_path(path)
                stream = stack.enter_context(path.open('a'))
                try:
                    fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise RemovalError('다른 설치·업그레이드 작업이 실행 중입니다.') from None
        confirm_removal(args, ask)


def confirm_removal(args, ask):
    if args.select_mode and not select_mode(args, ask):
        return
    expected = plan(args)
    describe(args, expected)
    if not args.apply:
        print('아직 삭제하지 않았습니다. 실제 제거는 같은 옵션에 --apply를 추가하세요.')
        return
    if not any(expected[k] for k in ('containers', 'volumes', 'networks', 'units', 'paths', 'images', 'docker_packages')):
        print('삭제 대상이 없습니다.')
        return
    if not args.yes:
        purge = args.purge_data and args.component in ('central', 'all')
        value = ask('위 자료를 삭제하려면 DELETE 입력 [취소]: ' if purge else '위 서비스를 제거하려면 yes 입력 [취소]: ').strip()
        if (value != 'DELETE' if purge else value.lower() not in ('y', 'yes')):
            print('삭제를 취소했습니다.')
            return
    apply(args, expected)


if __name__ == '__main__':
    try:
        main()
    except (EOFError, KeyboardInterrupt):
        sys.exit('입력을 취소했습니다. soc status로 남은 상태를 확인하세요.')
    except (RemovalError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        message = str(error) if isinstance(error, RemovalError) else type(error).__name__
        sys.exit('제거 중단: ' + message)
