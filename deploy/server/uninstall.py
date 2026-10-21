"""Ubuntu Cloud SOC 제거. 기본은 미리보기이며 실행은 --apply로 명시한다."""
import argparse
from contextlib import ExitStack
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
PROJECT = 'cloud-soc-central'
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
        for row in containers:
            labels = row.get('Config', {}).get('Labels') or {}
            if labels.get('com.docker.compose.project') != PROJECT:
                continue
            files = labels.get('com.docker.compose.project.config_files', '').split(',')
            if (labels.get('com.docker.compose.service') not in SERVICES or
                    not files or Path(files[0]) != workspace / 'deploy/server/compose.yaml'):
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
            tag = 'cloud-soc-central-runtime:local'
            images = docker('image', 'ls', '--filter', 'reference=' + tag, '--format', '{{.ID}}').split()
            if images:
                image = json.loads(docker('image', 'inspect', tag))[0]
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
    return result


def remove_path(path):
    path = safe_path(path)
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def apply(args, expected):
    # Recheck ownership and sharing after confirmation, before the first removal.
    current = plan(args)
    if current != expected:
        raise RemovalError('미리보기 이후 설치 상태가 바뀌었습니다. 다시 실행해 확인하세요.')
    for name in current['units']:
        run(['systemctl', 'disable', '--now', name])
    for name in current['units']:
        safe_path(Path('/etc/systemd/system') / name).unlink()
    if current['units']:
        run(['systemctl', 'daemon-reload'])
    if current['containers']:
        docker('rm', '-f', *current['containers'])
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


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', type=Path, default=ROOT, help='Cloud SOC 저장소 루트')
    parser.add_argument('--component', choices=('central', 'agent', 'all'), default='central', help='제거 대상 (기본: central)')
    parser.add_argument('--purge-data', action='store_true', help='대상 데이터·인증서·비밀번호도 삭제')
    parser.add_argument('--remove-images', action='store_true', help='Cloud SOC 공통 이미지 태그도 삭제')
    parser.add_argument('--remove-docker', action='store_true', help='다른 사용처가 없을 때 공식 Docker 프로그램도 삭제')
    parser.add_argument('--apply', action='store_true', help='미리보기 후 실제 제거')
    parser.add_argument('--yes', action='store_true', help='실제 제거 시 확인 입력 생략')
    args = parser.parse_args()
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
        expected = plan(args)
        print('Cloud SOC 제거 계획 (다른 프로젝트와 Apache는 보존):')
        print(json.dumps(expected, ensure_ascii=False, indent=2))
        if not args.apply:
            print('아직 삭제하지 않았습니다. 실제 제거는 같은 옵션에 --apply를 추가하세요.')
            return
        if not args.yes and input('위 항목을 제거하려면 삭제 입력: ').strip() != '삭제':
            print('제거를 취소했습니다.')
            return
        apply(args, expected)


if __name__ == '__main__':
    try:
        main()
    except (RemovalError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        message = str(error) if isinstance(error, RemovalError) else type(error).__name__
        sys.exit('제거 중단: ' + message)
