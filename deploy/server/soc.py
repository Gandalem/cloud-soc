"""One local entry point; existing install/removal ownership checks stay authoritative."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]


def command(args, **kwargs):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_', 'SOC_'))}
    return subprocess.run([str(a) for a in args], check=False, env=env, **kwargs)


def require_host():
    if os.name != 'posix' or os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise RuntimeError('systemd가 실행 중인 Ubuntu에서 sudo로 실행하세요.')
    if 'ID=ubuntu' not in Path('/etc/os-release').read_text().splitlines():
        raise RuntimeError('서버 설치·삭제는 Ubuntu에서 실행하세요.')


def install(*, ask=input):
    if (ROOT / 'state/server').exists() or (ROOT / 'state/server').is_symlink():
        raise RuntimeError('기존 설치 또는 중단된 상태가 있습니다. 덮어쓰지 않습니다. 상태 메뉴와 docs/runtime_deployment.md의 복구 절차를 사용하세요.')
    print('환경: 1. 실습  2. 사내망  3. 클라우드')
    mode = ask('선택 [1]: ').strip() or '1'
    if mode not in ('1', '2', '3'):
        raise RuntimeError('설치 환경을 선택하세요.')
    host = ask('포털 접속 DNS 또는 IP (https:// 제외): ').strip()
    addresses = command(['ip', '-4', '-j', 'address', 'show'], capture_output=True, text=True)
    candidates = []
    if addresses.returncode == 0:
        for interface in json.loads(addresses.stdout):
            candidates.extend(row['local'] for row in interface.get('addr_info', []) if row.get('scope') == 'global')
    print('서버에 할당된 IPv4: ' + (', '.join(candidates) or '후보 없음'))
    if mode == '3':
        print('공인 접속 주소와 서버 사설 IP는 다를 수 있습니다. 클라우드 보안 그룹에서 관리자·장치 접근 범위를 제한하세요.')
    default = '127.0.0.1' if mode == '1' else candidates[0] if len(candidates) == 1 else ''
    bind = ask(f'서버 바인딩 IPv4 [{default or "직접 선택"}]: ').strip() or default
    if not host or not bind:
        raise RuntimeError('접속 주소와 실제 바인딩 IP가 필요합니다.')
    agent = ask('장치 수집 DNS 또는 IP [포털과 동일]: ').strip() or host
    print('포털 HTTPS 443 / Kibana HTTPS 5601 / 장치 수집 HTTPS 9200')
    print('내부 서비스는 외부에 공개하지 마세요. Docker 공개 포트와 클라우드 방화벽 규칙을 함께 확인하세요.')
    clock = command(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'], capture_output=True, text=True)
    if clock.returncode != 0 or clock.stdout.strip() != 'yes':
        print('시간 동기화를 확인하지 못했습니다. 서버 시각은 탐지와 인증서 검증에 사용됩니다.')
        if ask('시간 설정을 확인했고 진행하려면 yes 입력: ').strip().lower() != 'yes':
            return 0
    # The existing installer checks actual resource/port/address conflicts BEFORE mutation.
    return command(['sh', ROOT / 'deploy/server/install-ubuntu.sh', '--host', host,
                    '--bind-ip', bind, '--agent-host', agent]).returncode


def status():
    print('상태 위치: ' + str(ROOT / 'state/server'))
    print('이 조회는 서버 실행 상태이며 장치 수집·분석 완료를 의미하지 않습니다.')
    result = command(['docker', '--host', 'unix:///var/run/docker.sock', 'ps', '-a',
        '--filter', 'label=com.docker.compose.project=cloud-soc-central',
        '--format', '{{.Names}}\t{{.Status}}'], capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError('Docker 상태를 조회하지 못했습니다. 권한과 Docker 실행 상태를 확인하세요.')
    print(result.stdout.strip() or '실행 기록이 없습니다.')
    return 0


def uninstall(*, ask=input):
    print('1. 프로그램 삭제 — 서버 데이터·설정·인증서 보존')
    print('2. 서버 데이터·설정까지 완전 삭제')
    choice = ask('선택 [취소]: ').strip()
    if choice not in ('1', '2'):
        return 0
    args = [sys.executable, ROOT / 'deploy/server/uninstall.py', '--workspace', ROOT,
            '--component', 'central', '--apply']
    if choice == '2':
        if ask('서버 데이터·인증서·계정을 삭제하려면 DELETE 입력: ').strip() != 'DELETE':
            return 0
        args.append('--purge-data')
    return command(args).returncode


def main():
    parser = argparse.ArgumentParser(description='Cloud SOC 서버 설치·상태·삭제 도우미')
    parser.add_argument('action', nargs='?', choices=('install', 'status', 'uninstall', 'help'))
    args = parser.parse_args()
    if args.action == 'help':
        parser.print_help()
        return 0
    action = args.action
    if action is None:
        print('Cloud SOC\n1. 설치\n2. 상태 확인\n3. 삭제\n4. 도움말\n0. 종료')
        action = {'1': 'install', '2': 'status', '3': 'uninstall', '4': 'help'}.get(input('선택: ').strip())
        if action is None:
            return 0
        if action == 'help':
            parser.print_help()
            return 0
    require_host()
    return {'install': install, 'status': status, 'uninstall': uninstall}[action]()


if __name__ == '__main__':
    try:
        sys.exit(main())
    except RuntimeError as error:
        sys.exit(str(error))
    except (OSError, ValueError, EOFError):
        sys.exit('작업을 완료하지 못했습니다. 기존 상태는 자동 초기화하지 않았습니다. 설치 기록과 입력·권한을 확인하세요.')
