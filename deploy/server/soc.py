"""Local central-server menu; underlying ownership checks remain authoritative."""
import importlib.util
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'deploy/server'))
from server_cli import KoreanParser


def command(args, **kwargs):
    env = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_', 'SOC_'))}
    return subprocess.run([str(a) for a in args], check=False, env=env, **kwargs)


def require_host():
    if os.name != 'posix' or os.geteuid() != 0 or not Path('/run/systemd/system').is_dir():
        raise RuntimeError('systemd가 실행 중인 Ubuntu에서 sudo로 실행하세요.')
    if 'ID=ubuntu' not in Path('/etc/os-release').read_text().splitlines():
        raise RuntimeError('서버 설치·삭제는 Ubuntu에서 실행하세요.')


def choice(ask, prompt, choices, *, default='', aliases=None):
    while True:
        value = ask(prompt).strip().lower() or default
        value = (aliases or {}).get(value, value)
        if value in choices:
            return value
        print('입력할 수 있는 값: ' + ', '.join(choices))


def host_input(ask, prompt, *, default=''):
    from prepare import validate_host, PreparationError
    while True:
        value = ask(prompt).strip() or default
        try:
            validate_host(value)
            if value == '0.0.0.0':
                raise PreparationError('접속 주소에 0.0.0.0은 사용할 수 없습니다.')
        except PreparationError:
            print('DNS 이름 또는 IPv4를 입력하세요. https://, 포트, 경로는 빼세요. 예: soc.example.com 또는 192.168.1.10')
            continue
        return value.lower()


def install(*, ask=input):
    state = ROOT / 'state/server'
    if state.exists() or state.is_symlink():
        raise RuntimeError('기존 서버 자료가 있습니다. 새 설치를 진행하지 않았습니다. soc status로 상태를 확인하고 docs/runtime_deployment.md의 복구 절차를 따르세요.')
    print('\n서버 설치\n  lab    실습\n  lan    사내망\n  cloud  클라우드')
    mode = choice(ask, '설치 환경 [lab]: ', ('lab', 'lan', 'cloud'), default='lab', aliases={'1':'lab','2':'lan','3':'cloud'})
    host = host_input(ask, '포털 접속 DNS 또는 IPv4: ')
    addresses = command(['ip', '-4', '-j', 'address', 'show'], capture_output=True, text=True)
    if addresses.returncode:
        raise RuntimeError('서버 IP를 조회하지 못했습니다. ip -4 address로 주소를 확인하세요.')
    candidates = sorted({row['local'] for interface in json.loads(addresses.stdout)
                         for row in interface.get('addr_info', []) if row.get('scope') == 'global'})
    print('서버에 할당된 IPv4: ' + (', '.join(candidates) or '없음'))
    if mode == 'cloud':
        print('클라우드 공인 접속 주소와 서버에 할당된 사설 IP는 다를 수 있습니다.')
    default = '127.0.0.1' if mode == 'lab' else candidates[0] if len(candidates) == 1 else ''
    while True:
        bind = ask(f'바인딩 IPv4 [{default or "직접 입력"}]: ').strip() or default
        try:
            ipaddress.IPv4Address(bind)
        except ValueError:
            print('IPv4 형식으로 입력하세요. 예: 192.168.1.10')
            continue
        if bind not in candidates and bind != '127.0.0.1':
            print('이 서버에 할당된 IP를 선택하세요. 0.0.0.0이나 클라우드 NAT 공인 IP는 사용할 수 없습니다.')
            continue
        break
    agent = host_input(ask, '장치 수집 DNS 또는 IPv4 [포털과 동일]: ', default=host)
    print('\n접속 주소: 포털 https://' + host + ' / Kibana https://' + host + ':5601')
    print('장치 수집 주소: https://' + agent + ':9200')
    print('클라우드 방화벽·보안 그룹의 접속 허용 IP를 확인하세요.')
    clock = command(['timedatectl', 'show', '-p', 'NTPSynchronized', '--value'], capture_output=True, text=True)
    if clock.returncode != 0 or clock.stdout.strip() != 'yes':
        print('시간 동기화를 확인하지 못했습니다. timedatectl status에서 서버 시각을 확인하세요.')
        if ask('시각을 확인했고 설치를 계속하려면 yes 입력 [취소]: ').strip().lower() != 'yes':
            print('설치를 취소했습니다.')
            return 0
    result = command(['sh', ROOT / 'deploy/server/install-ubuntu.sh', '--host', host, '--bind-ip', bind, '--agent-host', agent])
    if result.returncode:
        print('설치가 끝나지 않았습니다. 표시된 실패 단계와 남은 설정을 확인하세요.', file=sys.stderr)
    return result.returncode


def removal_tool():
    spec = importlib.util.spec_from_file_location('cloud_soc_server_removal', ROOT / 'deploy/server/uninstall.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def status():
    from cloud_soc.deployment.contract import SERVICES
    remove = removal_tool()
    state = ROOT / 'state/server'
    print('\n서버 상태\n설정 위치: ' + str(state))
    rows = remove.objects('container')
    owned = {}
    initializations = []
    for row in rows:
        labels = row.get('Config', {}).get('Labels') or {}
        if labels.get('com.docker.compose.project') != remove.PROJECT:
            continue
        files = labels.get('com.docker.compose.project.config_files', '').split(',')
        service = labels.get('com.docker.compose.service')
        if not files or Path(files[0]) != ROOT / 'deploy/server/compose.yaml' or service not in remove.SERVICES:
            raise RuntimeError('같은 프로젝트 이름의 다른 설치가 있습니다. 현재 저장소의 상태로 표시하지 않았습니다.')
        if service in owned or any(s == service for s, _ in initializations):
            raise RuntimeError('중복된 서버 서비스가 있습니다. 컨테이너 구성을 확인하세요.')
        if service == 'bootstrap':
            initializations.append((service, row.get('State', {})))
        else:
            owned[service] = row.get('State', {})
    if not owned:
        print('실행 서비스 없음 · ' + ('보존된 서버 자료 있음' if state.exists() else '설치 정보 없음'))
        if state.exists():
            print('기존 자료로 새 설치를 덮어쓰지 않습니다. docs/runtime_deployment.md의 복구 절차를 따르세요.')
    counts = {'running':0, 'problem':0}
    for name in SERVICES:
        current = owned.get(name)
        if current is None:
            if owned:
                print('  ' + name + ': 없음')
                counts['problem'] += 1
            continue
        health = current.get('Health', {}).get('Status')
        running = current.get('Running') is True and current.get('Status') == 'running'
        if running:
            counts['running'] += 1
            label = {'healthy':'상태 점검 통과','starting':'상태 점검 중','unhealthy':'상태 점검 실패'}.get(health, '상태 점검 미설정')
            print('  ' + name + ': 실행 중 · ' + label)
            if health in ('starting', 'unhealthy'):
                counts['problem'] += 1
        else:
            labels = {'exited':'종료','created':'시작 전','paused':'일시 정지','restarting':'재시작 중','dead':'오류','removing':'제거 중'}
            print('  ' + name + ': ' + labels.get(current.get('Status'), '조회 불명') + ' · 종료 코드 ' + str(current.get('ExitCode', '미확인')))
            counts['problem'] += 1
    for name, current in initializations:
        complete = current.get('Status') == 'exited' and current.get('ExitCode') == 0
        print('  초기 준비 작업: ' + ('완료' if complete else '실행 중' if current.get('Running') else '실패 또는 상태 불명'))
        if not complete and not current.get('Running'):
            counts['problem'] += 1
    if owned:
        print(f"필수 서비스 {len(SERVICES)}개 · 실행 중 {counts['running']}개 · 확인 필요 {counts['problem']}개")
    print('이 표는 서버 실행 상태입니다. 장치 로그 수신과 경보 생성은 포털에서 확인하세요.')
    if counts['problem']:
        print('다음 작업: 표시된 서비스의 실행 상태와 설정을 확인하세요.')
    return int(bool(counts['problem']))


def uninstall(*, ask=input):
    # Selection and confirmation belong to the locked removal workflow, once.
    return command([sys.executable, ROOT / 'deploy/server/uninstall.py', '--workspace', ROOT,
                    '--component', 'central', '--apply', '--select-mode']).returncode


def main(*, ask=input):
    sys.path.insert(0, str(ROOT / 'src'))
    parser = KoreanParser(prog='soc', description='Cloud SOC 서버 설치·상태·삭제',
        epilog='사용 예시: sudo sh soc install / sudo sh soc status / sudo sh soc uninstall / sh soc --help')
    parser.add_argument('action', nargs='?', choices=('install','status','uninstall','help'), help='실행할 명령')
    args = parser.parse_args()
    if args.action == 'help':
        parser.print_help()
        return 0
    if args.action:
        require_host()
        return {'install':lambda: install(ask=ask), 'status':status, 'uninstall':uninstall}[args.action]()
    while True:
        print('\nCloud SOC 서버 관리\n  install    서버 설치\n  status     상태 확인\n  uninstall  서버 삭제\n  help       도움말\n  exit       종료')
        action = choice(ask, '명령 [exit]: ', ('install','status','uninstall','help','exit'), default='exit',
                        aliases={'1':'install','2':'status','3':'uninstall','4':'help','0':'exit'})
        if action == 'exit':
            return 0
        if action == 'help':
            parser.print_help()
            continue
        try:
            require_host()
            {'install':lambda: install(ask=ask), 'status':status, 'uninstall':uninstall}[action]()
        except RuntimeError as error:
            print(str(error), file=sys.stderr)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            print('작업이 중단됐습니다. 입력·파일·Docker 상태를 확인하세요.', file=sys.stderr)


if __name__ == '__main__':
    try:
        sys.exit(main())
    except (EOFError, KeyboardInterrupt):
        sys.exit('입력을 취소했습니다. 진행 중이던 작업은 soc status로 확인하세요.')
    except RuntimeError as error:
        sys.exit(str(error))
    except (OSError, ValueError, subprocess.TimeoutExpired):
        sys.exit('작업이 중단됐습니다. 입력·파일·Docker 상태를 확인하세요. 기존 설정을 자동 초기화하지 않았습니다.')
