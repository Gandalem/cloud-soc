"""Local management of an identified Linux enrollment; never manages arbitrary Beats."""
import argparse
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import uuid


def enrollment(source):
    spec = importlib.util.spec_from_file_location('soc_enrollment', source / 'enrollment-linux.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def receipt(module, spec):
    rows = []
    for path in module.STATE.glob('complete-*.json'):
        module.private(path)
        row = json.loads(path.read_text())
        if row.get('spec', {}).get('package_id') == spec['package_id']:
            rows.append(row)
    if len(rows) != 1:
        raise RuntimeError('이 설치 묶음에 연결된 완료 기록을 하나로 확인할 수 없습니다.')
    row = rows[0]
    if row.get('state') != 'complete' or module.stable(spec, row['owner']) != row.get('files'):
        raise RuntimeError('설치 소유 기록 또는 파일이 다릅니다. 자동 변경하지 않습니다.')
    return row


def manage(module, spec, action, *, confirm=input):
    row = receipt(module, spec)
    if action == 'status':
        states = {}
        for scope in module.roles(spec):
            result = module.run(['systemctl', 'show', module.SERVICES[scope], '-p', 'ActiveState', '--value'], capture_output=True)
            states[scope] = result.stdout.decode().strip()
        print(json.dumps({'device_id': spec.get('managed_device_id'), 'services': states,
            'initial_receipt': row['state'], 'current_log_receipt': '서버에서 별도 조회',
            'analysis': '서버에서 별도 조회'}, ensure_ascii=False, indent=2))
        return
    if action in ('stop', 'start'):
        verb = 'disable' if action == 'stop' else 'enable'
        for scope in module.roles(spec):
            module.system(verb, '--now', module.SERVICES[scope])
        module.system(verb, '--now', 'cloud-soc-discovery.timer')
        if action == 'stop':
            module.system('stop', 'cloud-soc-discovery.service')
        print('로컬 서비스에 적용했습니다. 서버 수신 상태와 자격 증명은 별도로 확인하세요.')
        return
    if action != 'uninstall':
        raise RuntimeError('지원하지 않는 관리 작업입니다.')
    print('이 장치의 Cloud SOC 서비스만 제거합니다. 원본 로그와 서버 로그·경보는 보존합니다.')
    print('미전송 자료가 남을 수 있습니다. 1: 자료 보존 후 제거 / 2: 수집기 자료까지 삭제 / 그 외: 취소')
    choice = confirm('선택: ').strip()
    if choice not in ('1', '2'):
        print('취소했습니다.')
        return
    if choice == '2' and confirm('수집기 큐·설정·키를 삭제하려면 DELETE 입력: ').strip() != 'DELETE':
        print('취소했습니다.')
        return
    # Recheck the entire ownership snapshot after the user's confirmation.
    receipt(module, spec)
    targets = [module.ROOTS[s] for s in module.roles(spec)]
    for target in targets:
        if target.resolve() != target or target not in (Path('/opt/cloud-soc-agent'), Path('/opt/cloud-soc-network')):
            raise RuntimeError('삭제 범위가 소유한 고정 설치 경로와 다릅니다.')
    for unit in module.units(spec):
        module.system('disable', '--now', unit)
    for unit in module.units(spec):
        module.private(module.UNIT_ROOT / unit)
    for target in targets:
        for item in target.rglob('*'):
            module.private(item)
    archive = module.STATE / ('retired-' + uuid.uuid4().hex)
    archive.mkdir(mode=0o700)
    module.save(archive / 'operation.json', {'state': 'removing', 'device_id': spec.get('managed_device_id'),
        'session': row['session'], 'data_preserved': choice == '1', 'remote_revocation': 'not_confirmed'})
    for unit in module.units(spec):
        (module.UNIT_ROOT / unit).unlink()
    module.system('daemon-reload')
    for target in targets:
        if choice == '1':
            target.rename(archive / target.name)
        else:
            shutil.rmtree(target)
    module.save(archive / 'operation.json', {'state': 'removed', 'device_id': spec.get('managed_device_id'),
        'session': row['session'], 'data_preserved': choice == '1', 'remote_revocation': 'not_confirmed'})
    module.save(Path(__file__).resolve().parent / 'managed-local.json', {'state': 'removed',
        'device_id': spec.get('managed_device_id'), 'remote_revocation': 'not_confirmed'})
    print('로컬 프로그램 제거 완료. 서버 접근 차단은 포털의 같은 장치에서 완료하세요.')
    if choice == '1':
        print('자료·설정은 관리자 전용 보존 디렉터리에 남겼습니다. 재설치가 자동으로 복원하지는 않습니다.')


def main():
    parser = argparse.ArgumentParser(description='Cloud SOC Agent 설치·상태·중지·재개·삭제')
    parser.add_argument('action', nargs='?', choices=('install', 'status', 'stop', 'start', 'uninstall', 'help'))
    parser.add_argument('--interface', help='네트워크 수집을 선택한 경우 실제 NIC')
    args = parser.parse_args()
    if args.action == 'help':
        parser.print_help()
        return 0
    if os.name != 'posix' or os.geteuid() != 0:
        raise RuntimeError('sudo로 실행하세요.')
    action = args.action
    if action is None:
        print('1. 설치  2. 상태  3. 중지  4. 재개  5. 삭제  0. 종료')
        action = {'1': 'install', '2': 'status', '3': 'stop', '4': 'start', '5': 'uninstall'}.get(input('선택: ').strip())
        if action is None:
            return 0
    source = Path(__file__).resolve().parent
    module = enrollment(source)
    module.private(source, directory=True)
    spec = json.loads((source / 'package.json').read_text())
    local = source / 'managed-local.json'
    if local.exists():
        module.private(local)
        previous = json.loads(local.read_text())
        if previous.get('device_id') != spec.get('managed_device_id'):
            raise RuntimeError('로컬 관리 기록의 장치가 다릅니다.')
        if previous.get('state') == 'removed':
            if action in ('status', 'uninstall'):
                print('로컬 프로그램 삭제됨. 서버 접근 차단 결과는 포털에서 확인하세요.')
                return 0
            raise RuntimeError('삭제된 설치입니다. 보존 자료를 자동 복원하지 않습니다. 포털에서 재설치 절차를 확인하세요.')
    if action != 'install':
        import fcntl
        module.private(module.STATE, directory=True)
        fd = os.open(module.STATE / 'install.lock', os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            manage(module, spec, action)
        finally:
            os.close(fd)
        return 0
    if any(module.STATE.glob('complete-*.json')):
        try:
            receipt(module, spec)
        except RuntimeError:
            raise RuntimeError('기존 완료 설치 기록을 확인하세요. 신규 설치로 덮어쓰지 않습니다.') from None
        manage(module, spec, 'status')
        return 0
    registration_path = source / 'registration.json'
    module.private(registration_path)
    registration = json.loads(registration_path.read_text())
    interface = args.interface
    if spec['network'] and not interface:
        print('사용 가능한 NIC: ' + ', '.join(p.name for p in Path('/sys/class/net').iterdir()))
        interface = input('수집할 NIC: ').strip()
    # Persist only the random retry identity; the one-time handoff has its own protected file.
    sid = registration.get('enrollment_id', '')
    if not isinstance(sid, str) or not module.re.fullmatch(r'[a-f0-9]{32}', sid):
        raise RuntimeError('등록 요청 ID가 올바르지 않습니다.')
    attempt_path = source / ('attempt-' + sid + '.json')
    if not attempt_path.exists():
        module.save(attempt_path, {'attempt': module.secrets.token_urlsafe(32)})
    module.private(attempt_path)
    attempt = json.loads(attempt_path.read_text())['attempt']
    recovery = False
    pending = module.STATE / 'pending.json'
    if pending.exists():
        module.private(pending)
        previous = json.loads(pending.read_text())
        if previous.get('spec', {}).get('package_id') != spec['package_id'] or previous.get('state') != 'failed':
            raise RuntimeError('중단된 설치 기록이 있습니다. 실패 상태와 서버 폐기를 확인한 후 복구하세요.')
        if input('실패 설치의 큐·읽기 위치를 보존하여 재등록하려면 yes 입력: ').strip().lower() != 'yes':
            return 0
        recovery = True
    module.execute(source, spec, registration['package_sha256'], interface, recovery, False,
                   registration=registration, attempt=attempt)
    registration_path.unlink()
    print('등록 정보의 로컬 사본을 정리했습니다. 다운로드 원본도 안전하게 삭제하세요.')
    return 0


if __name__ == '__main__':
    os.umask(0o077)
    try:
        sys.exit(main())
    except Exception as error:
        message = str(error) if isinstance(error, RuntimeError) else '권한·설치 기록·서버 상태를 확인하세요.'
        sys.exit('작업 중단: ' + message)
