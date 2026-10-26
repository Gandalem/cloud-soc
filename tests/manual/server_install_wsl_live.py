"""Disposable WSL server-menu acceptance; no original distro is modified.

Windows coordinator imports one owned Ubuntu image. Linux helper runs the actual
menu/installer in a private network namespace with its own systemd Docker engine.
Only the explicitly approved shared map-count setting is changed and restored.
"""
import argparse
import base64
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import sys
import tarfile
import time
import traceback

PROJECT = Path(__file__).resolve().parents[2]
IMAGE_HASH = 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e'
NAMESPACE = 'soc-server-ux-lab'


def digest(path):
    with Path(path).open('rb') as stream:
        return hashlib.file_digest(stream, 'sha256').hexdigest()


def require(value, message):
    if not value:
        raise RuntimeError(message)


def wsl_names():
    return sorted(subprocess.check_output(['wsl.exe', '--list', '--quiet']).decode('utf-16-le').split())


def base_path(name):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Lxss') as root:
        for i in range(winreg.QueryInfoKey(root)[0]):
            with winreg.OpenKey(root, winreg.EnumKey(root, i)) as entry:
                if winreg.QueryValueEx(entry, 'DistributionName')[0] == name:
                    value = winreg.QueryValueEx(entry, 'BasePath')[0]
                    prefix = chr(92) * 2 + '?' + chr(92)
                    return Path(value.removeprefix(prefix)).resolve()
    return None


def linux_path(path):
    path = Path(path).resolve()
    return '/mnt/' + path.drive[0].lower() + path.as_posix()[2:]


def windows_main(args):
    root = args.state.resolve()
    image = args.image.resolve(strict=True)
    require(not root.exists() and root.is_relative_to((PROJECT / 'state').resolve()), '새 시험 자료 경로가 필요합니다.')
    require(digest(image) == IMAGE_HASH, '시험 Ubuntu 이미지 체크섬이 다릅니다.')
    root.mkdir(parents=True)
    trial = 'CloudSOC-ServerUX-2404-' + secrets.token_hex(5)
    location = root / 'wsl'
    prior = wsl_names()
    owner = {'trial': trial, 'prior': prior, 'path': str(location), 'nonce': secrets.token_hex(16)}
    (root / 'ownership.json').write_text(json.dumps(owner, indent=2), encoding='utf-8')
    def run(argv, name, timeout=120):
        reply = subprocess.run(argv, capture_output=True, timeout=timeout)
        (root / (name + '.log')).write_bytes(reply.stdout + reply.stderr)
        require(reply.returncode == 0, name + ' 실패. 해당 시험 로그를 확인하세요.')
        return reply.stdout.decode('utf-8', errors='replace').strip()
    def wsl(*argv, name='command', timeout=120):
        require(trial not in prior and base_path(trial) == location.resolve(), '시험 WSL 소유 경로가 다릅니다.')
        return run(['wsl.exe', '-d', trial, '-u', 'root', '--cd', '/', '--', *argv], name, timeout)
    baseline_map = int(run(['wsl.exe', '-d', 'Ubuntu', '-u', 'root', '--', 'sysctl', '-n', 'vm.max_map_count'], 'map-before'))
    cleanup = {'trial_removed': False, 'original_distros_preserved': False, 'map_restored': False}
    status = 1
    keepalive = None
    archive_path = root / 'source.tar'
    try:
        print('새 WSL 시험 환경을 준비합니다.', flush=True)
        run(['wsl.exe', '--import', trial, str(location), str(image), '--version', '2'], 'import', 300)
        require(base_path(trial) == location.resolve(), '가져온 WSL 경로가 다릅니다.')
        wsl('sh', '-c', 'set -eu; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '
            'python3 systemd systemd-sysv iproute2 procps util-linux slirp4netns iptables', name='prepare', timeout=900)
        wsl('python3', '-c', "from pathlib import Path;Path('/etc/wsl.conf').write_text('[boot]\\nsystemd=true\\n[interop]\\nappendWindowsPath=false\\n')", name='systemd-config')
        run(['wsl.exe', '--terminate', trial], 'terminate-preparation')
        for _ in range(30):
            if wsl('cat', '/proc/1/comm', name='pid1') == 'systemd':
                break
            time.sleep(1)
        else:
            raise RuntimeError('시험 WSL의 systemd가 시작되지 않았습니다.')
        keepalive = subprocess.Popen(['wsl.exe', '-d', trial, '-u', 'root', '--cd', '/', '--', 'sleep', '7200'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        require(wsl('sh', '-c', 'test ! -e /var/run/docker.sock; command -v docker || true', name='empty-engine') == '',
                '시험 WSL에 기존 Docker가 연결돼 있습니다.')
        with tarfile.open(archive_path, 'w') as archive:
            for name in ('src', 'rules', 'prototype', 'deploy', 'requirements.txt', 'constraints.txt', 'soc', '.dockerignore'):
                origin = PROJECT / name
                paths = [origin, *origin.rglob('*')] if origin.is_dir() else [origin]
                for path in paths:
                    if any(p in ('__pycache__', 'node_modules', '.git', '.venv') for p in path.parts) or path.suffix == '.pyc':
                        continue
                    require(not path.is_symlink(), '소스의 심볼릭 링크는 시험에 복사하지 않습니다.')
                    archive.add(path, arcname=path.relative_to(PROJECT).as_posix(), recursive=False)
            archive.add(Path(__file__), arcname='tests/manual/server_install_wsl_live.py')
        wsl('mkdir', '-p', '/srv/cloud-soc', name='checkout-directory')
        wsl('tar', '-xf', linux_path(archive_path), '-C', '/srv/cloud-soc', name='checkout-copy')
        wsl('python3', '-c', "from pathlib import Path;import base64,sys;Path('/run/cloud-soc-server-lab.json').write_bytes(base64.b64decode(sys.argv[1]))",
            base64.b64encode(json.dumps(owner).encode()).decode(), name='inside-ownership')
        wsl('sh', '-c', 'set -eu; iptables-save > /run/iptables-before; ip -j link > /run/links-before; '
            'ip netns add soc-server-ux-lab; mkdir -p /etc/netns/soc-server-ux-lab; '
            'printf "nameserver 10.0.2.3\\n" > /etc/netns/soc-server-ux-lab/resolv.conf; '
            'systemctl mask --runtime containerd.service; mkdir -p /etc/systemd/system/docker.service.d; '
            "printf '%s' '[Service]\nNetworkNamespacePath=/run/netns/soc-server-ux-lab\nExecStart=\nExecStart=/usr/bin/dockerd -H fd://\n' > /etc/systemd/system/docker.service.d/10-lab-network.conf; "
            'systemd-run --unit=cloud-soc-server-slirp --collect --service-type=exec '
            '/usr/bin/slirp4netns --configure --mtu=65520 --disable-host-loopback --netns-type=path '
            '/run/netns/soc-server-ux-lab tap0', name='private-network')
        for _ in range(30):
            if '10.0.2.100' in wsl('ip', '-n', NAMESPACE, '-brief', 'address', name='private-network-ready'):
                break
            time.sleep(1)
        else:
            wsl('sh', '-c', 'journalctl -u cloud-soc-server-slirp --no-pager -n 30; true', name='network-diagnostics')
            raise RuntimeError('시험 전용 네트워크가 준비되지 않았습니다.')
        print('새 WSL에서 실제 서버 설치를 시작합니다.', flush=True)
        reply = subprocess.Popen(['wsl.exe', '-d', trial, '-u', 'root', '--cd', '/', '--', 'ip', 'netns', 'exec', NAMESPACE,
            'python3', '/srv/cloud-soc/tests/manual/server_install_wsl_live.py', '--inside'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # Long install work stays in the child; forward only short phase notices.
        stdout = bytearray()
        for line in reply.stdout:
            stdout.extend(line)
            print(line.decode('utf-8', errors='replace').rstrip(), flush=True)
        stderr = reply.stderr.read()
        code = reply.wait(timeout=30)
        (root / 'inside-notices.log').write_bytes(stdout + stderr)
        if code != 0 and args.diagnose_seconds:
            print('시험 오류 진단 중 · 제한 시간 뒤 새 WSL 자동 삭제', flush=True)
            deadline = time.monotonic() + min(args.diagnose_seconds, 900)
            while time.monotonic() < deadline and not (root / 'finish-diagnostics').exists():
                time.sleep(2)
        require(code == 0, 'WSL 서버 흐름 시험이 중단됐습니다.')
        status = 0
    except Exception as error:
        (root / 'failure.json').write_text(json.dumps({'type': type(error).__name__, 'message': str(error),
            'location': [{'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)]}, indent=2), encoding='utf-8')
        print('WSL 시험 중단: ' + str(error), flush=True)
    finally:
        try:
            if trial in wsl_names():
                require(owner == json.loads((root / 'ownership.json').read_text()) and trial not in prior,
                        '시험 WSL 식별 기록이 다릅니다.')
                require(base_path(trial) == location.resolve() and location.resolve().is_relative_to(root), 'WSL 정리 경로가 다릅니다.')
                try:
                    report_folder = root / 'reports'
                    report_folder.mkdir(exist_ok=True)
                    # Copy only redacted reports, never server state or keys.
                    wsl('python3', '-c', "from pathlib import Path;import shutil,sys;p=Path('/tmp/soc-server-ux-reports');"
                        "[shutil.copyfile(f,Path(sys.argv[1])/f.name) for f in p.glob('*') if f.suffix in ('.log','.json')]",
                        linux_path(report_folder), name='reports-copy')
                except Exception as error:
                    cleanup['report_copy_error'] = str(error)
                wsl('sh', '-c', 'systemctl stop docker.service docker.socket containerd.service cloud-soc-server-slirp.service 2>/dev/null || true', name='trial-docker-stop')
                try:
                    before = wsl('cat', '/run/iptables-before', name='iptables-before')
                    after = wsl('iptables-save', name='iptables-after')
                    def rules(text):
                        return [re.sub(r'\[\d+:\d+\]', '[counters]', line) for line in text.splitlines()
                                if line and not line.startswith('#')]
                    cleanup['original_iptables_preserved'] = rules(before) == rules(after)
                    if not cleanup['original_iptables_preserved']:
                        status = 1
                except Exception as error:
                    cleanup['network_comparison_error'] = str(error)
                vhd = location / 'ext4.vhdx'
                cleanup['vhd_bytes_before_removal'] = vhd.stat().st_size if vhd.exists() else None
                run(['wsl.exe', '--terminate', trial], 'trial-terminate')
                run(['wsl.exe', '--unregister', trial], 'trial-unregister', 180)
            cleanup['trial_removed'] = trial not in wsl_names() and not any(location.glob('*.vhdx'))
            cleanup['original_distros_preserved'] = wsl_names() == prior
        except Exception as error:
            cleanup['cleanup_error'] = str(error)
            status = 1
        try:
            run(['wsl.exe', '-d', 'Ubuntu', '-u', 'root', '--', 'sysctl', '-w', 'vm.max_map_count=' + str(baseline_map)], 'map-restore')
            actual = int(run(['wsl.exe', '-d', 'Ubuntu', '-u', 'root', '--', 'sysctl', '-n', 'vm.max_map_count'], 'map-after'))
            cleanup['map_restored'] = actual == baseline_map
        except Exception as error:
            cleanup['map_restore_error'] = str(error)
            status = 1
        if keepalive is not None:
            try:
                keepalive.wait(timeout=30)
            except subprocess.TimeoutExpired:
                keepalive.terminate()
        if archive_path.exists():
            require(archive_path.resolve().parent == root, '소스 임시 파일 경로가 다릅니다.')
            archive_path.unlink()
        if args.delete_image_cache and status == 0:
            require(image.is_relative_to((PROJECT / 'state').resolve()) and digest(image) == IMAGE_HASH, '정리할 시험 이미지가 다릅니다.')
            image.unlink()
            cleanup['old_image_cache_removed'] = True
        (root / 'cleanup.json').write_text(json.dumps(cleanup, indent=2), encoding='utf-8')
        print('시험 WSL 삭제: ' + str(cleanup['trial_removed']) + ' / 커널 값 원복: ' + str(cleanup['map_restored']), flush=True)
        if not all(cleanup.get(k) for k in ('trial_removed', 'original_distros_preserved', 'map_restored')):
            status = 1
    return status


def inside_main():
    import pty
    import select
    import ssl
    import urllib.request
    require(PROJECT == Path('/srv/cloud-soc') and os.geteuid() == 0, '시험 WSL의 전용 소스 경로가 아닙니다.')
    owner = json.loads(Path('/run/cloud-soc-server-lab.json').read_text())
    require(os.environ.get('WSL_DISTRO_NAME') == owner['trial'] and owner['trial'].startswith('CloudSOC-ServerUX-2404-'), '시험 WSL 이름이 다릅니다.')
    require(os.readlink('/proc/self/ns/net') != os.readlink('/proc/1/ns/net'), '전용 네트워크 밖에서는 실행할 수 없습니다.')
    os.chdir(PROJECT)
    os.umask(0o077)
    reports = Path('/tmp/soc-server-ux-reports')
    reports.mkdir()
    password = secrets.token_urlsafe(30)
    def save(name, text):
        (reports / name).write_text(text.replace(password, '[REDACTED]'), encoding='utf-8')
    def action(name, argv, prompts=(), timeout=2400, expected=0):
        pid, fd = pty.fork()
        if not pid:
            os.environ['TERM'] = 'dumb'
            os.execvp(argv[0], argv)
        end, data, completed = time.monotonic() + timeout, bytearray(), set()
        status = None
        announced = set()
        try:
            while time.monotonic() < end:
                ready, _, _ = select.select([fd], [], [], 1)
                if ready:
                    try:
                        chunk = os.read(fd, 65536)
                    except OSError:
                        break
                    if not chunk:
                        break
                    data.extend(chunk)
                    tail = bytes(data[-65536:]).decode('utf-8', errors='replace')
                    if name == 'install':
                        for stage in ('[설치 1/5]', '[설치 2/5]', '[설치 3/5]', '[설치 4/5]', '[설치 5/5]', '[설치] 소스·설정·서버 자원', '[설치] Elasticsearch·Kibana', '[설치] Elasticsearch를 시작', '[설치] Portal과 수집·탐지'):
                            if stage in tail and stage not in announced:
                                print(stage, flush=True)
                                announced.add(stage)
                    for i, (prompt, answer) in enumerate(prompts):
                        if i not in completed and prompt in tail:
                            os.write(fd, (answer + '\n').encode())
                            completed.add(i)
                done, value = os.waitpid(pid, os.WNOHANG)
                if done:
                    status = value
                    break
            else:
                os.killpg(pid, 15)
                raise RuntimeError(name + ' 시간이 초과됐습니다.')
        finally:
            os.close(fd)
            if status is None:
                _, status = os.waitpid(pid, 0)
            text = data.decode('utf-8', errors='replace')
            save(name + '.log', text)
        code = os.waitstatus_to_exitcode(status)
        if name == 'install' and code != 0:
            diagnostic = subprocess.run(['systemctl', 'show', 'docker', '-p', 'ExecStart'], capture_output=True, text=True, timeout=15)
            save('docker-start-command.log', diagnostic.stdout + diagnostic.stderr)
            diagnostic = subprocess.run(['pgrep', '-a', 'dockerd'], capture_output=True, text=True, timeout=15)
            save('docker-process.log', diagnostic.stdout + diagnostic.stderr)
            for n, probe in enumerate((['--entrypoint', '/usr/local/bin/python', 'cloud-soc-central-runtime:local', '-V'],
                    ['--entrypoint', '/bin/sh', 'cloud-soc-central-runtime:local', '-c',
                     'id; command -v python; ls -ld /app /usr/local/bin/python /usr/local/bin/python3.12'])):
                diagnostic = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'run', '--rm',
                    '--network', 'none', *probe], capture_output=True, text=True, timeout=45)
                save('container-probe-' + str(n) + '.log', diagnostic.stdout + diagnostic.stderr)
        require(code == expected if expected is not None else code != 0, name + ' 종료 코드가 다릅니다: ' + str(code))
        return text
    def run(name, argv, timeout=900):
        reply = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        save(name + '.log', reply.stdout + reply.stderr)
        require(reply.returncode == 0, name + ' 실패. 시험 로그를 확인하세요.')
        return reply.stdout
    def fingerprint():
        paths = [PROJECT / 'state/server/compose.env']
        for folder in ('tls', 'private', 'secrets', 'runtime/keys'):
            paths += [p for p in (PROJECT / 'state/server' / folder).rglob('*') if p.is_file()]
        return {str(p.relative_to(PROJECT)): digest(p) for p in paths}
    def es(path, method='GET', body=None):
        state = PROJECT / 'state/server'
        secret = (state / 'secrets/elastic_password').read_text().strip()
        request = urllib.request.Request('https://localhost:9200' + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + base64.b64encode(('elastic:' + secret).encode()).decode(), 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=str(state / 'tls/ca.crt')), timeout=30) as response:
            return json.load(response)
    results = {}
    try:
        action('install', ['sh', 'soc', 'install'], prompts=[
            ('설치 환경 [lab]:', 'lab'), ('포털 접속 DNS 또는 IPv4:', 'localhost'),
            ('바인딩 IPv4 [127.0.0.1]:', ''), ('장치 수집 DNS 또는 IPv4 [포털과 동일]:', ''),
            ('시각을 확인했고 설치를 계속하려면 yes 입력', 'yes'),
            ('y/yes/INSTALL 입력', 'yes'), ('Portal 관리자 비밀번호 (입력 내용은 표시되지 않습니다):', password),
            ('비밀번호 확인:', password)])
        print('설치 완료 · 새 WSL의 전용 Docker 사용', flush=True)
        text = action('status', ['sh', 'soc', 'status'])
        require('필수 서비스 12개 · 실행 중 12개 · 확인 필요 0개' in text, '필수 서비스 상태가 다릅니다.')
        action('menu', ['sh', 'soc'], prompts=[('명령 [exit]:', 'exit')])
        action('help', ['sh', 'soc', '--help'])
        run('startup', ['python3', 'deploy/server/manage.py', 'verify', '--startup-only'])
        active = json.loads(subprocess.check_output(['docker','inspect', *run('container-ids', ['docker', 'ps', '-q']).split()]))
        expected_init = {'normalizer','normalizer-priority','detector','detector-priority','detector-additional','detector-retrospective','slack-notifier','enrollment-cleanup'}
        require(all(row['HostConfig'].get('Init') is True for row in active if row['Config']['Labels']['com.docker.compose.service'] in expected_init), '작업자 init가 실제 컨테이너에 적용되지 않았습니다.')
        initial = fingerprint()
        canary = {'synthetic': True, 'marker': 'server-ux-preservation'}
        es('/soc-server-ux-canary/_create/owned-1?refresh=wait_for', 'PUT', canary)
        cancelled = action('cancel', ['sh', 'soc', 'uninstall'], prompts=[('삭제 방식 [cancel]:', '')])
        require('삭제를 취소했습니다.' in cancelled and fingerprint() == initial, '삭제 취소 때 자료가 바뀌었습니다.')
        keep = action('keep', ['sh', 'soc', 'uninstall'], prompts=[('삭제 방식 [cancel]:', 'keep'), ('위 서비스를 제거하려면 yes 입력', 'yes')])
        require(keep.count('위 서비스를 제거하려면 yes 입력') == 1 and fingerprint() == initial, '보존 삭제의 확인 횟수 또는 원본 설정이 다릅니다.')
        require(not run('kept-containers', ['docker', 'ps', '-aq', '--filter', 'label=com.docker.compose.project=cloud-soc-central']).strip(), '보존 제거 뒤 컨테이너가 남았습니다.')
        require('보존된 서버 자료 있음' in action('kept-status', ['sh', 'soc', 'status']), '보존 상태 표시가 다릅니다.')
        action('preserved-install-blocked', ['sh', 'soc', 'install'], expected=None)
        require(fingerprint() == initial, '신규 설치 거부 때 자료가 바뀌었습니다.')
        print('보존 삭제·취소·중복 확인 없음·기존 자료 신규 설치 차단 확인', flush=True)
        run('recover', ['python3', 'deploy/server/manage.py', 'recover'])
        run('restore', ['python3', 'deploy/server/manage.py', 'install', '--build'], timeout=1800)
        require(fingerprint() == initial, '보존 복구 뒤 기존 키·인증서가 바뀌었습니다.')
        require(es('/soc-server-ux-canary/_doc/owned-1')['_source'] == canary, '보존 복구 뒤 원본이 다릅니다.')
        require('실행 중 12개 · 확인 필요 0개' in action('restored-status', ['sh', 'soc', 'status']), '복구 상태가 다릅니다.')
        print('보존 자료 복구 · 같은 키·인증서·합성 원본 확인', flush=True)
        purge = action('purge', ['sh', 'soc', 'uninstall'], prompts=[('삭제 방식 [cancel]:', 'purge'), ('위 자료를 삭제하려면 DELETE 입력', 'DELETE')])
        require(purge.count('위 자료를 삭제하려면 DELETE 입력') == 1, '완전 삭제 확인 횟수가 다릅니다.')
        require(not (PROJECT / 'state/server').exists(), '시험 서버 설정이 남았습니다.')
        require(not run('purged-volumes', ['docker', 'volume', 'ls', '-q', '--filter', 'label=com.docker.compose.project=cloud-soc-central']).strip(), '시험 볼륨이 남았습니다.')
        require(not run('purged-containers', ['docker', 'ps', '-aq']).strip(), '시험 컨테이너가 남았습니다.')
        require('설치 정보 없음' in action('purged-status', ['sh', 'soc', 'status']), '완전 삭제 상태가 다릅니다.')
        repeated = action('repeat-removal', ['sh', 'soc', 'uninstall'], prompts=[('삭제 방식 [cancel]:', 'keep')])
        require('삭제 대상이 없습니다.' in repeated, '반복 제거 결과가 다릅니다.')
        results.update(installation=True, required_services=12, menu=True, single_confirmation=True, preserved_reinstall_blocked=True,
            immutable_keys_and_certificates=True, synthetic_document_preserved=True, restored=True, purge=True, repeated_removal=True)
        print('완전 삭제·반복 삭제 확인 · 시험 컨테이너/볼륨 0', flush=True)
    finally:
        save('result.json', json.dumps(results, indent=2))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inside', action='store_true')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--image', type=Path)
    parser.add_argument('--state', type=Path)
    parser.add_argument('--delete-image-cache', action='store_true')
    parser.add_argument('--diagnose-seconds', type=int, default=0)
    args = parser.parse_args()
    if args.inside:
        inside_main()
    else:
        require(args.run and args.image and args.state, '--run·--image·--state가 필요합니다.')
        sys.exit(windows_main(args))
