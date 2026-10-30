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
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import traceback

PROJECT = Path(__file__).resolve().parents[2]
IMAGE_HASH = 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e'
NAMESPACE = 'soc-server-ux-lab'
MANAGEMENT_FILES = ('soc', 'deploy/server/manage.py', 'deploy/server/soc.py', 'deploy/server/server_cli.py',
    'deploy/server/uninstall.py', 'src/cloud_soc/__init__.py', *('src/cloud_soc/deployment/' + n + '.py' for n in
    ('__init__', 'host', 'contract', 'compose_review', 'dependencies', 'downloads', 'public_stream', 'migrations', 'verify', 'access')))


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
    require(digest(image) == args.image_sha256, '시험 Ubuntu 이미지 체크섬이 다릅니다.')
    require(bool(args.https_apt_ca) == bool(args.https_apt_ca_sha256), '시험 HTTPS CA 파일과 지문을 함께 지정하세요.')
    if args.https_apt_ca:
        require(digest(args.https_apt_ca) == args.https_apt_ca_sha256, '시험 공개 CA 지문이 다릅니다.')
    require(bool(args.management_overlay) == bool(args.management_overlay_sha256), '관리 파일 묶음과 지문을 함께 지정하세요.')
    if args.management_overlay:
        require(args.upgrade_check, '관리 파일 조합 시험에는 --upgrade-check가 필요합니다.')
        require(digest(args.management_overlay / 'wsl-inputs.json') == args.management_overlay_sha256,
                '관리 파일 목록 지문이 다릅니다.')
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
        if args.https_apt_ca:
            wsl('cp', linux_path(args.https_apt_ca), '/etc/apt/cloud-soc-lab-ca.pem', name='trial-public-ca-copy')
            require(wsl('sha256sum', '/etc/apt/cloud-soc-lab-ca.pem', name='trial-public-ca-hash').split()[0]
                    == args.https_apt_ca_sha256, '복사된 시험 공개 CA 지문이 다릅니다.')
            wsl('sh', '-c', 'set -eu; test ! -L /etc/apt/sources.list.d/ubuntu.sources; '
                'sed -i "s|URIs: http://archive.ubuntu.com/ubuntu/|URIs: https://archive.ubuntu.com/ubuntu/|; '
                's|URIs: http://security.ubuntu.com/ubuntu/|URIs: https://security.ubuntu.com/ubuntu/|" '
                '/etc/apt/sources.list.d/ubuntu.sources; '
                'printf \'Acquire::https::CaInfo "/etc/apt/cloud-soc-lab-ca.pem";\\nAcquire::Retries "2";\\nAcquire::https::Timeout "30";\\n\' '
                '> /etc/apt/apt.conf.d/99-cloud-soc-lab-https', name='trial-https-repositories')
        wsl('sh', '-c', 'set -eu; apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 '
            '-o Acquire::https::Timeout=30 -o APT::Update::Error-Mode=any update -qq; '
            'DEBIAN_FRONTEND=noninteractive apt-get -o Acquire::Retries=3 -o Acquire::http::Timeout=30 '
            '-o Acquire::https::Timeout=30 install -y --no-install-recommends '
            'python3 systemd systemd-sysv iproute2 procps util-linux slirp4netns iptables '
            'ca-certificates curl git openssl', name='prepare', timeout=900)
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
            '/usr/bin/slirp4netns --configure --mtu=1500 --disable-host-loopback --netns-type=path '
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
            'python3', '/srv/cloud-soc/tests/manual/server_install_wsl_live.py', '--inside',
            *(['--upgrade-check'] if args.upgrade_check else []),
            *(['--image-source-check'] if args.image_source_check else []),
            *(['--deployment-guards-check'] if args.deployment_guards_check else []),
            *(['--management-overlay', linux_path(args.management_overlay), '--management-overlay-sha256',
               args.management_overlay_sha256] if args.management_overlay else []),
            *(['--image-cache', linux_path(args.image_cache)] if args.image_cache else [])], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
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
            require(image.is_relative_to((PROJECT / 'state').resolve()) and digest(image) == args.image_sha256, '정리할 시험 이미지가 다릅니다.')
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
        if name == 'install' and code != 0 and shutil.which('docker'):
            diagnostic = subprocess.run(['systemctl', 'show', 'docker', '-p', 'ExecStart'], capture_output=True, text=True, timeout=15)
            save('docker-start-command.log', diagnostic.stdout + diagnostic.stderr)
            diagnostic = subprocess.run(['pgrep', '-a', 'dockerd'], capture_output=True, text=True, timeout=15)
            save('docker-process.log', diagnostic.stdout + diagnostic.stderr)
            for n, probe in enumerate((['--entrypoint', '/usr/local/bin/python', 'cloud-soc-central-runtime:local', '-V'],
                    ['--entrypoint', '/bin/sh', 'cloud-soc-central-runtime:local', '-c',
                     'id; command -v python; ls -ld /app /usr/local/bin/python /usr/local/bin/python3.12'])):
                diagnostic = subprocess.run(['docker', '--host', 'unix:///var/run/docker.sock', 'run', '--rm',
                    '--pull=never', '--network', 'none', *probe], capture_output=True, text=True, timeout=45)
                save('container-probe-' + str(n) + '.log', diagnostic.stdout + diagnostic.stderr)
        require(code == expected if expected is not None else code != 0, name + ' 종료 코드가 다릅니다: ' + str(code))
        return text
    def run(name, argv, timeout=900, env=None):
        reply = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env)
        save(name + '.log', reply.stdout + reply.stderr)
        require(reply.returncode == 0, name + ' 실패. 시험 로그를 확인하세요.')
        return reply.stdout
    def fingerprint():
        paths = [PROJECT / 'state/server/compose.env']
        for folder in ('tls', 'private', 'secrets', 'runtime/keys'):
            paths += [p for p in (PROJECT / 'state/server' / folder).rglob('*') if p.is_file()]
        return {str(p.relative_to(PROJECT)): digest(p) for p in paths}
    def runtime_identity():
        ids = subprocess.check_output(['docker', 'ps', '-aq', '--no-trunc'], text=True).split()
        rows = json.loads(subprocess.check_output(['docker', 'inspect', *ids])) if ids else []
        return {row['Id']: {'image': row['Image'], 'started': row['State']['StartedAt'],
                'restarts': row.get('RestartCount'), 'running': row['State']['Running'],
                'paused': row['State'].get('Paused'), 'restarting': row['State'].get('Restarting')} for row in rows}
    def service_images(name):
        ids = subprocess.check_output(['docker', 'ps', '-aq'], text=True).split()
        rows = json.loads(subprocess.check_output(['docker', 'inspect', *ids])) if ids else []
        images = {row['Config']['Labels']['com.docker.compose.service']: row['Image'] for row in rows}
        save(name + '.json', json.dumps(images))
        return images
    def es(path, method='GET', body=None):
        state = PROJECT / 'state/server'
        secret = (state / 'secrets/elastic_password').read_text().strip()
        request = urllib.request.Request('https://localhost:9200' + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': 'Basic ' + base64.b64encode(('elastic:' + secret).encode()).decode(), 'Content-Type': 'application/json'})
        with urllib.request.urlopen(request, context=ssl.create_default_context(cafile=str(state / 'tls/ca.crt')), timeout=30) as response:
            return json.load(response)
    def check_portal(name):
        sys.path.insert(0, str(PROJECT / 'src'))
        from cloud_soc.deployment.verify import portal
        deadline = time.monotonic() + 180
        while True:
            try:
                checked = portal('https://localhost', PROJECT / 'state/server/tls/ca.crt', password)
                save(name + '.json', json.dumps(checked))
                return
            except urllib.error.HTTPError as error:
                if error.code in (401, 403) or time.monotonic() >= deadline:
                    raise
            except (ValueError, OSError):
                if time.monotonic() >= deadline:
                    raise
            time.sleep(10)
    results = {}
    try:
        try:
            if args.image_cache:
                cache = json.loads(args.image_cache.read_text())
                required = {'python:3.12-slim-bookworm', 'caddy:2.11.4-alpine',
                            'docker.elastic.co/elasticsearch/elasticsearch:9.5.2',
                            'docker.elastic.co/kibana/kibana:9.5.2'}
                require(cache.get('version') == 1 and len(cache['images']) == 4
                        and {r['tag'] for r in cache['images']} == required, '공식 이미지 캐시 목록이 다릅니다.')
                action('prepare-cached', ['sh', 'deploy/server/install-ubuntu.sh', '--host', 'localhost',
                    '--bind-ip', '127.0.0.1', '--prepare-only', '--yes'], prompts=[
                    ('시각을 확인했고 설치를 계속하려면 yes 입력', 'yes'),
                    ('Portal 관리자 비밀번호 (입력 내용은 표시되지 않습니다):', password), ('비밀번호 확인:', password)])
                prepared = fingerprint()
                for row in cache['images']:
                    archive = args.image_cache.parent / row['archive']
                    require(archive.resolve().parent == args.image_cache.resolve().parent
                            and not archive.is_symlink() and digest(archive) == row['sha256'], '이미지 캐시 파일이 바뀌었습니다.')
                    run('cache-load-' + row['name'], ['docker', 'load', '--input', str(archive)], timeout=600)
                    image = json.loads(run('cache-inspect-' + row['name'], ['docker', 'image', 'inspect', row['tag']]))[0]
                    require(image['Os'] == 'linux' and image['Architecture'] == 'amd64'
                            and image['RootFS']['Layers'] == row['rootfs'], '공식 캐시 이미지의 실행 내용이 다릅니다.')
                print('공식 이미지 캐시 4개 무결성 확인 · 제품 Dockerfile로 새 앱 빌드', flush=True)
                run('install-cached', ['python3', 'deploy/server/manage.py', 'install', '--build'], timeout=1800)
                after = fingerprint()
                require(all(after.get(k) == v for k, v in prepared.items()), '준비 후 설치 중 키·인증서가 바뀌었습니다.')
                results.update(uninterrupted_fresh_install=False, fresh_prepared_install=True,
                               verified_official_images_preloaded=4, direct_registry_download_verified=False)
            else:
                action('install', ['sh', 'soc', 'install'], prompts=[
                    ('설치 환경 [lab]:', 'lab'), ('포털 접속 DNS 또는 IPv4', 'localhost'),
                    ('바인딩 IPv4 [127.0.0.1]:', ''), ('장치 수집 DNS 또는 IPv4 [포털과 동일]:', ''),
                    ('시각을 확인했고 설치를 계속하려면 yes 입력', 'yes'),
                    ('y/yes/INSTALL 입력', 'yes'), ('Portal 관리자 비밀번호 (입력 내용은 표시되지 않습니다):', password),
                    ('비밀번호 확인:', password)])
                results['uninterrupted_fresh_install'] = True
                results['direct_registry_download_verified'] = True
                results['verified_official_images_preloaded'] = 0
        except RuntimeError:
            state = PROJECT / 'state/server'
            failed = (reports / 'install.log').read_text()
            require((state / 'compose.env').is_file() and not (state / 'runtime/current.json').exists()
                    and not (state / 'runtime/pending.json').exists()
                    and 'Docker image build' in failed, '알 수 없는 설치 실패는 자동 복구 시험으로 넘기지 않습니다.')
            prepared = fingerprint()
            print('최초 이미지 빌드 실패 · 문서의 준비 상태 복구 절차를 확인합니다.', flush=True)
            run('prepared-state-recovery', ['python3', 'deploy/server/manage.py', 'install', '--build'], timeout=1800)
            after = fingerprint()
            require(all(after.get(k) == v for k, v in prepared.items()), '준비 상태 복구 중 기존 키·인증서가 바뀌었습니다.')
            results.update(uninterrupted_fresh_install=False, prepared_state_recovery=True,
                           prepared_credentials_preserved=True)
        print('설치 완료 · 새 WSL의 전용 Docker 사용', flush=True)
        text = action('status', ['sh', 'soc', 'status'])
        require('필수 서비스 12개 · 실행 중 12개 · 확인 필요 0개' in text, '필수 서비스 상태가 다릅니다.')
        action('menu', ['sh', 'soc'], prompts=[('명령 [exit]:', 'exit')])
        action('help', ['sh', 'soc', '--help'])
        run('startup', ['python3', 'deploy/server/manage.py', 'verify', '--startup-only'])
        check_portal('fresh-portal')
        results['fresh_portal_tls_login_and_apis'] = True
        print('신규 설치의 HTTPS 로그인·대시보드 API 확인', flush=True)
        active = json.loads(subprocess.check_output(['docker','inspect', *run('container-ids', ['docker', 'ps', '-q']).split()]))
        expected_init = {'normalizer','normalizer-priority','detector','detector-priority','detector-additional','detector-retrospective','slack-notifier','enrollment-cleanup'}
        require(all(row['HostConfig'].get('Init') is True for row in active if row['Config']['Labels']['com.docker.compose.service'] in expected_init), '작업자 init가 실제 컨테이너에 적용되지 않았습니다.')
        initial = fingerprint()
        canary = {'synthetic': True, 'marker': 'server-ux-preservation'}
        es('/soc-server-ux-canary/_create/owned-1?refresh=wait_for', 'PUT', canary)
        compatibility = '--management-overlay' in sys.argv
        release_source = PROJECT
        management_manifest = None
        public_names = ('src', 'rules', 'prototype', 'deploy', 'requirements.txt', 'constraints.txt', 'soc', '.dockerignore')
        def copy_public(source, destination):
            require(not destination.exists(), '시험 소스 경로가 이미 있습니다.')
            destination.mkdir(mode=0o700)
            for name in public_names:
                item = source / name
                if item.is_dir():
                    shutil.copytree(item, destination / name, ignore=shutil.ignore_patterns('__pycache__', '*.pyc'))
                else:
                    shutil.copy2(item, destination / name)
        if '--deployment-guards-check' in sys.argv:
            state = PROJECT / 'state/server'
            runtime = state / 'runtime'
            release = Path('/srv/cloud-soc-safety-candidate')
            copy_public(PROJECT, release)
            # Model the older mutable-site format, then reuse its actual tag.
            site_path = runtime / 'site.json'
            site = json.loads(site_path.read_text())
            tag = 'cloud-soc-central-runtime:local'
            from cloud_soc.deployment.contract import APP_SERVICES
            for name in (*APP_SERVICES, 'bootstrap'):
                site['services'][name]['image'] = tag
            site_path.write_text(json.dumps(site))
            old_command = json.loads((runtime / 'compose.active.json').read_text())
            run('safety-legacy-site-setup', [*old_command, 'up', '-d', '--no-build', '--pull', 'never'])
            old_images = service_images('safety-old-container-images')
            before = runtime_identity()
            manager = release / 'deploy/server/manage.py'
            (release / 'deploy/server/rollback-marker.txt').write_text('different candidate source for rollback\n')
            run('safety-candidate-build', ['python3', str(manager), 'build', '--workspace', str(release),
                '--image', tag], timeout=1800)
            candidate = json.loads(run('safety-candidate-id', ['docker', 'image', 'inspect', tag]))[0]['Id']
            require(candidate != old_images['portal'] and runtime_identity() == before,
                    '태그 재사용 후보가 실제 이전 이미지와 다르거나 실행 보존 조건을 만족하지 못했습니다.')
            # No disk filling: only the free-space reading is synthetic; Docker info is real.
            low_disk = ('import sys;from types import SimpleNamespace;from unittest.mock import patch;'
                f'sys.path.insert(0,{str(release / "src")!r});'
                'from cloud_soc.deployment.downloads import build_runtime_image;'
                'from cloud_soc.deployment.host import Docker;'
                'from cloud_soc.deployment import image_safety;'
                f'ctx=patch.object(image_safety.shutil,"disk_usage",return_value=SimpleNamespace(free=0));ctx.start();'
                f'build_runtime_image(Docker(),{str(release)!r},"fixture:low-disk-never-built")')
            reply = subprocess.run(['python3', '-c', low_disk], capture_output=True, text=True, timeout=60)
            require(reply.returncode != 0 and 'DeploymentSafetyError' in reply.stderr and runtime_identity() == before,
                    '저용량 합성 읽기에서 빌드가 거부되지 않았습니다.')
            results['low_disk_rejected_before_build'] = True
            compose_path = release / 'deploy/server/compose.yaml'
            compose_text = compose_path.read_text()
            missing = 'cloud-soc-guard-fixture:gateway-not-cached'
            import re
            changed, count = re.subn(r'(image:\s*)caddy:[^\s]+', r'\g<1>' + missing, compose_text)
            require(count == 1, '게이트웨이 합성 이미지 설정을 특정할 수 없습니다.')
            compose_path.write_text(changed)
            run('safety-missing-image-candidate-build', ['python3', str(manager), 'build', '--workspace', str(release),
                '--image', tag], timeout=1800)
            candidate = json.loads(run('safety-final-candidate-id', ['docker', 'image', 'inspect', tag]))[0]['Id']
            plan = Path('/run/cloud-soc-safety-plan.json')
            plan_command = ['python3', str(manager), 'plan', '--workspace', str(release), '--state', str(state),
                            '--image', tag, '--plan', str(plan)]
            reply = subprocess.run(plan_command, capture_output=True, text=True, timeout=900)
            save('safety-missing-image-plan.log', reply.stdout + reply.stderr)
            require(reply.returncode != 0 and 'prepare-images' in reply.stderr and not plan.exists()
                    and runtime_identity() == before, '기반 이미지 누락 때 서비스 중지 전 계획 거부가 안 됐습니다.')
            results['missing_infrastructure_refused_before_stop'] = True
            run('safety-fixture-image-cache', ['docker', 'tag', old_images['gateway'], missing])
            run('safety-prepare-images', ['python3', str(manager), 'prepare-images', '--workspace', str(release),
                '--state', str(state), '--image', tag], timeout=900)
            require(runtime_identity() == before and fingerprint() == initial, '이미지 준비가 실행 또는 키를 바꿨습니다.')
            run('safety-reviewed-plan', plan_command, timeout=900)
            # Fail once AFTER real candidate containers are started; rollback must
            # start the old IDs even though their original tag points at the candidate.
            with tempfile.TemporaryDirectory(prefix='soc-rollback-fault-') as temporary:
                marker = Path(temporary) / 'candidate-started.json'
                wrapper = Path(temporary) / 'docker'
                wrapper.write_text('#!/usr/bin/python3\nimport json,os,pathlib,subprocess,sys\n'
                    f'p=pathlib.Path({str(marker)!r})\n'
                    f'if "up" in sys.argv and {str(release / "deploy/server/compose.yaml")!r} in sys.argv and not p.exists():\n'
                    ' r=subprocess.run(["/usr/bin/docker",*sys.argv[1:]])\n'
                    ' if r.returncode: sys.exit(r.returncode)\n'
                    ' value=subprocess.check_output(["/usr/bin/docker","inspect","--format","{{.Image}}","cloud-soc-central-portal-1"],text=True).strip()\n'
                    ' p.write_text(json.dumps({"image_id":value}));sys.exit(1)\n'
                    'os.execv("/usr/bin/docker",["docker",*sys.argv[1:]])\n')
                wrapper.chmod(0o700)
                environment = {**os.environ, 'PATH': temporary + ':' + os.environ['PATH']}
                reply = subprocess.run(['python3', str(manager), 'apply', '--plan', str(plan)],
                                       capture_output=True, text=True, timeout=1800, env=environment)
                save('safety-failed-apply-rollback.log', reply.stdout + reply.stderr)
                require(reply.returncode != 0 and marker.is_file() and json.loads(marker.read_text())['image_id'] == candidate,
                        '실제 후보 실행 뒤 합성 실패가 발생하지 않았습니다.')
            restored = service_images('safety-restored-images')
            require(restored == old_images,
                    '태그 재사용 실패 복구가 이전 실제 이미지 ID로 복원되지 않았습니다.')
            require(not (runtime / 'pending.json').exists() and fingerprint() == initial,
                    '복구 기록 또는 기존 보호 자료가 다릅니다.')
            require(json.loads(run('safety-tag-still-new', ['docker', 'image', 'inspect', tag]))[0]['Id'] == candidate,
                    '복구 중 공유 태그를 덮어썼습니다.')
            recovered_site = json.loads(site_path.read_text())
            for name, row in site['services'].items():
                for key, value in row.items():
                    if key != 'image':
                        require(recovered_site['services'][name][key] == value, '복구 중 이미지 외 사이트 설정이 달라졌습니다.')
            require('실행 중 12개 · 확인 필요 0개' in action('safety-status', ['sh', 'soc', 'status']), '복구 후 상태 확인 실패')
            run('safety-removal-preview', ['python3', 'deploy/server/uninstall.py', '--workspace', str(PROJECT)])
            run('safety-next-plan', plan_command, timeout=900)
            require(es('/soc-server-ux-canary/_doc/owned-1')['_source'] == canary, '복구 뒤 합성 원본이 다릅니다.')
            check_portal('safety-restored-portal')
            results['same_tag_actual_activation_failure_exact_id_rollback'] = True
            results['rollback_status_removal_preview_and_next_plan'] = True
            results['rollback_tls_portal_data_keys_preserved'] = True
            results['infrastructure_fixture_scope'] = 'same vendor binary alias; not vendor upgrade compatibility'
            print('태그 재사용 실패 복구·이미지 누락 사전 차단·디스크 부족 차단 확인', flush=True)
        if '--image-source-check' in sys.argv:
            from contextlib import redirect_stdout
            import importlib.util
            import io
            from cloud_soc.deployment.host import Docker
            spec = importlib.util.spec_from_file_location('image_source_manage', PROJECT / 'deploy/server/manage.py')
            manager_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(manager_module)
            observations = []
            class ObservedDocker(Docker):
                def run(self, args, **kw):
                    if args[0] == 'compose' and 'pull' in args:
                        cut = args.index('pull')
                        rendered = json.loads(super().run(args[:cut] + ['config', '--format', 'json'], env=kw.get('env')))
                        observations.append((args[-1], rendered['services'][args[-1]]['image']))
                    return super().run(args, **kw)
            engine = ObservedDocker()
            original = Docker().json(['compose', '--env-file', str(PROJECT / 'state/server/compose.env'),
                '-f', str(PROJECT / 'deploy/server/compose.yaml'), 'config', '--format', 'json'])
            vendor_image = original['services']['gateway']['image']
            tags = ['cloud-soc-image-source:' + label for label in ('es-config','kibana-config','gateway-v1','gateway-v2')]
            existing = engine.run(['image','ls','--format','{{.Repository}}:{{.Tag}}']).splitlines()
            require(not any(tag in existing for tag in tags), '시험 이미지 태그가 이미 있습니다.')
            before_identity = runtime_identity()
            created = []
            cases = []
            try:
                for tag in tags:
                    engine.run(['image','tag',vendor_image,tag])
                    created.append(tag)
                with tempfile.TemporaryDirectory(prefix='soc-image-source-') as temporary:
                    workspace = Path(temporary)
                    fixture = workspace / 'deploy/server/compose.yaml'
                    fixture.parent.mkdir(parents=True)
                    state = workspace / 'state'
                    state.mkdir()
                    (state / 'compose.env').write_text('SOC_IMAGE_SOURCE_GATEWAY=' + tags[2] + '\n')
                    for label, gateway in (('initial', tags[2]), ('config-only-change', tags[3]),
                                           ('environment-override', '${SOC_IMAGE_SOURCE_GATEWAY:?}')):
                        fixture.write_text('services:\n  elasticsearch:\n    image: ' + tags[0] +
                            '\n  kibana:\n    image: ' + tags[1] + '\n  gateway:\n    image: ' + gateway + '\n')
                        environment = {'SOC_IMAGE_SOURCE_GATEWAY': tags[3]}
                        observations.clear()
                        cached_before = engine.run(['image','ls','--no-trunc','--format','{{.ID}} {{.Repository}}:{{.Tag}}'])
                        with redirect_stdout(io.StringIO()) as captured:
                            manager_module.prepare_install_images(engine, workspace, state, environment)
                        save('image-source-' + label + '.log', captured.getvalue())
                        expected = [('elasticsearch',tags[0]),('kibana',tags[1]),
                                    ('gateway',tags[2] if label == 'initial' else tags[3])]
                        require(observations == expected, '실제 Compose의 이미지 선택이 배포 설정과 다릅니다.')
                        require(cached_before == engine.run(['image','ls','--no-trunc','--format','{{.ID}} {{.Repository}}:{{.Tag}}']),
                                '기존 호환 이미지 대신 다른 이미지를 받았습니다.')
                        cases.append({'case': label, 'actual_compose_images': list(observations), 'cache_reused': True})
                require(runtime_identity() == before_identity, '이미지 준비 중 서비스 시작/재시작 상태가 변경됐습니다.')
                require(fingerprint() == initial, '이미지 준비 중 보호 입력이 변경됐습니다.')
            finally:
                if created:
                    engine.run(['image','rm',*created])
            save('image-source-probe.json', json.dumps({'cases': cases, 'no_container_restart': True,
                                                       'protected_inputs_preserved': True}))
            results['image_source_configuration_cases'] = len(cases)
            results['image_source_config_change_and_environment_verified'] = True
            results['image_source_cache_reused'] = True
            results['image_source_no_container_restart'] = True
            print('실제 Compose로 설정의 이미지 버전 변경·환경 변수·캐시 재사용 확인', flush=True)
        if compatibility:
            profile = Path(sys.argv[sys.argv.index('--management-overlay') + 1])
            expected = sys.argv[sys.argv.index('--management-overlay-sha256') + 1]
            require(digest(profile / 'wsl-inputs.json') == expected, '관리 파일 목록이 변경됐습니다.')
            management_manifest = json.loads((profile / 'wsl-inputs.json').read_text())
            require(set(management_manifest['files']) == set(MANAGEMENT_FILES), '허용된 관리 파일 목록이 다릅니다.')
            require(digest(profile / 'wsl-inputs.tar') == management_manifest['archive_sha256'], '관리 파일 압축본이 변경됐습니다.')
            release_source = Path('/srv/cloud-soc-before-management')
            copy_public(PROJECT, release_source)
            with tarfile.open(profile / 'wsl-inputs.tar') as archive:
                members = archive.getmembers()
                present = {n for n, h in management_manifest['files'].items() if h is not None}
                require(len(members) == len(present) and {m.name for m in members} == present,
                        '관리 파일 압축 항목이 다릅니다.')
                contents = {}
                for member in members:
                    require(member.isfile(), '관리 파일은 일반 파일이어야 합니다.')
                    data = archive.extractfile(member).read()
                    require(hashlib.sha256(data).hexdigest() == management_manifest['files'][member.name],
                            '중앙 관리 파일 지문이 다릅니다.')
                    contents[member.name] = data
            for name, wanted in management_manifest['files'].items():
                target = PROJECT / name
                require(not any(p.is_symlink() for p in (target, *target.parents)) and
                        (not target.exists() or target.is_file()), '관리 시험 경로의 링크/형식을 거부했습니다.')
                if wanted is None:
                    target.unlink(missing_ok=True)
                else:
                    target.write_bytes(contents[name])
                    target.chmod(0o755 if name == 'soc' else 0o644)
                cache = target.parent / '__pycache__'
                require(not cache.is_symlink(), '연결된 시험 캐시 경로를 거부했습니다.')
                if target.suffix == '.py' and cache.is_dir():
                    for compiled in cache.glob(target.stem + '.*.pyc'):
                        require(compiled.is_file() and not compiled.is_symlink(), '시험 캐시의 링크/형식을 거부했습니다.')
                        compiled.unlink()
            require(all((digest(PROJECT / n) if (PROJECT / n).is_file() else None) == h
                        for n, h in management_manifest['files'].items()), '중앙 관리 파일 조합이 다릅니다.')
            require(fingerprint() == initial, '관리 파일 교체 중 보호 입력이 변경됐습니다.')
            require('실행 중 12개 · 확인 필요 0개' in action('compatibility-status', ['sh', 'soc', 'status']),
                    '중앙 호환 도구의 상태 조회가 실패했습니다.')
            run('compatibility-removal-preview', ['python3', 'deploy/server/uninstall.py', '--workspace', str(PROJECT)])
            results['central_management_manifest_sha256'] = expected
            results['central_management_files_matched'] = True
            print('중앙의 관리 파일 지문·없는 모듈까지 동일하게 반영 · 상태/삭제 미리보기 확인', flush=True)
        if '--upgrade-check' in sys.argv:
            print('릴리스 폴더 갱신·다음 외부 릴리스 전환을 확인합니다.', flush=True)
            for label in ('a', 'b'):
                release = Path('/srv/cloud-soc-release-' + label)
                copy_public(release_source, release)
                manager = (PROJECT if compatibility else release) / 'deploy/server/manage.py'
                image = 'cloud-soc-runtime:wsl-release-' + label
                before_build = run('before-build-containers-' + label, ['docker', 'ps', '-aq', '--no-trunc'])
                before_identity = runtime_identity()
                save('before-build-identity-' + label + '.json', json.dumps(before_identity))
                with tempfile.TemporaryDirectory(prefix='soc-candidate-retry-') as retry_dir:
                    environment = os.environ.copy()
                    marker = Path(retry_dir) / 'attempted'
                    wrapper = Path(retry_dir) / 'docker'
                    # One synthetic transport failure, followed by the real
                    # Docker build. This affects only the candidate subprocess.
                    wrapper.write_text('#!/usr/bin/python3\nimport os,pathlib,sys\n'
                        f'p=pathlib.Path({str(marker)!r})\n'
                        'if "build" in sys.argv and not p.exists():\n'
                        ' p.write_text("synthetic-once")\n'
                        ' print("connection reset by peer (synthetic candidate retry)", flush=True)\n'
                        ' sys.exit(1)\n'
                        'os.execv("/usr/bin/docker", ["docker", *sys.argv[1:]])\n')
                    wrapper.chmod(0o700)
                    if label == 'a':
                        environment['PATH'] = retry_dir + ':' + environment['PATH']
                    built = run('upgrade-build-' + label, ['python3', str(manager),
                        'build', '--workspace', str(release), '--image', image], timeout=1800, env=environment)
                    receipt = json.loads(built.splitlines()[-1])
                    require(receipt['built'] is True and receipt['activation_performed'] is False,
                            '후보 빌드가 적용 완료로 표시됐습니다.')
                    if label == 'a':
                        require(marker.is_file() and built.count('초 후 재시도합니다') == 1,
                                '합성 일시 오류 뒤 실제 후보 빌드 재시도를 확인하지 못했습니다.')
                        results['upgrade_build_retry_then_real_build'] = True
                require(run('after-build-containers-' + label, ['docker', 'ps', '-aq', '--no-trunc']) == before_build,
                        '후보 빌드 중 컨테이너가 변경됐습니다.')
                after_identity = runtime_identity()
                save('after-build-identity-' + label + '.json', json.dumps(after_identity))
                require(after_identity == before_identity, '후보 빌드 중 서비스 시작 시각/재시작 횟수가 변경됐습니다.')
                results['upgrade_build_no_container_restart'] = True
                require(fingerprint() == initial, '후보 빌드 중 키·인증서가 변경됐습니다.')
                require(es('/soc-server-ux-canary/_doc/owned-1')['_source'] == canary,
                        '후보 빌드 중 기존 자료가 변경됐습니다.')
                results['upgrade_build_preserves_services_and_protected_inputs'] = True
                # Never export a deployment plan: it includes protected runtime configuration.
                plan = Path('/run/cloud-soc-upgrade-plan-' + label + '.json')
                run('upgrade-plan-summary-' + label, ['python3', str(manager), 'plan',
                    '--workspace', str(release), '--state', str(PROJECT / 'state/server'),
                    '--image', image, '--plan', str(plan)], timeout=900)
                run('upgrade-apply-' + label, ['python3', str(manager), 'apply',
                    '--plan', str(plan)], timeout=1800)
                require(fingerprint() == initial, '릴리스 갱신 뒤 키·인증서가 바뀌었습니다.')
                require(es('/soc-server-ux-canary/_doc/owned-1')['_source'] == canary, '릴리스 갱신 뒤 원본이 다릅니다.')
                require('실행 중 12개 · 확인 필요 0개' in action('upgraded-status-' + label, ['sh', 'soc', 'status']), '갱신 뒤 서비스 상태가 다릅니다.')
            results['same_source_release_directory_upgrades'] = 2
            results['older_release_compatibility_verified'] = False
            check_portal('upgraded-portal')
            results['upgraded_portal_tls_login_and_apis'] = True
            print('두 번의 실제 릴리스 갱신·키/인증서/합성 원본 보존 확인', flush=True)
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
        if '--deployment-guards-check' in sys.argv:
            run('safety-explicit-recovery-image-removal', ['python3', 'deploy/server/uninstall.py',
                '--workspace', str(PROJECT), '--remove-images', '--apply', '--yes'], timeout=600)
            require(not run('safety-no-recovery-tags', ['docker', 'image', 'ls', '--filter',
                'reference=cloud-soc-recovery:*', '--format', '{{.Repository}}:{{.Tag}}']).strip(),
                '명시한 이미지 제거 후 복구 태그가 남았습니다.')
            results['explicit_recovery_image_removal'] = True
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
    parser.add_argument('--image-sha256', default=IMAGE_HASH, choices=(IMAGE_HASH,
        'e77b6f10c2590cef872b33ee9f635a0e3fd1f57fb074c0e52b5c7f56147a0c86'))
    parser.add_argument('--upgrade-check', action='store_true')
    parser.add_argument('--image-source-check', action='store_true')
    parser.add_argument('--deployment-guards-check', action='store_true')
    parser.add_argument('--management-overlay', type=Path, help='Optional hash-pinned public management files captured from the central VM')
    parser.add_argument('--management-overlay-sha256')
    parser.add_argument('--image-cache', type=Path, help='Optional verified public vendor-image bundle; not a direct-download acceptance')
    parser.add_argument('--https-apt-ca', type=Path, help='Test-only public CA bundle for HTTPS Ubuntu repositories')
    parser.add_argument('--https-apt-ca-sha256')
    parser.add_argument('--state', type=Path)
    parser.add_argument('--delete-image-cache', action='store_true')
    parser.add_argument('--diagnose-seconds', type=int, default=0)
    args = parser.parse_args()
    if args.inside:
        inside_main()
    else:
        require(args.run and args.image and args.state, '--run·--image·--state가 필요합니다.')
        sys.exit(windows_main(args))
