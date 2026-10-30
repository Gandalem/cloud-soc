#!/usr/bin/env python3
"""Build/restart only this user's local mall, then install the audit collector."""
import os
import argparse
from pathlib import Path
import signal
import subprocess
import sys
import time
from urllib.parse import urlencode
from urllib.request import Request, urlopen

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--mall', type=Path, default=Path.home() / 'security-mall')
parser.add_argument('--manual-actions', action='store_true', help='Start only; the user performs real login actions before connecting')
parser.add_argument('--sudo-docker', action='store_true', help='Use cached sudo only for Docker; keep mall files owned by this user')
options = parser.parse_args()
mall = options.mall.expanduser().resolve()
docker_command = ['sudo', '-n', 'docker'] if options.sudo_docker else ['docker']
if os.getuid() == 0:
    sys.exit('sudo 없이 쇼핑몰 소유자 계정으로 실행하세요. Docker만 sudo가 필요하면 --sudo-docker를 사용하세요.')
if subprocess.run([*docker_command, 'info'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode:
    sys.exit('Docker 접근 불가. sudo -v 후 --sudo-docker를 사용하거나 Docker 접근 가능한 일반 터미널에서 실행하세요.')
subprocess.run(['bash', 'gradlew', '--no-daemon', '--max-workers=1',
                '-Dorg.gradle.jvmargs=-Xmx512m', 'bootJar', '--console=plain'], cwd=mall, check=True)
jars = [p for p in (mall / 'build/libs').glob('*.jar') if not p.name.endswith('-plain.jar')]
if len(jars) != 1:
    sys.exit('실행 JAR을 하나로 확정할 수 없습니다.')
jar = jars[0].resolve()
targets = []
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit():
        continue
    try:
        if entry.stat().st_uid != os.getuid():
            continue
        args = (entry / 'cmdline').read_bytes().split(b'\0')
        if not args or Path(os.fsdecode(args[0])).name != 'java':
            continue
        main = b'com.security.securitymall.SecuritymallApplication' in args
        belongs = str(mall).encode() in b' '.join(args)
        if (main and belongs) or str(jar).encode() in args:
            targets.append(int(entry.name))
    except (OSError, ValueError):
        continue
for pid in targets:
    os.kill(pid, signal.SIGTERM)
for _ in range(30):
    if all(not Path('/proc/' + str(pid)).exists() for pid in targets):
        break
    time.sleep(1)
else:
    sys.exit('기존 쇼핑몰 종료 대기 시간 초과. 강제 종료하지 않습니다.')
os.umask(0o077)
with (mall / 'mall-console.log').open('ab') as out:
    child = subprocess.Popen(['java', '-Xms128m', '-Xmx512m', '-Dmall.audit.dir=' + str(mall / 'audit'), '-jar', str(jar),
                              '--server.address=127.0.0.1', '--server.port=8080'],
                             cwd=mall, stdin=subprocess.DEVNULL, stdout=out, stderr=out,
                             start_new_session=True)
(mall / 'mall.pid').write_text(str(child.pid) + '\n')
for _ in range(60):
    if child.poll() is not None:
        sys.exit('쇼핑몰 시작 실패. ~/security-mall/mall-console.log 확인 필요.')
    try:
        with urlopen('http://127.0.0.1:8080/login', timeout=2) as response:
            if response.status == 200:
                break
    except Exception:
        pass
    time.sleep(1)
else:
    sys.exit('쇼핑몰 시작 확인 시간 초과. 실행 로그를 확인하세요.')
if options.manual_actions:
    print('쇼핑몰 실행 완료: http://127.0.0.1:8080')
    print('브라우저에서 회원가입·로그인 성공/실패를 직접 수행하세요. 자동 로그인 요청은 만들지 않았습니다.')
    print('다른 터미널에서 connect.py --mall <같은 쇼핑몰 경로>로 수집을 연결하세요. Docker만 sudo가 필요하면 --sudo-docker를 추가하세요.')
    raise SystemExit(0)
# One deliberately failed login, no account or order creation.
req = Request('http://127.0.0.1:8080/login', data=urlencode({
    'username': 'local-audit-receipt-check', 'password': os.urandom(24).hex()}).encode())
with urlopen(req, timeout=10) as response:
    response.read(1)
connection = [sys.executable, str(root / 'connect.py'), '--mall', str(mall)]
if options.sudo_docker:
    connection.append('--sudo-docker')
subprocess.run(connection, check=True)
print('수신 대기 중...')
time.sleep(15)
subprocess.run([*connection, '--verify'], check=True)
