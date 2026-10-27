#!/usr/bin/env python3
"""Preserve the previous JAR, rebuild, then restart only this user's mall.

No HTTP health request, synthetic action, test, syntax check or collector change.
"""
import argparse
import os
from pathlib import Path
import shutil
import signal
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--mall', type=Path, default=Path.home() / 'security-mall')
    a = p.parse_args()
    mall = a.mall.expanduser().resolve()
    if os.getuid() == 0:
        raise ValueError('Run without sudo')
    os.umask(0o077)
    pidfile = mall / 'mall.pid'
    # Existing launcher uses this PID and an absolute -jar path.
    pid = int(pidfile.read_text().strip())
    proc = Path('/proc') / str(pid)
    if proc.stat().st_uid != os.getuid():
        raise ValueError('Existing mall process owner differs')
    args = [os.fsdecode(v) for v in (proc / 'cmdline').read_bytes().split(b'\0') if v]
    if '-jar' not in args or Path(args[0]).name != 'java':
        raise ValueError('Expected the existing mall Java process')
    oldjar = Path(args[args.index('-jar') + 1]).resolve()
    if not oldjar.is_relative_to(mall) or Path(os.readlink(proc / 'cwd')).resolve() != mall:
        raise ValueError('Existing Java process belongs to another application')
    # Stop before Gradle can overwrite classes read by the running executable JAR.
    # Preserve an executable rollback artifact before rebuilding.
    backup = mall / 'audit' / ('previous-app-' + time.strftime('%Y%m%dT%H%M%SZ', time.gmtime()) + '.jar')
    with backup.open('xb') as out, oldjar.open('rb') as src:
        shutil.copyfileobj(src, out)
    os.kill(pid, signal.SIGTERM)
    for _ in range(60):
        if not proc.exists():
            break
        time.sleep(1)
    else:
        raise RuntimeError('Old mall did not stop; no force kill or build performed')
    try:
        subprocess.run(['bash', 'gradlew', '--no-daemon', '--max-workers=1',
            '-Dorg.gradle.jvmargs=-Xmx512m', 'bootJar', '-x', 'test', '--console=plain'], cwd=mall, check=True)
        jars = [f for f in (mall / 'build/libs').glob('*.jar') if not f.name.endswith('-plain.jar')]
        if len(jars) != 1:
            raise ValueError('Expected a single application JAR')
        jar = jars[0].resolve()
    except Exception:
        jar = backup
        print('Build stopped; launching the preserved previous JAR. Business source changes remain unapplied.')
    with (mall / 'mall-console.log').open('ab') as log:
        child = subprocess.Popen(['java', '-Xms128m', '-Xmx512m',
            '-Dmall.audit.dir=' + str(mall / 'audit'), '-jar', str(jar),
            '--server.address=127.0.0.1', '--server.port=8080',
            '--spring.servlet.multipart.max-file-size=5MB', '--spring.servlet.multipart.max-request-size=6MB'],
            cwd=mall, stdin=subprocess.DEVNULL, stdout=log, stderr=log, start_new_session=True)
    pidfile.write_text(str(child.pid) + '\n')
    print('Java process launch requested; PID=' + str(child.pid) + '; no startup/HTTP verification performed')
    print('Existing DB, accounts, login audit key and login collector preserved. Local page: http://127.0.0.1:8080/soc-business')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print('Business restart stopped: ' + type(error).__name__ + '; no force kill, DB reset or credential replacement')
        raise SystemExit(1)
