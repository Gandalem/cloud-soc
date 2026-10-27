#!/usr/bin/env python3
"""Verify the existing Elasticsearch password, repair its local deployment copy, resume."""
import getpass
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile

STATE = Path('/home/lyn/cloud-soc/state/server')
SECRET = STATE / 'secrets/elastic_password'
DEPLOY = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent/outputs/deploy-vm.sh')
IMAGE = 'cloud-soc-runtime:receipt-bdc2b02'
DOCKER = ['docker', '--host', 'unix:///var/run/docker.sock']
CHECK = '''import json,sys
from elasticsearch import Elasticsearch
password=json.load(sys.stdin)['password']
try:
    with Elasticsearch('https://elasticsearch:9200', basic_auth=('elastic',password),
                       ca_certs='/run/certs/ca.crt', request_timeout=20,max_retries=0) as c:
        if c.security.authenticate()['username'] != 'elastic':
            raise ValueError('unexpected_identity')
        c.security.get_role(name='cloud_soc_agent_monitor')
    print(json.dumps({'ok':True}))
except Exception as error:
    print(json.dumps({'ok':False,'http_status':getattr(getattr(error,'meta',None),'status',None)}))
    raise SystemExit(1) from None
'''


def verify(password):
    result = subprocess.run([*DOCKER, 'run', '--rm', '-i', '--network', 'cloud-soc-central_default',
        '--user', '0:0', '-v', str(STATE / 'tls/ca.crt') + ':/run/certs/ca.crt:ro',
        '--entrypoint', 'python', IMAGE, '-c', CHECK], input=json.dumps({'password':password}),
        text=True, capture_output=True, timeout=70)
    try:
        value = json.loads(result.stdout)
    except (ValueError, TypeError):
        raise SystemExit('Authentication check could not run; no credentials changed.') from None
    if result.returncode == 0 and value.get('ok') is True:
        return True
    if value.get('http_status') == 401:
        return False
    raise SystemExit('Authentication check failed for a reason other than a wrong password; no credentials changed.')


def replace_verified(password, original):
    current = SECRET.stat(follow_symlinks=False)
    if (current.st_ino, current.st_dev, current.st_mtime_ns, current.st_size) != (
            original.st_ino, original.st_dev, original.st_mtime_ns, original.st_size):
        raise SystemExit('Deployment credential changed concurrently; no replacement performed.')
    backup_fd, backup_name = tempfile.mkstemp(prefix='elastic-password-before-', dir=STATE / 'runtime')
    with os.fdopen(backup_fd, 'wb') as target:
        target.write(SECRET.read_bytes());target.flush();os.fsync(target.fileno())
    new_fd, new_name = tempfile.mkstemp(prefix='.elastic-password-', dir=SECRET.parent)
    try:
        with os.fdopen(new_fd, 'w') as target:
            target.write(password + '\n');target.flush();os.fsync(target.fileno())
            os.fchown(target.fileno(), original.st_uid, original.st_gid)
            os.fchmod(target.fileno(), stat.S_IMODE(original.st_mode))
        os.replace(new_name, SECRET)
        folder_fd = os.open(SECRET.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(folder_fd)
        finally:
            os.close(folder_fd)
    finally:
        if os.path.exists(new_name):
            os.unlink(new_name)
    print('Verified deployment credential saved. Previous file retained in a root-only backup.', flush=True)


def main():
    if os.geteuid() != 0:
        raise SystemExit('Run with sudo python3.')
    if (STATE / 'runtime/pending.json').exists():
        raise SystemExit('Interrupted upgrade record exists; recovery must be handled before a new deployment.')
    if SECRET.is_symlink() or SECRET.parent.is_symlink():
        raise SystemExit('Symlinked credential path refused.')
    original = SECRET.stat(follow_symlinks=False)
    if not stat.S_ISREG(original.st_mode) or original.st_size > 4096:
        raise SystemExit('Unexpected deployment credential file.')
    saved = SECRET.read_text().strip()
    print('Checking the saved deployment credential.', flush=True)
    selected = saved if verify(saved) else None
    if selected is None:
        # A bind-mounted secret may retain the previously valid inode. Never echo it.
        mounted = subprocess.run([*DOCKER, 'exec', 'cloud-soc-central-elasticsearch-1',
            'cat', '/run/secrets/elastic_password'], capture_output=True, text=True, timeout=15)
        if mounted.returncode == 0 and 0 < len(mounted.stdout) <= 4096:
            candidate = mounted.stdout.strip()
            if candidate != saved and verify(candidate):
                selected = candidate
                print('The existing mounted credential authenticated successfully.', flush=True)
    if selected is None:
        print('Enter the CURRENT Elasticsearch elastic password. This does not reset any account.', flush=True)
        for _ in range(3):
            candidate = getpass.getpass('Elasticsearch elastic password (hidden): ')
            if not candidate or len(candidate) > 4096 or '\n' in candidate or '\r' in candidate:
                print('Invalid input; retry.', flush=True)
                continue
            if verify(candidate):
                selected = candidate
                break
            print('Authentication failed; the credential file was not changed.', flush=True)
    if selected is None:
        raise SystemExit('No valid administrator credential supplied; deployment not resumed.')
    if selected != saved:
        replace_verified(selected, original)
    print('Administrator authentication verified; resuming protected deployment.', flush=True)
    os.execv('/bin/bash', ['/bin/bash', str(DEPLOY)])


if __name__ == '__main__':
    try:
        main()
    except (KeyboardInterrupt, EOFError):
        raise SystemExit('Cancelled; no password printed.') from None
    except Exception:
        raise SystemExit('Credential recovery stopped; no password printed. Do not delete runtime state.') from None
