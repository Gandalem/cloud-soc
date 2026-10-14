"""Explicit loopback SSH exercise: ten failed attempts, no account/policy changes."""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile


def exercise(directory, *, clean_source):
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run the explicit SSH exercise on its approved Linux target')
    if not all(shutil.which(name) for name in ('ssh', 'setsid', 'getent')):
        raise ValueError('Existing local OpenSSH client and setsid required; no packages installed')
    started = datetime.now(timezone.utc).isoformat()
    token = hashlib.sha256(started.encode()).hexdigest()[:12]
    source = '127.77.' + str(int(token[:2], 16)) + '.' + str(1 + int(token[2:4], 16) % 253)
    user = 'socprobe_' + token
    if subprocess.run(['getent', 'passwd', user], capture_output=True).returncode == 0 or not clean_source(source):
        raise ValueError('Probe account/source is not isolated from existing observations')
    host_key = Path('/etc/ssh/ssh_host_ed25519_key.pub')
    if not host_key.is_file() or host_key.is_symlink():
        raise ValueError('Trusted local public SSH host key is required')
    directory = Path(directory);directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='ssh-exercise-', dir=directory) as temporary:
        root = Path(temporary);ask = root / 'askpass';known = root / 'known_hosts'
        ask.write_text("#!/bin/sh\nprintf '%s\\n' 'cloud-soc-invalid-deployment-probe'\n");ask.chmod(0o700)
        known.write_text('127.0.0.1 ' + host_key.read_text().strip() + '\n');known.chmod(0o600)
        env = {**os.environ, 'SSH_ASKPASS': str(ask), 'SSH_ASKPASS_REQUIRE': 'force', 'DISPLAY': 'cloud-soc-verification'}
        exits = []
        for _ in range(10):
            p = subprocess.run(['setsid', '--wait', 'ssh', '-F', '/dev/null', '-b', source,
                '-o', 'PreferredAuthentications=password', '-o', 'PubkeyAuthentication=no',
                '-o', 'NumberOfPasswordPrompts=1', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile=' + str(known), '-o', 'GlobalKnownHostsFile=/dev/null',
                '-o', 'ConnectTimeout=4', user + '@127.0.0.1', 'true'],
                stdin=subprocess.DEVNULL, capture_output=True, timeout=12, env=env)
            exits.append(p.returncode)
            if p.returncode != 255:
                raise ValueError('Unexpected authentication outcome; exercise stopped')
    # Failed SSH exits are only attempts; ES/normalization/final alert remain separate acceptance gates.
    return {'kind': 'real_loopback_ssh_attempts', 'source_ip': source, 'username': user, 'attempts': 10,
            'started_at': started, 'completed_at': datetime.now(timezone.utc).isoformat(),
            'authentication_policy_changed': False, 'central_receipt_verified': False}


def main():
    import argparse
    from cloud_soc.deployment.host import Docker
    from cloud_soc.deployment.migrations import atomic_json
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args();engine = Docker()
    def clean(ip):
        code = "import json,sys;from cloud_soc.portal.app import create_app;c=create_app().extensions['monitor'];d=json.load(sys.stdin);r=c.count(index='soc-normalized-v1',query={'bool':{'filter':[{'term':{'source.ip':d['ip']}},{'range':{'@timestamp':{'gte':'now-20m'}}}]}});assert not r.get('_shards',{}).get('failed');print(json.dumps(r['count']==0))"
        return engine.json(['exec', '-i', 'cloud-soc-central-portal-1', 'python', '-c', code], input=json.dumps({'ip': ip}))
    result = exercise(args.state / 'runtime/probes', clean_source=clean)
    output = args.state / 'runtime/probes' / (result['username'] + '.json')
    atomic_json(output, result)
    print(json.dumps(result | {'receipt': str(output)}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('ssh_exercise_not_verified; no account/firewall/SSH policy changes; details omitted') from None
