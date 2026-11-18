"""Root-owned timer runner: isolated one-shot container, no Portal dependency."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--test-notification', action='store_true')
    args = parser.parse_args()
    p = args.config
    if p.is_symlink() or p.stat().st_uid != 0 or p.stat().st_mode & 0o077:
        raise ValueError('Private root-owned configuration required')
    cfg = json.loads(p.read_text())
    state = Path(cfg['state'])
    with (state / 'host.lock').open('a') as lock:
        os.chmod(state / 'host.lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        usage = shutil.disk_usage(cfg['disk_path'])
        disk = 100 * (usage.total - usage.free) / usage.total
        reserve = state / 'monitor.reserve'
        if reserve.is_symlink():
            raise ValueError('Unsafe reserve')
        if disk >= 85 and reserve.exists():
            reserve.unlink()  # Only this monitor's expendable reserve, never evidence.
        elif disk < 75 and not reserve.exists():
            fd = os.open(reserve, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            try:
                os.posix_fallocate(fd, 0, 16 * 1024 * 1024)
            finally:
                os.close(fd)
        mounts = [(cfg['probe'], '/watchdog.py', True), (cfg['ca'], '/run/ca.crt', True),
                  (cfg['password'], '/run/monitor-password', True),
                  (cfg['notifications'], '/notifications', True), (cfg['state'], '/health', False)]
        command = ['docker', 'run', '--rm', '-i', '--name', 'cloud-soc-health-watchdog-probe',
                   '--user', f'{cfg["probe_uid"]}:{cfg["probe_gid"]}',
                   '--network', cfg['network'], '--read-only', '--cap-drop', 'ALL',
                   '--security-opt', 'no-new-privileges:true', '--memory', '192m', '--pids-limit', '64',
                   '--tmpfs', '/tmp:rw,nosuid,noexec,size=16m']
        for source, target, readonly in mounts:
            command += ['--mount', f'type=bind,src={source},dst={target}' + (',readonly' if readonly else '')]
        command += ['--entrypoint', 'python', cfg['image'], '/watchdog.py']
        if args.dry_run:
            command += ['--dry-run']
        if args.test_notification:
            command += ['--test-notification']
        try:
            result = subprocess.run(command, input=json.dumps({'disk': disk, 'policy': cfg.get('policy', {})}),
                                    text=True, capture_output=True, timeout=150)
        except subprocess.TimeoutExpired:
            subprocess.run(['docker', 'rm', '-f', 'cloud-soc-health-watchdog-probe'],
                           capture_output=True, timeout=15)
            raise RuntimeError('probe_timeout') from None
        if result.returncode:
            raise RuntimeError('probe_failed')
        # Only a validated probe response can enter the journal; never Docker stderr/credentials.
        report = json.loads(result.stdout)
        print(json.dumps(report))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('health_watchdog_host_failed; inspect service status; protected details omitted') from None
