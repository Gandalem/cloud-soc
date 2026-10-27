"""Real stop/removal against a new private daemon, never the host socket.

Run only through deploy/server/tests/server-removal.Dockerfile in a disposable
privileged container, --network none, without host sockets/directories mounted.
This is not an Ubuntu/systemd installation or a real-log acceptance test.
"""
from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile
import time
from types import SimpleNamespace


ROOT = Path(__file__).resolve().parents[2]


def run(*args, input=None):
    reply = subprocess.run(list(args), input=input, capture_output=True, timeout=30)
    if reply.returncode:
        raise RuntimeError('실험 명령 실패: ' + Path(args[0]).name)
    return reply.stdout.decode()


def docker(*args, input=None):
    return run('docker', '--host', 'unix:///var/run/docker.sock', *args, input=input)


def require(condition, message):
    if not condition:
        raise RuntimeError(message)


def main():
    require(os.environ.get('SOC_SERVER_DISPOSABLE_LAB') == '1' and Path('/fixture/busybox').is_file(),
            '전용 폐기 컨테이너에서만 실행하세요.')
    require(not Path('/var/run/docker.sock').exists(), '기존 Docker 소켓이 있으면 실행할 수 없습니다.')
    with tempfile.TemporaryDirectory(prefix='soc-removal-') as temporary, tempfile.TemporaryFile() as daemon_log:
        base = Path(temporary)
        daemon = subprocess.Popen(['dockerd', '--host=unix:///var/run/docker.sock',
            '--data-root=' + str(base / 'docker'), '--exec-root=' + str(base / 'exec'),
            '--pidfile=' + str(base / 'docker.pid'), '--storage-driver=vfs',
            '--bridge=none', '--userland-proxy=false', '--iptables=false', '--ip6tables=false', '--ip-forward=false', '--ip-masq=false'],
            stdout=daemon_log, stderr=daemon_log)
        try:
            for _ in range(60):
                if daemon.poll() is not None:
                    daemon_log.seek(0)
                    print(daemon_log.read().decode(errors='replace')[-6000:])
                    raise RuntimeError('전용 Docker 데몬이 종료됐습니다.')
                try:
                    docker('info')
                    break
                except RuntimeError:
                    time.sleep(0.5)
            else:
                raise RuntimeError('전용 Docker 데몬 준비 시간이 지났습니다.')
            require(not docker('ps', '-aq').strip(), '빈 전용 엔진이 아닙니다.')
            # A local rootfs fixture avoids remote pulls inside the private daemon.
            data = io.BytesIO()
            with tarfile.open(fileobj=data, mode='w') as archive:
                archive.add('/fixture/busybox', arcname='bin/busybox')
                archive.add('/fixture/ld-musl-x86_64.so.1', arcname='lib/ld-musl-x86_64.so.1')
                link = tarfile.TarInfo('bin/sh')
                link.type, link.linkname = tarfile.SYMTYPE, 'busybox'
                archive.addfile(link)
            docker('import', '-', 'soc-removal-fixture:local', input=data.getvalue())
            spec = importlib.util.spec_from_file_location('server_removal_live', ROOT / 'deploy/server/uninstall.py')
            remove = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(remove)
            workspace = base / 'checkout'
            (workspace / 'deploy/server').mkdir(parents=True)
            (workspace / 'deploy/server/install-ubuntu.sh').touch()
            remove.KERNEL_FILE = base / 'untouched-sysctl'
            state = workspace / 'state/server'
            state.mkdir(parents=True)
            marker = state / 'compose.env'
            marker.write_text('synthetic-settings')
            args = SimpleNamespace(workspace=workspace, component='central', purge_data=False,
                remove_images=False, remove_docker=False, select_mode=True, apply=True, yes=False)
            project = remove.PROJECT
            volume = project + '_es-data'
            docker('volume', 'create', '--label', 'com.docker.compose.project=' + project, volume)
            docker('volume', 'create', 'foreign-data')

            def start(service, *, ignore=False, foreign=False):
                command = 'trap "" TERM; while :; do /bin/busybox sleep 1; done' if ignore else \
                          'trap "exit 0" TERM; while :; do /bin/busybox sleep 1; done'
                return docker('run', '-d', '--network', 'none', '--restart', 'unless-stopped',
                    '--label', 'com.docker.compose.project=' + ('foreign-project' if foreign else project),
                    '--label', 'com.docker.compose.service=' + service,
                    '--label', 'com.docker.compose.project.config_files=' + str(workspace / 'deploy/server/compose.yaml'),
                    '--mount', 'type=volume,src=' + ('foreign-data' if foreign else volume) + ',dst=/data',
                    'soc-removal-fixture:local', '/bin/sh', '-c', command).strip()

            foreign = start('foreign', foreign=True)
            docker('exec', foreign, '/bin/sh', '-c', 'echo foreign-canary > /data/keep')
            owned = [start(service) for service in ('gateway', 'normalizer', 'portal', 'elasticsearch')]
            docker('exec', owned[0], '/bin/sh', '-c', 'echo own-canary > /data/keep')
            time.sleep(1)  # allow PID 1 to install its handlers
            try:
                with redirect_stdout(io.StringIO()):
                    remove.confirm_removal(args, lambda _prompt, answers=iter(['keep', 'yes']): next(answers))
            except remove.RemovalError:
                daemon_log.seek(0)
                print(daemon_log.read().decode(errors='replace')[-8000:])
                raise
            require(marker.read_text() == 'synthetic-settings', '보존 모드에서 설정이 바뀌었습니다.')
            require(docker('volume', 'inspect', volume).strip(), '보존 볼륨이 없습니다.')
            require(docker('exec', foreign, '/bin/sh', '-c', '/bin/busybox cat /data/keep').strip() == 'foreign-canary', '다른 프로젝트 자료가 바뀌었습니다.')
            print('PASS keep: 실제 정상 종료·비강제 제거·설정/볼륨/다른 프로젝트 보존')

            stalled = start('gateway', ignore=True)
            time.sleep(1)
            args.purge_data = True
            remove.STOP_TIMEOUT = 2
            try:
                with redirect_stdout(io.StringIO()):
                    remove.apply(args, remove.plan(args))
            except remove.RemovalError:
                pass
            else:
                raise RuntimeError('종료 시간 초과를 성공 처리했습니다.')
            require(json.loads(docker('inspect', stalled))[0]['State']['Running'], '대기 초과 때 강제 종료됐습니다.')
            require(marker.read_text() == 'synthetic-settings', '대기 초과 때 설정이 삭제됐습니다.')
            require(docker('exec', stalled, '/bin/sh', '-c', '/bin/busybox cat /data/keep').strip() == 'own-canary', '대기 초과 때 볼륨이 바뀌었습니다.')
            print('PASS timeout: 강제 종료 없음·실행 상태·설정·볼륨 원문 보존')
            # Only this deliberately stalled, disposable fixture is forcibly cleaned.
            # The product remover refused it; cleanup is not graceful-stop evidence.
            docker('rm', '-f', stalled)
            remove.STOP_TIMEOUT = 90
            start('gateway')
            time.sleep(1)
            with redirect_stdout(io.StringIO()):
                remove.confirm_removal(args, lambda _prompt, answers=iter(['purge', 'DELETE']): next(answers))
            require(not state.exists(), '완전 삭제 뒤 시험 설정이 남았습니다.')
            require(volume not in docker('volume', 'ls', '--format', '{{.Name}}').split(), '전용 볼륨이 남았습니다.')
            require(docker('exec', foreign, '/bin/sh', '-c', '/bin/busybox cat /data/keep').strip() == 'foreign-canary', '다른 프로젝트 자료가 바뀌었습니다.')
            print('PASS purge: 해당 설정·볼륨 제거·다른 프로젝트 보존')
            state.mkdir()
            foreign_file = base / 'foreign-settings'
            foreign_file.write_text('foreign-settings-canary')
            marker.symlink_to(foreign_file)
            try:
                remove.plan(args)
            except remove.RemovalError:
                pass
            else:
                raise RuntimeError('심볼릭 링크 설정을 삭제 대상으로 허용했습니다.')
            require(foreign_file.read_text() == 'foreign-settings-canary', '외부 설정이 바뀌었습니다.')
            print('PASS symlink: 실제 Linux 링크 설정 거부·외부 원문 보존')
            docker('rm', '-f', foreign)
            docker('volume', 'rm', 'foreign-data')
            require(not docker('ps', '-aq').strip(), '시험 컨테이너가 남았습니다.')
            require(not docker('volume', 'ls', '-q').strip(), '시험 볼륨이 남았습니다.')
            print('PASS cleanup: 전용 엔진 컨테이너·볼륨 0')
        finally:
            daemon.terminate()
            try:
                daemon.wait(timeout=15)
            except subprocess.TimeoutExpired:
                daemon.kill()
                daemon.wait(timeout=5)


if __name__ == '__main__':
    main()
