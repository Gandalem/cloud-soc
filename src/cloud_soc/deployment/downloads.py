"""Serial, bounded preparation of the public images required for installation."""
import time
from pathlib import Path

from cloud_soc.deployment.host import DockerCommandError
from cloud_soc.deployment.image_safety import check_disk_budget, retain_images


def public_operation(engine, args, *, timeout, idle_timeout=120, env=None, before_attempt=None):
    for attempt in range(3):
        if before_attempt:
            before_attempt()
        try:
            return engine.run(args, timeout=timeout, idle_timeout=idle_timeout, stream=True,
                              **({'env': env} if env is not None else {}))
        except DockerCommandError as error:
            if not error.retryable or attempt == 2:
                raise
            pause = 5 * (2 ** attempt)
            print(f'[설치] 다운로드 연결이 지연되거나 끊겼습니다. {pause}초 후 재시도합니다 ({attempt + 2}/3). '
                  '받은 이미지와 기존 설정은 보존합니다.', flush=True)
            time.sleep(pause)


def ensure_image(engine, image, label, *, before_attempt=None):
    present = engine.run(['image', 'ls', '--filter', 'reference=' + image, '--format', '{{.ID}}']).strip()
    if present:
        print('[설치] ' + label + ': 지정 버전 이미지가 있어 재사용합니다.', flush=True)
        return
    print('[설치] ' + label + ': 지정 버전 이미지를 다운로드합니다. '
          '다운로드 표시가 120초 동안 바뀌지 않으면 연결을 재시도합니다 (최대 3회).', flush=True)
    public_operation(engine, ['pull', image], timeout=1800, before_attempt=before_attempt)


def build_runtime_image(engine, workspace, image):
    """Build an installation or upgrade candidate without activating services."""
    workspace = Path(workspace).resolve(strict=True)
    dockerfile = workspace / 'deploy/server/Dockerfile'
    # Use this release's base, never a second copy of the Python version.
    first = dockerfile.read_text().splitlines()[0].split()
    if len(first) != 2 or first[0] != 'FROM' or not first[1].startswith('python:'):
        raise ValueError('공식 Python 기반 Dockerfile의 첫 FROM 행을 확인하세요')
    check_disk_budget(engine, workspace)
    retain_images(engine)
    ensure_image(engine, first[1], 'Python 기반 이미지',
                 before_attempt=lambda: check_disk_budget(engine, workspace))
    public_operation(engine, ['build', '--progress=plain', '--pull=false', '-f', str(dockerfile), '-t', image,
                             str(workspace)], timeout=900, idle_timeout=180,
                     before_attempt=lambda: check_disk_budget(engine, workspace))

