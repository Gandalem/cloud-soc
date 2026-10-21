"""Host compatibility for the reviewed install commands; no host modifications."""
import re


class DependencyError(ValueError):
    pass


def version(value):
    match = re.fullmatch(r'v?(\d+)\.(\d+)\.(\d+)(?:[-+][A-Za-z0-9._-]+)?', value.strip())
    if not match:
        raise DependencyError('버전을 확인할 수 없습니다. 공식 Docker/Compose 버전을 확인하세요.')
    return tuple(int(part) for part in match.groups())


def check(engine):
    data = engine.json(['version', '--format', '{{json .}}'])
    for label, actual in (('Docker CLI', data['Client']['Version']), ('Docker Engine', data['Server']['Version'])):
        if version(actual) < (24, 0, 0):
            raise DependencyError(label + '가 낮아 업데이트가 필요합니다. 최소 24.0.0 이상으로 업데이트한 뒤 다시 실행하세요.')
    compose = engine.run(['compose', 'version', '--short']).strip()
    if version(compose) < (2, 24, 0):
        raise DependencyError('Docker Compose가 낮아 업데이트가 필요합니다. 최소 2.24.0 이상으로 업데이트한 뒤 다시 실행하세요.')
    if '--policy' not in engine.run(['compose', 'pull', '--help']) or '--progress' not in engine.run(['build', '--help']):
        raise DependencyError('Docker/Compose에 필요한 빌드·이미지 다운로드 기능이 없습니다. 공식 패키지를 업데이트하세요.')
    print('[설치] 기존 Docker·Compose가 호환됩니다. 재설치나 업데이트 없이 사용합니다.', flush=True)
