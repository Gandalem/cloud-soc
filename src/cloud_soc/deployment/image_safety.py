"""Local image and storage checks, before activation or public downloads."""
import shutil
import re

from cloud_soc.deployment.contract import policy

INFRASTRUCTURE = ('elasticsearch', 'kibana', 'gateway')
RECOVERY_REPOSITORY = 'cloud-soc-recovery'


class DeploymentSafetyError(ValueError):
    """Fixed operational messages safe to show without Docker output."""


def check_disk_budget(engine, workspace, purpose='build'):
    limits = policy(workspace)['resources']
    required = (limits['fresh_free_bytes'] if purpose == 'download' else
                limits['headroom_bytes'] if purpose == 'reserve' else
                limits['upgrade_free_bytes'] + limits['headroom_bytes'])
    info = engine.json(['info', '--format', '{{json .}}'])
    root = info.get('DockerRootDir')
    if info.get('OSType') != 'linux' or not isinstance(root, str) or not root.startswith('/'):
        raise DeploymentSafetyError('Docker 저장소의 여유 공간을 확인할 수 없습니다. Linux Docker 호스트에서 실행하세요')
    try:
        free = shutil.disk_usage(root).free
    except OSError:
        raise DeploymentSafetyError('Docker 저장소의 여유 공간을 확인할 수 없습니다') from None
    if free < required:
        raise DeploymentSafetyError('Docker 저장소 여유 공간이 부족합니다. 빌드·다운로드 전에 공간을 확보하세요 '
                                    f'(필요 {required // 1024 // 1024} MiB)')
    return {'free_bytes': free, 'required_bytes': required}


def local_image(engine, reference):
    from cloud_soc.deployment.host import DockerCommandError
    try:
        result = engine.json(['image', 'inspect', reference])
    except DockerCommandError as error:
        if error.image_missing:
            return None
        raise
    if not isinstance(result, list) or not result or not isinstance(result[0].get('Id'), str):
        raise DeploymentSafetyError('로컬 이미지의 식별자를 확인할 수 없습니다')
    return result[0]['Id']


def retain_images(engine):
    """Keep image records reachable before a build reassigns their last tag."""
    from cloud_soc.deployment.host import containers
    for identity in {obj['Image'] for obj in containers(engine, 'cloud-soc-central').values()}:
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', identity):
            raise DeploymentSafetyError('실행 이미지의 식별자를 확인할 수 없습니다. 빌드를 중단했습니다')
        reference = RECOVERY_REPOSITORY + ':' + identity.split(':')[1]
        existing = local_image(engine, reference)
        if existing == identity:
            continue
        if existing is not None or local_image(engine, identity) != identity:
            raise DeploymentSafetyError('이전 실행 이미지를 보존할 수 없습니다. 빌드를 중단했습니다')
        engine.run(['image', 'tag', identity, reference])


def infrastructure_images(engine, rendered, *, allow_missing=False):
    result = {}
    for service in INFRASTRUCTURE:
        reference = rendered['services'][service]['image']
        identity = local_image(engine, reference)
        if identity is None and not allow_missing:
            raise DeploymentSafetyError('배포에 필요한 기반 이미지가 없습니다. manage.py prepare-images로 이미지를 준비한 뒤 새 계획을 만드세요')
        result[service] = {'reference': reference, 'image_id': identity}
    return result


def recovery_mode(engine, runtime, active, objects, rendered):
    if not objects:
        return 'none'
    files = [active[i + 1] for i, word in enumerate(active[:-1]) if word == '-f']
    if str(runtime / 'site.json') in files:
        return 'site'
    for name, obj in objects.items():
        reference = rendered.get('services', {}).get(name, {}).get('image')
        if (not reference or (reference != obj['Image'] and '@sha256:' not in reference)
                or local_image(engine, reference) != obj['Image']):
            raise DeploymentSafetyError('이전 실행의 복구 이미지를 고정할 수 없습니다. 기존 Compose 구성을 검토·인수한 뒤 새 계획을 만드세요')
    return 'immutable'
