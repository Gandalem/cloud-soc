"""Append explicit Portal aliases without changing the existing public or ingest URL."""
from copy import deepcopy
import hashlib
import ipaddress
import json
from pathlib import Path
import subprocess
from urllib.parse import urlsplit

from cloud_soc.deployment.compose_review import ComposeReviewError
from cloud_soc.portal.origins import additional_origins

PORTAL_KEY = 'SOC_PORTAL_ORIGINS'
GATEWAY_KEY = 'SOC_PORTAL_TLS_ORIGINS'
GATEWAY_TARGET = '/etc/caddy/Caddyfile'


def profile(value):
    if (not isinstance(value, dict) or set(value) != {'version', 'aliases'}
            or type(value['version']) is not int or value['version'] != 1):
        raise ComposeReviewError('추가 주소 설정은 version과 aliases 목록만 지정하세요.')
    try:
        aliases = additional_origins(value['aliases'])
    except ValueError:
        raise ComposeReviewError('추가 주소는 경로·계정 정보가 없는 HTTPS DNS 또는 IPv4로 지정하세요.') from None
    if not 1 <= len(aliases) <= 8 or any(urlsplit(x).port not in (None, 443) for x in aliases):
        raise ComposeReviewError('추가 주소는 HTTPS 443으로 1~8개 지정하세요.')
    return {'version': 1, 'aliases': aliases}


def read_profile(path):
    path = Path(path)
    if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents)):
        raise ComposeReviewError('추가 주소 설정은 링크가 아닌 일반 파일로 지정하세요.')
    with path.open('rb') as stream:
        raw = stream.read(8193)
    if len(raw) > 8192:
        raise ComposeReviewError('추가 주소 설정 파일이 너무 큽니다.')
    try:
        value = profile(json.loads(raw))
    except (json.JSONDecodeError, UnicodeError):
        raise ComposeReviewError('추가 주소 설정 파일의 JSON 형식을 확인하세요.') from None
    return {'path': str(path.resolve()), 'sha256': hashlib.sha256(raw).hexdigest(), 'profile': value}


def merged_origins(portal, gateway, aliases):
    """Keep every old alias and give Portal and gateway the same appended allowlist."""
    try:
        old_portal = additional_origins(json.loads(portal.get(PORTAL_KEY) or '[]'))
        old_gateway = additional_origins((gateway.get(GATEWAY_KEY) or '').split())
        result = additional_origins([*old_portal, *old_gateway, *aliases])
    except (ValueError, TypeError):
        raise ComposeReviewError('기존 추가 주소 설정 형식을 확인하세요. 기존 값은 변경하지 않았습니다.') from None
    if len(result) > 8 or any(urlsplit(x).port not in (None, 443) for x in result):
        raise ComposeReviewError('기존 주소를 포함해 추가 주소는 HTTPS 443으로 최대 8개까지 지원합니다.')
    return result


def certificate_names(state, origins):
    for origin in origins:
        hostname = urlsplit(origin).hostname
        try:
            ipaddress.IPv4Address(hostname)
            check = '-verify_ip'
        except ValueError:
            check = '-verify_hostname'
        try:
            result = subprocess.run(['openssl', 'verify', '-purpose', 'sslserver',
                '-CAfile', str(state / 'tls/ca.crt'), check, hostname, str(state / 'tls/server.crt')],
                capture_output=True, timeout=10)
        except (OSError, subprocess.TimeoutExpired):
            raise ComposeReviewError('OpenSSL로 추가 주소의 인증서를 확인하지 못했습니다.') from None
        if result.returncode:
            raise ComposeReviewError('기존 서버 인증서에 추가 주소가 없거나 유효하지 않습니다. 인증서를 확인하세요.')


def template_mount(old, workspace):
    """Only the shipped previous/current Caddy template may be replaced for aliases."""
    template = Path(workspace) / 'deploy/server/Caddyfile'
    current = template.read_text(encoding='utf-8')
    previous = current.replace(' {$SOC_PORTAL_TLS_ORIGINS:}', '')
    source = Path(old.get('source', ''))
    if (old.get('type') != 'bind' or old.get('target') != GATEWAY_TARGET or not old.get('read_only')
            or not source.is_absolute() or any(p.is_symlink() for p in (source, *source.parents))
            or not source.is_file() or source.read_text(encoding='utf-8') not in (previous, current)):
        raise ComposeReviewError('사용자 지정 게이트웨이 설정이 있습니다. 기존 라우팅을 먼저 확인하세요.')
    return {**old, 'source': template.as_posix()}


def overlay(site, request, state, workspace):
    result = deepcopy(site)
    services = result.setdefault('services', {})
    portal = services.setdefault('portal', {}).setdefault('environment', {})
    gateway = services.setdefault('gateway', {}).setdefault('environment', {})
    origins = merged_origins(portal, gateway, request['profile']['aliases'])
    certificate_names(state, origins)
    portal[PORTAL_KEY] = json.dumps(origins)
    gateway[GATEWAY_KEY] = ' '.join(origins)
    mounts = services['gateway'].get('volumes', [])
    if not isinstance(mounts, list):
        raise ComposeReviewError('게이트웨이 연결 파일 형식을 확인하세요.')
    for i, mount in enumerate(mounts):
        if not isinstance(mount, dict):
            raise ComposeReviewError('게이트웨이 연결 파일은 Compose 확장 형식으로 확인해야 합니다.')
        if mount.get('target') == GATEWAY_TARGET:
            mounts[i] = template_mount(mount, workspace)
    return result


def approved_environment(objects, aliases):
    from cloud_soc.deployment.host import public_environment
    values = {name: public_environment(objects[name]) for name in ('portal', 'gateway')}
    origins = merged_origins(values['portal'], values['gateway'], aliases)
    return {'portal': {PORTAL_KEY: json.dumps(origins)}, 'gateway': {GATEWAY_KEY: ' '.join(origins)}}
