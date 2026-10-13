"""Compile trusted site settings into independent Filebeat inputs; no I/O."""
from datetime import datetime, timezone
from pathlib import PurePosixPath, PureWindowsPath
import re

SCHEMA = 'web-access-agent-v1'
SERVERS = ('apache', 'nginx', 'docker')


def validate_sites(sites, platform):
    if not isinstance(sites, list) or len(sites) > 8:
        raise ValueError('웹 사이트는 최대 8개입니다.')
    result, paths, ids = [], set(), set()
    for site in sites:
        if not isinstance(site, dict) or set(site) != {'id', 'name', 'server_type', 'log_path', 'start_at'}:
            raise ValueError('사이트 ID·이름·서버 종류·로그 경로·시작 시각을 입력하세요.')
        if not isinstance(site['id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}', site['id']):
            raise ValueError('사이트 ID는 영문·숫자·밑줄·하이픈 1~64자입니다.')
        if not isinstance(site['name'], str) or not 1 <= len(site['name']) <= 64 or site['name'] != site['name'].strip() or re.search(r'[\x00-\x1f\x7f<>]', site['name']):
            raise ValueError('사이트 이름은 제어 문자 없는 1~64자입니다.')
        if site['server_type'] not in SERVERS:
            raise ValueError('Apache/Nginx 표준 access 로그 또는 Docker JSON access 로그를 선택하세요.')
        value = site['log_path']
        if not isinstance(value, str) or len(value) > 500 or re.search(r'[\x00-\x1f\x7f$*?\[\]{}]', value):
            raise ValueError('웹 로그는 변수·와일드카드 없는 절대 파일 경로여야 합니다.')
        path_type = PureWindowsPath if platform == 'windows' else PurePosixPath
        path = path_type(value)
        if not path.is_absolute() or '..' in path.parts or value != value.strip():
            raise ValueError('절대 로컬 파일 경로만 지원합니다.')
        canonical = str(path)
        if platform == 'windows':
            if not re.match(r'^[A-Za-z]:[\\/]', value) or len(path.parts) < 4:
                raise ValueError('드라이브 아래 명시적 로그 파일을 선택하세요.')
            suffix = '\\'.join(path.parts[1:]).lower()
            if any(suffix == p or suffix.startswith(p+'\\') for p in ('users', 'windows\\system32', 'program files\\cloud-soc-agent', 'program files\\cloud-soc-network')):
                raise ValueError('개인·보호·수집기 경로는 웹 로그로 사용할 수 없습니다.')
            key = canonical.lower()
        else:
            if not re.fullmatch(r'/[-a-zA-Z0-9_./]+', value) or len(path.parts) < 4 or any(canonical == p or canonical.startswith(p+'/') for p in ('/etc','/proc','/sys','/dev','/run','/home','/root','/opt/cloud-soc-agent','/opt/cloud-soc-network')):
                raise ValueError('웹 로그는 보호 경로 외의 명시적 파일이어야 합니다.')
            key = canonical
        # The complete directory is reserved for protected web collection. This
        # excludes rotated siblings from generic discovery, even while disabled.
        if path.suffix.lower() in ('.key','.pem','.sqlite','.db','.gz','.zip'):
            raise ValueError('키·DB·압축 파일은 웹 로그가 아닙니다.')
        try:
            start = datetime.fromisoformat(site['start_at'].replace('Z', '+00:00'))
            if start.tzinfo is None or not 2000 <= start.year <= 2100:
                raise ValueError()
        except (AttributeError, TypeError, ValueError):
            raise ValueError('시간대가 포함된 수집 시작 시각을 선택하세요.') from None
        if key in paths or site['id'].lower() in ids:
            raise ValueError('같은 웹 로그 경로나 사이트 ID를 중복 설정할 수 없습니다.')
        paths.add(key); ids.add(site['id'].lower())
        result.append({**site, 'log_path': canonical, 'start_at': start.astimezone(timezone.utc).isoformat().replace('+00:00','Z')})
    return result


def profile(spec):
    inputs = []
    exclusions = [r'C:\inetpub\logs'] if spec['os']=='windows' else ['/var/log/apache2','/var/log/httpd','/var/log/nginx']
    for site in spec.get('sites', []):
        path_type = PureWindowsPath if spec['os'] == 'windows' else PurePosixPath
        parent = str(path_type(site['log_path']).parent)
        exclusions.append(parent)
        inputs.append({'type':'filestream', 'id':'cloud-soc-site-'+site['id'], 'enabled':True,
            'paths':[site['log_path']], 'prospector.scanner.symlinks':False,
            'file_identity.fingerprint':{'growing':True},
            'prospector.scanner.fingerprint.length':64,
            'fields_under_root':True, 'fields':{'labels':{'log_source':'generic_web_access'}},
            'processors':[
                {'script':{'lang':'javascript','file':'${path.config}/site-privacy.js','params':site,'timeout':'50ms','tag_on_exception':'_site_privacy_error'}},
                {'drop_event':{'when':{'contains':{'tags':'_site_privacy_error'}}}},
                {'timestamp':{'field':'web.occurred_at','layouts':['2006-01-02T15:04:05.999Z07:00']}},
                {'drop_fields':{'fields':['web.occurred_at'],'ignore_missing':True}}]})
    return {'schema':1, 'system':spec.get('system', True), 'network':spec['network'],
            'web_inputs':inputs, 'web_exclusions':sorted(set(exclusions)), 'platform':spec['os']}
