#!/usr/bin/env python3
"""Run as the VM user with Docker access. No credentials are printed."""
import base64
import getpass
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import time
from urllib.error import HTTPError
from urllib.request import Request, build_opener, HTTPSHandler, ProxyHandler

ROOT = Path(__file__).resolve().parent
STATE = ROOT / 'state'
ES = 'cloud-soc-central-elasticsearch-1'
NAME = 'security-mall-login-filebeat'
INDEX = 'soc-host-raw-mall-isolated-local-login-v1'
PIPELINE = 'security-mall-local-login-final-v1'
IMAGE = 'docker.elastic.co/beats/filebeat:9.5.2'
MALL = Path.home() / 'security-mall'


def docker(*args, data=None):
    p = subprocess.run(['docker', *args], input=data, capture_output=True)
    if p.returncode:
        raise RuntimeError('Docker 명령 실패: ' + ' '.join(args[:2]) + ' (키·원문은 출력하지 않음)')
    return p.stdout


def private(path, data):
    if path.is_symlink():
        raise RuntimeError('설정 경로가 심볼릭 링크입니다.')
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, 'wb') as out:
        out.write(data)


def main():
    os.umask(0o077)
    STATE.mkdir(mode=0o700, exist_ok=True)
    config = STATE / 'config'
    data = STATE / 'data'
    config.mkdir(mode=0o700, exist_ok=True)
    data.mkdir(mode=0o700, exist_ok=True)
    info = json.loads(docker('inspect', ES))[0]
    ports = info['NetworkSettings']['Ports']['9200/tcp']
    if not ports:
        raise RuntimeError('중앙 ES 수신 포트가 없습니다.')
    host = ports[0]['HostIp']
    if host in ('0.0.0.0', '::'):
        host = '127.0.0.1'
    url = 'https://' + host + ':' + ports[0]['HostPort']
    ca = docker('exec', ES, 'cat', '/usr/share/elasticsearch/config/certs/ca.crt')
    private(config / 'ca.crt', ca)
    password = docker('exec', ES, 'cat', '/run/secrets/elastic_password').strip()
    auth = 'Basic ' + base64.b64encode(b'elastic:' + password).decode()
    context = ssl.create_default_context(cadata=ca.decode('ascii'))
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=context))

    def authenticate():
        req = Request(url + '/_security/_authenticate', headers={'Authorization': auth})
        try:
            with opener.open(req, timeout=15) as response:
                user = json.load(response)
                if user.get('username') != 'elastic':
                    raise RuntimeError('예상한 Elasticsearch 관리자 계정이 아닙니다.')
                return True
        except HTTPError as error:
            if error.code == 401:
                return False
            raise RuntimeError('ES 인증 확인 실패 HTTP ' + str(error.code)) from None

    if not authenticate():
        print('컨테이너 비밀번호 파일로 ES 인증 실패(401). 저장 데이터의 비밀번호와 다를 수 있습니다.')
        if not sys.stdin.isatty():
            raise RuntimeError('일반 터미널에서 실행하여 현재 Elasticsearch elastic 비밀번호를 입력하세요.')
        password = getpass.getpass('현재 Elasticsearch elastic 비밀번호(Portal 비밀번호 아님, 표시·저장 안 함): ').encode()
        if not password:
            raise RuntimeError('비밀번호 입력 취소. 중앙 설정 변경 없이 종료합니다.')
        auth = 'Basic ' + base64.b64encode(b'elastic:' + password).decode()
        if not authenticate():
            raise RuntimeError('입력한 elastic 비밀번호도 인증 실패(401). 중앙 설정 변경 없이 종료합니다.')

    def api(method, path, value=None, missing=False):
        body = json.dumps(value).encode() if value is not None else None
        req = Request(url + path, data=body, method=method,
                      headers={'Authorization': auth, 'Content-Type': 'application/json'})
        try:
            with opener.open(req, timeout=15) as response:
                return json.load(response)
        except HTTPError as error:
            if missing and error.code == 404:
                return None
            raise RuntimeError('ES 요청 실패 HTTP ' + str(error.code) + ': ' + path.split('?')[0]) from None

    if '--verify' in sys.argv:
        result = api('POST', '/' + INDEX + '/_search', {
            'size': 5, 'sort': [{'event.ingested': 'desc'}],
            '_source': ['@timestamp', 'event.ingested', 'security_mall.audit.event_outcome'],
            'aggs': {'outcomes': {'terms': {'field': 'security_mall.audit.event_outcome'}}}})
        print(json.dumps({'index': INDEX, 'stored': result['hits']['total'],
                          'outcomes': result['aggregations']['outcomes']['buckets'],
                          'latest': [r['_source'] for r in result['hits']['hits']]}, ensure_ascii=False, indent=2))
        return

    audit = MALL / 'audit' / 'security-audit.jsonl'
    if not audit.is_file() or audit.is_symlink():
        raise RuntimeError('먼저 수정된 쇼핑몰을 재시작하고 로그인 1회 후 다시 실행하세요.')
    pipeline = json.loads((ROOT / 'pipeline.json').read_text())
    existing = api('GET', '/_ingest/pipeline/' + PIPELINE, missing=True)
    if existing is None:
        api('PUT', '/_ingest/pipeline/' + PIPELINE, pipeline)
    elif existing[PIPELINE].get('processors') != pipeline['processors']:
        raise RuntimeError('동명 pipeline 설정 불일치. 기존 설정을 덮어쓰지 않습니다.')
    template = json.loads((ROOT / 'index-template.json').read_text())['template']
    template['settings']['index.final_pipeline'] = PIPELINE
    current = api('GET', '/' + INDEX + '/_settings', missing=True)
    if current is None:
        api('PUT', '/' + INDEX, template)
    elif current[INDEX]['settings']['index'].get('final_pipeline') != PIPELINE:
        raise RuntimeError('기존 인덱스 final_pipeline 불일치.')

    credential = STATE / 'writer.json'
    if credential.exists():
        key = json.loads(credential.read_text())
        if key['expiration'] <= time.time() * 1000 + 60000:
            raise RuntimeError('실습 키 만료 임박/만료. 자동 재발급하지 않습니다.')
    else:
        key = api('POST', '/_security/api_key', {
            'name': 'security-mall-local-login-filebeat', 'expiration': '30d',
            'role_descriptors': {'mall_login': {'cluster': ['monitor'], 'indices': [
                {'names': [INDEX], 'privileges': ['create_doc']}]}}})
        private(credential, json.dumps(key).encode())
    text = (ROOT / 'filebeat.example.yml').read_text()
    values = {'MALL_TEST_DATA_PATH': '/data', 'MALL_TEST_LOG_PATH': '/data/logs',
              'MALL_TEST_AUDIT_PATH': '/audit/security-audit.jsonl',
              'MALL_TEST_ES_URL': url, 'MALL_TEST_ES_CA': '/config/ca.crt', 'MALL_TEST_RAW_INDEX': INDEX}
    import re
    for name, value in values.items():
        text = re.sub(r'\$\{' + name + r':\?[^}]*\}', lambda _: value, text)
    # This sensitive value stays a keystore reference, never a YAML literal.
    text = re.sub(r'\$\{MALL_TEST_ES_API_KEY:\?[^}]*\}', '${MALL_TEST_ES_API_KEY}', text)
    private(config / 'filebeat.yml', text.encode())
    private(config / 'security-mall-audit.js', (ROOT / 'security-mall-audit.js').read_bytes())
    mounts = ['--user', str(os.getuid()) + ':' + str(os.getgid()), '--network', 'host',
              '--cap-drop', 'ALL', '--security-opt', 'no-new-privileges:true',
              '--read-only', '--tmpfs', '/tmp',
              '-v', str(config) + ':/config:ro', '-v', str(data) + ':/data',
              '-v', str(audit) + ':/audit/security-audit.jsonl:ro']
    flags = ['--path.config=/config', '--path.data=/data', '--path.logs=/data/logs', '-c', '/config/filebeat.yml']
    docker('pull', IMAGE)
    if not (data / 'filebeat.keystore').exists():
        docker('run', '--rm', *mounts, IMAGE, 'keystore', 'create', *flags)
    docker('run', '--rm', '-i', *mounts, IMAGE, 'keystore', 'add', 'MALL_TEST_ES_API_KEY',
           '--stdin', '--force', *flags, data=(key['id'] + ':' + key['api_key'] + '\n').encode())
    docker('run', '--rm', *mounts, IMAGE, 'test', 'config', *flags)
    docker('run', '--rm', *mounts, IMAGE, 'test', 'output', *flags)
    prior = subprocess.run(['docker', 'inspect', NAME], capture_output=True)
    if prior.returncode == 0:
        old = json.loads(prior.stdout)[0]
        mounted = {m['Destination']: m['Source'] for m in old['Mounts']}
        if mounted.get('/data') != str(data):
            raise RuntimeError('동명 다른 수집기 존재. 교체하지 않습니다.')
        docker('restart', NAME)
    else:
        docker('run', '-d', '--name', NAME, '--restart', 'unless-stopped', *mounts, IMAGE, '-e', *flags)
    print('Filebeat 시작. 전용 원본 인덱스: ' + INDEX)
    print('실습 키 만료: ' + time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(key['expiration'] / 1000)))
    print('로그인 후 python3 "' + str(Path(__file__).resolve()) + '" --verify 로 실제 수신을 확인하세요.')


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        if isinstance(error, RuntimeError):
            print(str(error), file=sys.stderr)
        else:
            print('연결 준비 실패: ' + type(error).__name__ + ' (자격 증명·서버 응답 생략)', file=sys.stderr)
        sys.exit(1)
