"""Optional aliases must not replace the school's public URL, receiver or recovery path."""
from contextlib import nullcontext
from copy import deepcopy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloud_soc.deployment import access, compose_review, host
from cloud_soc.portal.origins import https_origin
from test_compose_review import fixture, manage_module

ROOT = Path(__file__).resolve().parents[1]
DOCKER = os.environ.get('SOC_TEST_DOCKER')


def request():
    return {'profile': {'version': 1, 'aliases': ['https://extra.example.test']}}


@pytest.mark.parametrize('value', ['http://soc.test', 'https://user:secret@soc.test', 'https://*.test',
    'https://soc.test/path', 'https://soc.test?x=y', 'https://soc.test\nadmin off',
    'https://0.0.0.0', 'https://224.0.0.1', 'https://soc.test:65536', 'https://soc..test'])
def test_invalid_origin_is_not_echoed(value):
    with pytest.raises(ValueError) as error:
        https_origin(value)
    assert value not in str(error.value)


@pytest.mark.parametrize('change', [
    {'public_url': 'https://different.test'}, {'authtoken': 'SYNTHETIC_SECRET'}, {'mode': 'ngrok'},
    {'aliases': []}, {'aliases': ['https://extra.test:8443']}, {'version': True},
    {'aliases': [f'https://alias{i}.test' for i in range(9)]},
])
def test_alias_request_cannot_change_public_mode_or_accept_secrets(change):
    value = {**request()['profile'], **change}
    with pytest.raises(compose_review.ComposeReviewError) as error:
        access.profile(value)
    assert 'SYNTHETIC_SECRET' not in str(error.value)


def test_optional_overlay_keeps_public_ngrok_receiver_and_existing_aliases(tmp_path, monkeypatch):
    cert = Mock();monkeypatch.setattr(access, 'certificate_names', cert)
    site = {'services': {'portal': {'environment': {'SOC_PUBLIC_URL': 'https://school.ngrok-free.app',
        'SOC_AGENT_ENDPOINT': 'https://192.0.2.5:9200', 'SOC_PORTAL_ORIGINS': '["https://old.example.test"]'}},
        'gateway': {'environment': {'SOC_PUBLIC_HOST': '192.0.2.5', 'SOC_ADMIN_ALLOWED_CIDRS': '127.0.0.1/32'},
                    'ports': [{'target': 443, 'published': '443', 'host_ip': '127.0.0.1'}]}}}
    before = deepcopy(site)
    result = access.overlay(site, request(), tmp_path, ROOT)
    assert site == before
    portal = result['services']['portal']['environment']
    assert portal['SOC_PUBLIC_URL'] == 'https://school.ngrok-free.app'
    assert portal['SOC_AGENT_ENDPOINT'] == 'https://192.0.2.5:9200'
    assert json.loads(portal['SOC_PORTAL_ORIGINS']) == ['https://old.example.test', 'https://extra.example.test']
    gateway = result['services']['gateway']
    assert gateway['ports'] == before['services']['gateway']['ports']
    assert gateway['environment']['SOC_PUBLIC_HOST'] == '192.0.2.5'
    assert gateway['environment']['SOC_ADMIN_ALLOWED_CIDRS'] == '127.0.0.1/32'
    assert gateway['environment']['SOC_PORTAL_TLS_ORIGINS'] == 'https://old.example.test https://extra.example.test'
    assert cert.call_args.args[1] == ['https://old.example.test', 'https://extra.example.test']


def test_profile_change_is_visible_to_plan_fingerprint(tmp_path):
    file = tmp_path / 'aliases.json'
    file.write_text(json.dumps(request()['profile']), encoding='utf-8')
    original = access.read_profile(file)
    file.write_text(file.read_text(encoding='utf-8') + '\n', encoding='utf-8')
    assert access.read_profile(file)['sha256'] != original['sha256']


def test_review_accepts_only_requested_alias_changes_and_known_gateway_template(tmp_path, monkeypatch):
    state, _, objects, original, _ = fixture(tmp_path)
    template = tmp_path / 'Caddyfile'
    current = (ROOT / 'deploy/server/Caddyfile').read_text(encoding='utf-8')
    template.write_text(current.replace(' {$SOC_PORTAL_TLS_ORIGINS:}', ''), encoding='utf-8')
    original['services']['gateway']['volumes'] = [{'type': 'bind', 'target': '/etc/caddy/Caddyfile',
                                                 'source': template.as_posix(), 'read_only': True}]
    monkeypatch.setattr(access, 'certificate_names', lambda *_: None)
    desired = access.overlay(original, request(), state, ROOT)
    compose_review.preserved_site(original, desired, objects, alias_request=request(), workspace=ROOT)
    assert template.read_text(encoding='utf-8') == current.replace(' {$SOC_PORTAL_TLS_ORIGINS:}', '')
    for fault in ('public', 'bind', 'receiver', 'caddy'):
        changed = deepcopy(desired)
        compared_objects = deepcopy(objects)
        if fault == 'public':
            changed['services']['portal']['environment']['SOC_PUBLIC_URL'] = 'https://different.test'
        if fault == 'bind':
            changed['services']['gateway']['ports'] = [{'target': 443, 'published': '443', 'host_ip': '0.0.0.0'}]
        if fault == 'receiver':
            compared_objects['portal']['Config']['Env'].append('SOC_AGENT_ENDPOINT=https://receiver.test:9200')
            changed['services']['portal']['environment']['SOC_AGENT_ENDPOINT'] = 'https://different.test:9200'
        if fault == 'caddy':
            changed['services']['gateway']['volumes'][0]['source'] = '/unreviewed/Caddyfile'
        with pytest.raises(compose_review.ComposeReviewError):
            compose_review.preserved_site(original, changed, compared_objects, alias_request=request(), workspace=ROOT)


def test_custom_gateway_is_refused_before_changing_files(tmp_path, monkeypatch):
    template = tmp_path / 'Caddyfile';template.write_text('custom policy', encoding='utf-8')
    site = {'services': {'gateway': {'volumes': [{'type': 'bind', 'target': '/etc/caddy/Caddyfile',
                                                'source': str(template), 'read_only': True}]}}}
    monkeypatch.setattr(access, 'certificate_names', lambda *_: None)
    with pytest.raises(compose_review.ComposeReviewError, match='사용자 지정'):
        access.overlay(site, request(), tmp_path, ROOT)
    assert template.read_text(encoding='utf-8') == 'custom policy'


def test_certificate_failure_does_not_echo_output_or_mutate_site(tmp_path, monkeypatch):
    monkeypatch.setattr(access.subprocess, 'run', Mock(return_value=SimpleNamespace(returncode=1, stderr=b'SECRET_CANARY')))
    site = {'services': {'portal': {'environment': {'SOC_PUBLIC_URL': 'https://existing.test'}}}}
    before = deepcopy(site)
    with pytest.raises(compose_review.ComposeReviewError) as error:
        access.overlay(site, request(), tmp_path, ROOT)
    assert 'SECRET_CANARY' not in str(error.value) and site == before


@pytest.mark.parametrize('changed', ['alias_request', 'compose_environment'])
def test_modified_plan_stops_before_service_or_database_mutation(tmp_path, monkeypatch, changed):
    plan = {'resources': {'ok': True}, 'workspace': str(ROOT), 'state': str(tmp_path), 'image': 'fixture:test',
            'project': 'cloud-soc-central', 'fingerprint': 'same', 'alias_request': {'path': 'aliases.json'},
            'compose_review': 'review.json',
            **{k: {} for k in ('policy', 'site', 'observed', 'protected_sha256', 'previous_compose', 'source', 'image_id', 'adoption')}}
    current = deepcopy(plan);current[changed] = {'modified': True}
    snapshot = Mock(return_value=current)
    monkeypatch.setattr(host, 'snapshot', snapshot);monkeypatch.setattr(host, 'lock', lambda _: nullcontext())
    engine = Mock()
    with pytest.raises(compose_review.ComposeReviewError, match='계획 이후'):
        host.apply(engine, plan)
    assert not engine.mock_calls
    assert snapshot.call_args.kwargs == {'compose_review': 'review.json', 'access_path': 'aliases.json'}


def test_cli_plan_forwards_both_review_and_alias_request_without_apply(tmp_path, monkeypatch):
    state, _, _, _, _ = fixture(tmp_path)
    args = ['plan', '--state', str(state), '--compose-review', 'review.json', '--access', 'aliases.json']
    module = manage_module(monkeypatch, args)
    snapshot = Mock(return_value={'resources': {'ok': True}})
    monkeypatch.setattr(module, 'snapshot', snapshot);monkeypatch.setattr(module, 'summary', lambda _: {})
    engine = Mock();monkeypatch.setattr(module, 'Docker', lambda: engine)
    assert module.main() == 0 and not engine.mock_calls
    assert snapshot.call_args.kwargs == {'compose_review': Path('review.json'), 'access_path': Path('aliases.json')}


def test_no_alias_request_keeps_existing_school_configuration(tmp_path):
    _, _, objects, original, _ = fixture(tmp_path)
    original['services']['gateway']['environment'] = {'SOC_PORTAL_LAN_ORIGIN': 'https://192.0.2.5'}
    objects['gateway']['Config']['Env'] = ['SOC_PORTAL_LAN_ORIGIN=https://192.0.2.5']
    p = {'site': host.site_overlay(original, objects), 'image': 'candidate:verified'}
    result = host.configure_site(p, tmp_path)
    assert result['services']['portal']['environment']['SOC_PUBLIC_URL'] == 'https://portal.example'
    assert result['services']['gateway']['environment']['SOC_PORTAL_LAN_ORIGIN'] == 'https://192.0.2.5'
    assert not result['services']['portal']['environment'].get('SOC_PORTAL_ORIGINS')


def test_following_deployment_preserves_previously_added_alias_without_request(tmp_path):
    _, _, objects, original, _ = fixture(tmp_path)
    objects['portal']['Config']['Env'].append('SOC_PORTAL_ORIGINS=["https://extra.example.test"]')
    objects['gateway']['Config']['Env'].append('SOC_PORTAL_TLS_ORIGINS=https://extra.example.test')
    result = host.configure_site({'site': host.site_overlay(original, objects), 'image': 'next:verified'}, tmp_path)
    assert json.loads(result['services']['portal']['environment']['SOC_PORTAL_ORIGINS']) == ['https://extra.example.test']
    assert result['services']['gateway']['environment']['SOC_PORTAL_TLS_ORIGINS'] == 'https://extra.example.test'


def test_fresh_plan_binds_alias_file_and_rejects_later_bytes_by_fingerprint(tmp_path, monkeypatch):
    env = tmp_path / 'compose.env';env.write_text('SOC_PUBLIC_HOST=127.0.0.1\n', encoding='utf-8')
    file = tmp_path / 'aliases.json';file.write_text(json.dumps(request()['profile']), encoding='utf-8')
    monkeypatch.setattr(host, 'containers', lambda *_: {})
    monkeypatch.setattr(host, 'worker_inventory', lambda *_: {})
    monkeypatch.setattr(host, 'build_contract', lambda *_, **__: ({}, {}))
    monkeypatch.setattr(host, 'hardware', lambda *_: {})
    monkeypatch.setattr(host, 'resource_check', lambda *_, **__: {'ok': True})
    monkeypatch.setattr(host, 'protected_hashes', lambda *_: {})
    monkeypatch.setattr(host, 'source_files', lambda *_: {})
    monkeypatch.setattr(host, 'validate_rendered', lambda *_: {})
    monkeypatch.setattr(access, 'certificate_names', lambda *_: None)
    class Engine:
        def __init__(self):
            self.overlay = None
        def run(self, args, **kwargs):
            assert args[0] == 'run' and '--network' in args and 'none' in args
            return 'verified'
        def json(self, args, **kwargs):
            if args[:2] == ['image', 'inspect']:
                return [{'Id': 'sha256:candidate'}]
            assert 'config' in args
            self.overlay = json.loads(kwargs['input'])
            return {}
    engine = Engine()
    before = host.snapshot(engine, ROOT, tmp_path, 'candidate:verified', access_path=file)
    assert before['fresh'] and before['alias_request']['path'] == str(file)
    assert str(file) in before['protected_sha256']
    assert engine.overlay['services']['gateway']['environment']['SOC_PORTAL_TLS_ORIGINS'] == 'https://extra.example.test'
    file.write_text(file.read_text(encoding='utf-8') + '\n', encoding='utf-8')
    after = host.snapshot(engine, ROOT, tmp_path, 'candidate:verified', access_path=file)
    assert after['fingerprint'] != before['fingerprint']


def test_alias_writer_never_replaces_an_existing_request(tmp_path, monkeypatch):
    spec = importlib.util.spec_from_file_location('alias_writer_test', ROOT / 'deploy/server/configure-access.py')
    module = importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    file = tmp_path / 'aliases.json';file.write_text('preserved', encoding='utf-8')
    monkeypatch.setattr('sys.argv', ['configure-access', '--alias', 'https://extra.test', '--output', str(file)])
    with pytest.raises(SystemExit) as error:
        module.main()
    assert error.value.code == 1 and file.read_text(encoding='utf-8') == 'preserved'


@pytest.mark.skipif(not shutil.which('openssl'), reason='OpenSSL is needed for real local certificate checks')
def test_real_ca_and_name_validation_preserves_certificates(tmp_path):
    tls = tmp_path / 'tls';tls.mkdir()
    cert = tls / 'server.crt'
    subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
        '-subj', '/CN=extra.example.test', '-addext', 'subjectAltName=DNS:extra.example.test,IP:127.0.0.1',
        '-keyout', str(tls / 'server.key'), '-out', str(cert)], check=True, capture_output=True, timeout=30)
    shutil.copyfile(cert, tls / 'ca.crt')
    before = {p: p.read_bytes() for p in tls.iterdir()}
    access.certificate_names(tmp_path, ['https://extra.example.test', 'https://127.0.0.1'])
    with pytest.raises(compose_review.ComposeReviewError, match='인증서'):
        access.certificate_names(tmp_path, ['https://other.example.test'])
    assert all(p.read_bytes() == raw for p, raw in before.items())


@pytest.mark.skipif(not DOCKER, reason='Set SOC_TEST_DOCKER for real client-only Compose rendering')
def test_real_compose_preserves_public_receiver_and_ports_with_aliases(tmp_path, monkeypatch):
    env = tmp_path / 'compose.env'
    env.write_text('SOC_PUBLIC_HOST=127.0.0.1\nSOC_STATE_DIR=' + tmp_path.as_posix() +
                   '\nSOC_AGENT_ENDPOINT=https://receiver.test:9200\n', encoding='utf-8')
    site = {'services': {'portal': {'environment': {'SOC_PUBLIC_URL': 'https://school.ngrok-free.app'}}}}
    monkeypatch.setattr(access, 'certificate_names', lambda *_: None)
    overlay = access.overlay(site, request(), tmp_path, ROOT)
    file = tmp_path / 'overlay.json';file.write_text(json.dumps(overlay), encoding='utf-8')
    clean = {k: v for k, v in os.environ.items() if not k.startswith(('DOCKER_', 'COMPOSE_', 'SOC_'))}
    output = subprocess.run([DOCKER, 'compose', '--env-file', str(env), '-f', str(ROOT / 'deploy/server/compose.yaml'),
        '-f', str(file), 'config', '--format', 'json'], capture_output=True, check=True, text=True, timeout=30, env=clean)
    services = json.loads(output.stdout)['services']
    assert services['portal']['environment']['SOC_PUBLIC_URL'] == 'https://school.ngrok-free.app'
    assert services['portal']['environment']['SOC_AGENT_ENDPOINT'] == 'https://receiver.test:9200'
    assert services['gateway']['environment']['SOC_PUBLIC_HOST'] == '127.0.0.1'
    assert services['gateway']['environment']['SOC_PORTAL_TLS_ORIGINS'] == 'https://extra.example.test'
    assert not services['portal'].get('ports')
    assert {p['target'] for p in services['gateway']['ports']} == {443, 5601}
