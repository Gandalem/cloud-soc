"""Independent security and replay contracts for the multicloud extension."""
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import importlib.util
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

from elasticsearch import NotFoundError
from flask import Flask, g
import pytest

from cloud_soc.multicloud.normalize import normalize
from cloud_soc.multicloud.storage import State, install, inspect_template, template_body
from cloud_soc.multicloud.collectors import Naver
from cloud_soc.portal.multicloud import blueprint
from cloud_soc.portal.status_setup import configure_reader

ROOT = Path(__file__).resolve().parents[1]
SCOPE = {'id': 'audit', 'organization': 'org-a', 'account': '1234567'}


def naver_event():
    return {'historyId': 'history-1', 'nrn': 'nrn:PUB:Account::1234567:Customer/static',
        'eventTime': 1793491200000, 'actionDisplayName': 'Login',
        'actionResultType': 'SUCCESS', 'productName': 'Account', 'sourceIp': '192.0.2.5',
        'productData': {'password': 'PRIVATE_PAYLOAD_CANARY'}}


def test_replay_keeps_identity_and_event_day_without_indexing_sensitive_payload():
    raw = naver_event()
    first = normalize('naver', raw, SCOPE)
    second = normalize('naver', deepcopy(raw), SCOPE)
    assert first[:2] == second[:2]
    assert first[0] == 'soc-multicloud-2026.11.01'
    assert first[2]['organization']['id'] == 'org-a'
    assert first[2]['source']['ip'] == '192.0.2.5'
    assert 'PRIVATE_PAYLOAD_CANARY' not in json.dumps(first[2])
    assert normalize('naver', raw, {**SCOPE, 'organization': 'org-b'})[1] != first[1]


@pytest.mark.parametrize('nrn', ['nrn:PUB:Account::9999999:Customer/static', 'not-an-nrn'])
def test_cross_account_or_missing_account_is_rejected(nrn):
    raw = naver_event()
    raw['nrn'] = nrn
    with pytest.raises(ValueError, match='account'):
        normalize('naver', raw, SCOPE)


def test_aws_account_boundary_is_not_derived_from_caller_supplied_actor():
    raw = {'recipientAccountId': '999999999999', 'userIdentity': {'accountId': '111111111111'}}
    with pytest.raises(ValueError, match='account'):
        normalize('aws', raw, {**SCOPE, 'account': '111111111111'})


def test_state_scope_change_never_rewinds_existing_watermark(tmp_path):
    path = tmp_path / 'scope.sqlite'
    with closing(State(path, SCOPE)) as state:
        state.put('watermark', '2026-11-01T02:00:00Z')
    with pytest.raises(ValueError, match='scope'):
        State(path, {**SCOPE, 'account': '7654321'})
    with closing(State(path, SCOPE)) as state:
        assert state.get('watermark') == '2026-11-01T02:00:00Z'


def test_failed_sink_write_prevents_api_window_acknowledgment(tmp_path):
    now = datetime.now(timezone.utc)
    scope = {**SCOPE, 'start': (now - timedelta(hours=1)).isoformat()}
    collector = object.__new__(Naver)
    collector.access, collector.key = 'synthetic-access', b'synthetic-secret'
    response = Mock()
    response.__enter__ = Mock(return_value=response)
    response.__exit__ = Mock(return_value=False)
    response.read.return_value = json.dumps({'items': [naver_event()], 'hasMore': False}).encode()
    sink = Mock()
    sink.write.side_effect = RuntimeError('write-not-acknowledged')
    with closing(State(tmp_path / 'scope.sqlite', scope)) as state:
        with patch('cloud_soc.multicloud.collectors.urlopen', return_value=response):
            with pytest.raises(RuntimeError, match='not-acknowledged'):
                collector.poll(scope, state, sink)
        assert state.get('watermark') is None


def template_client():
    client = Mock()
    client.indices.get_index_template.return_value = {'index_templates': [{
        'name': 'soc-multicloud-v1', 'index_template': {
            'index_patterns': ['soc-multicloud-*'], 'template': template_body(), 'priority': 250}}]}
    return client


def test_existing_unrelated_template_is_not_overwritten():
    client = template_client()
    client.indices.get_index_template.return_value['index_templates'][0]['index_template']['index_patterns'] = ['private-*']
    with pytest.raises(ValueError, match='conflict'):
        install(client)
    client.indices.put_index_template.assert_not_called()


def test_legacy_chat_template_is_adopted_without_changing_existing_indices():
    client = template_client()
    body = client.indices.get_index_template.return_value['index_templates'][0]['index_template']['template']
    body['mappings'].pop('_meta')
    assert inspect_template(client)['state'] == 'compatible'
    install(client)
    client.indices.put_index_template.assert_called_once()
    client.indices.put_settings.assert_not_called()
    client.indices.put_mapping.assert_not_called()
    client.delete_by_query.assert_not_called()


def test_reader_initialization_preserves_extra_roles_and_never_resets_existing_password():
    client = Mock()
    client.security.get_role.return_value = SimpleNamespace(body={'cloud_soc_agent_monitor': {'cluster': [], 'indices': []}})
    client.security.get_user.return_value = SimpleNamespace(body={'cloud_soc_agent_monitor': {
        'roles': ['cloud_soc_agent_monitor', 'existing-extra-role'], 'enabled': True}})
    configure_reader(client, 'new-password-must-not-be-used')
    client.security.put_user.assert_not_called()
    added = client.security.put_role.call_args.kwargs['body']['indices']
    assert any('soc-multicloud-*' in grant['names'] for grant in added)


def test_reader_missing_user_receives_initial_password_only_on_creation():
    client = Mock()
    error = NotFoundError('missing', meta=SimpleNamespace(status=404), body={})
    client.security.get_role.side_effect = error
    client.security.get_user.side_effect = error
    configure_reader(client, 'synthetic-initial-password')
    assert client.security.put_user.call_args.kwargs['password'] == 'synthetic-initial-password'


def dashboard(principal):
    app = Flask(__name__)
    app.register_blueprint(blueprint)
    es = Mock()
    es.search.return_value = {'hits': {'total': {'value': 0}, 'hits': []}, 'aggregations': {}}
    app.extensions['monitor'] = es

    @app.before_request
    def authenticate_fixture():
        g.log_principal = SimpleNamespace(organizations=principal)

    return app.test_client(), es


@pytest.mark.parametrize('organizations', [('org-a',), ()])
def test_dashboard_enforces_server_owned_organization_scope_even_when_empty(organizations):
    client, es = dashboard(organizations)
    response = client.get('/api/multicloud?provider=naver')
    assert response.status_code == 200
    filters = es.search.call_args.kwargs['query']['bool']['filter']
    assert {'terms': {'organization.id': list(organizations)}} in filters


def test_browser_cannot_supply_another_tenant_filter():
    client, es = dashboard(('org-a',))
    assert client.get('/api/multicloud?organization=org-b').status_code == 400
    es.search.assert_not_called()


def test_dashboard_does_not_present_partial_shard_failure_as_complete():
    client, es = dashboard(None)
    es.search.return_value['_shards'] = {'failed': 1}
    assert client.get('/api/multicloud').status_code == 503


def load_manager():
    spec = importlib.util.spec_from_file_location('multicloud_lifecycle_contract', ROOT/'deploy/multicloud/manage.py')
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.skipif(os.name != "posix", reason="Linux collector lifecycle uses fcntl")
def test_collector_registry_refuses_unpinned_image_and_public_ports(tmp_path):
    manager = load_manager()
    definition = {'name': 'cloud-soc-naver', 'services': {'naver': {'image': 'mutable:latest'}}}
    compose = tmp_path/'naver.compose.json'
    compose.write_text(json.dumps(definition))
    with pytest.raises(ValueError, match='pinned'):
        manager.deployment(tmp_path, 'naver')
    definition['services']['naver'].update(image='sha256:'+'1'*64, ports=['1234:1234'])
    compose.write_text(json.dumps(definition))
    with pytest.raises(ValueError, match='exposure'):
        manager.deployment(tmp_path, 'naver')


def test_feature_setup_failure_is_recorded_before_worker_keys_are_touched(tmp_path, ownership_calls):
    from test_deployment_parity import FakeSetup, POLICY, NOW
    from cloud_soc.deployment.contract import build_contract
    from cloud_soc.deployment.migrations import prerequisites
    client = FakeSetup()
    client.indices.put_index_template.side_effect = RuntimeError('isolated template failure')
    contract, _ = build_contract(POLICY, {}, tmp_path, now=NOW)
    with pytest.raises(RuntimeError, match='template failure'):
        prerequisites(client, POLICY, contract, tmp_path, {})
    ledger = json.loads((tmp_path/'migrations.json').read_text())
    assert ledger['features']['multicloud-v1'] == {'state': 'failed', 'error_type': 'RuntimeError'}
    assert ledger['version'] == 0
    assert not client.security.events
    assert not (tmp_path/'keys').exists()


def test_delayed_publication_has_separate_cursor_and_never_rewinds_live_position(tmp_path):
    now = datetime.now(timezone.utc)
    floor = now - timedelta(days=2)
    scope = {**SCOPE, 'start': floor.isoformat()}
    original = now - timedelta(minutes=10)
    collector = object.__new__(Naver)
    collector._collect = Mock()
    with closing(State(tmp_path/'delayed.sqlite', scope)) as state:
        state.put('watermark', original.isoformat())
        collector.poll(scope, state, Mock())
        assert datetime.fromisoformat(state.get('watermark').replace('Z', '+00:00')) >= original
        assert datetime.fromisoformat(state.get('naver_late_watermark_v1').replace('Z', '+00:00')) == floor + timedelta(minutes=15)
        assert collector._collect.call_count == 2
        assert collector._collect.call_args_list[1].args[1] == floor


def test_delayed_sink_failure_does_not_acknowledge_replay_range(tmp_path):
    now = datetime.now(timezone.utc)
    scope = {**SCOPE, 'start': (now-timedelta(days=2)).isoformat()}
    original = now - timedelta(minutes=10)
    collector = object.__new__(Naver)
    collector._collect = Mock(side_effect=[None, RuntimeError('late write failed')])
    with closing(State(tmp_path/'delayed.sqlite', scope)) as state:
        state.put('watermark', original.isoformat())
        with pytest.raises(RuntimeError, match='late write'):
            collector.poll(scope, state, Mock())
        assert state.get('naver_late_watermark_v1') is None
        assert datetime.fromisoformat(state.get('watermark').replace('Z', '+00:00')) >= original
