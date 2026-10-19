"""Execution observation must never be inferred from YAML or a successful replay."""
from copy import deepcopy
from datetime import datetime, timezone
from unittest.mock import Mock, patch

import pytest

from cloud_soc.detection.profiles import catalog
from cloud_soc.detection.telemetry import runtime_manifest
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.runtime_rules import inventory, public_manifest
from cloud_soc.processing.contract import STATUS


def worker(mode='continuous', state='success'):
    return {'state': state, 'runtime': runtime_manifest([catalog()[0]], mode)}


def test_yaml_enabled_never_means_runtime_selected():
    rows = inventory({'detector': {'state': 'not_started'}})
    assert all(row['state'] == 'not_observed' and not row['observations'] for row in rows)
    assert {row['scope'] for row in rows} == {'general', 'application_audit', 'application_waf'}


@pytest.mark.parametrize(('mode', 'state', 'expected'), [
    ('continuous', 'success', 'running'), ('continuous', 'running', 'running'),
    ('continuous', 'waiting', 'running'), ('continuous', 'failed', 'failed'),
    ('continuous', 'stale', 'stale'), ('snapshot', 'success', 'reported'),
    ('retrospective', 'success', 'reported')])
def test_freshness_and_execution_mode(mode, state, expected):
    rows = inventory({'detector': worker(mode, state)})
    assert rows[0]['observations'][0]['state'] == expected


def test_wrong_worker_revision_and_unavailable_inventory_are_explicit():
    value = worker()
    value['runtime']['rules'][0]['revision'] = 'f' * 64
    rows = inventory({'detector': value, 'detector-additional': {'state': 'unavailable'}})
    assert rows[0]['observations'][0]['state'] == 'revision_mismatch'
    assert rows[-1]['state'] == 'unknown'
    assert inventory({'detector': {'state': 'success', 'detection': 'WEB-WAF-01'}})[0]['state'] == 'unknown'


@pytest.mark.parametrize('mutation', [
    lambda x: x.update(schema_version=True), lambda x: x.update(mode='anything'),
    lambda x: x['rules'].append(deepcopy(x['rules'][0])),
    lambda x: x['rules'][0].update(revision='SECRET_CANARY'),
    lambda x: x['rules'][0].update(id='<script>'), lambda x: x['rules'][0].update(engine_version='secret value'),
    lambda x: x.update(rules=[None]), lambda x: x.update(rules=[])])
def test_invalid_manifest_is_not_projected(mutation):
    manifest = worker()['runtime']
    mutation(manifest)
    assert public_manifest(manifest) is None


def test_unknown_fields_are_not_disclosed():
    manifest = worker()['runtime']
    manifest['secret'] = 'SECRET_CANARY'
    manifest['rules'][0]['secret'] = 'SECRET_CANARY'
    assert 'SECRET_CANARY' not in str(public_manifest(manifest))


def test_status_reads_actual_manifest_and_stale_state():
    client = Mock()
    client.options.return_value = client
    reader = Operations(client)
    value = {'@timestamp': datetime.now(timezone.utc).isoformat(), 'state': 'success',
             'runtime': worker()['runtime']}
    with patch.object(reader, 'get', return_value=value) as get:
        result = reader.worker_status('detector')
        assert result['runtime'] == value['runtime']
        assert get.call_args.args[:2] == (STATUS, 'detector')
        assert 'runtime' in get.call_args.args[2]
        value['@timestamp'] = '2020-01-01T00:00:00Z'
        assert reader.worker_status('detector')['state'] == 'stale'


def test_scoped_reader_does_not_disclose_global_rule_inventory():
    reader = Operations(Mock(), organizations=('team-a',))
    with patch.object(reader, 'get') as get:
        result = reader.pipeline()
        assert 'rules' not in result
        get.assert_not_called()


def test_worker_selection_missing_from_checkout_is_visible_but_never_running():
    value = worker()
    value['runtime']['rules'][0]['id'] = 'CUSTOM-UNKNOWN'
    row = next(r for r in inventory({'detector': value}) if r['id'] == 'CUSTOM-UNKNOWN')
    assert row['catalog_revision'] is None and row['state'] == 'catalog_unavailable'
    assert row['observations'][0]['state'] == 'catalog_unavailable'
