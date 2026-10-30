"""Separate mall telemetry cannot overwrite the existing additional detector."""
from datetime import timedelta
from unittest.mock import patch

import pytest

from cloud_soc.detection.__main__ import main
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.processing.contract import STATUS
from ruleset_fixtures import BASE
from test_ruleset_integration import fixture_for


def test_mall_worker_detects_real_rule_with_independent_state_and_status(tmp_path):
    fixture = fixture_for('WEB-AUTH-01')
    fixture.docs[(STATUS, 'detector-additional')] = {'state': 'existing worker untouched'}
    result = run_incremental(fixture.client, state_path=tmp_path / 'mall.sqlite', start=BASE,
                             now=BASE + timedelta(seconds=230), lateness_seconds=60,
                             scanner=fixture.scan, additional_rule_ids=['WEB-AUTH-01'],
                             status_id='detector-mall-login')
    assert result['created'] == 1
    assert fixture.docs[(STATUS, 'detector-additional')] == {'state': 'existing worker untouched'}
    statuses = [call.kwargs for call in fixture.client.index.call_args_list if call.kwargs['index'] == STATUS]
    assert statuses and all(row['id'] == 'detector-mall-login' for row in statuses)
    assert statuses[-1]['document']['runtime']['rules'][0]['id'] == 'WEB-AUTH-01'


def test_mall_status_cannot_be_used_for_unrelated_rules(tmp_path):
    fixture = fixture_for('AUTH-SEQ-001')
    with pytest.raises(ValueError, match='Mall status'):
        run_incremental(fixture.client, state_path=tmp_path / 'other.sqlite', start=BASE,
                        now=BASE + timedelta(seconds=230), additional_rule_ids=['AUTH-SEQ-001'],
                        status_id='detector-mall-login')
    assert not (tmp_path / 'other.sqlite').exists()


def test_cli_only_accepts_mall_status_with_the_exact_explicit_rule():
    with patch('cloud_soc.detection.__main__.Elasticsearch') as client:
        assert main(['--additional-rules', 'WEB-AUTH-01', '--status-id', 'detector-mall-login',
                     '--state', 'state/mall-login/runtime.sqlite']) == 0
        assert main(['--additional-rules', 'AUTH-SEQ-001', '--status-id', 'detector-mall-login']) == 1
        client.assert_not_called()
