"""Independent opt-in rules preserve the AUTH worker, identity and notices."""
from contextlib import closing
from datetime import timedelta
import json
import sqlite3
from unittest.mock import patch

import pytest

from cloud_soc.detection.__main__ import main
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.worker import approved_rules
from cloud_soc.portal.operations import Operations
from test_ruleset_integration import fixture_for, BASE


def test_profile_requires_explicit_enabled_ids_without_auth():
    rules = approved_rules(additional_rule_ids=['AUTH-SEQ-001','ATTACK-01'])
    assert [r['id'] for r in rules] == ['AUTH-SEQ-001','ATTACK-01']
    assert [r['id'] for r in approved_rules()] == ['AUTH-001']
    for options in ({'additional_rule_ids':['AUTH-001']}, {'additional_rule_ids':['AWS-CONSOLE-001']},
                    {'additional_rule_ids':['AUTH-SEQ-001'],'include_cloud':True},
                    {'additional_rule_ids':['AUTH-SEQ-001'],'rule_ids':['AUTH-001']}):
        with pytest.raises(ValueError):
            approved_rules(**options)


@pytest.mark.parametrize('extra', [[],['--early-auth'],['--snapshot']])
def test_cli_refuses_default_state_or_auth_modes(extra):
    with patch('cloud_soc.detection.__main__.Elasticsearch') as es:
        assert main(['--additional-rules','AUTH-SEQ-001',*extra]) == 1
        es.assert_not_called()


def test_cli_offline_selection_with_explicit_separate_state(tmp_path):
    with patch('cloud_soc.detection.__main__.Elasticsearch') as es:
        assert main(['--additional-rules','AUTH-SEQ-001','--state',str(tmp_path/'extra.sqlite')]) == 0
        es.assert_not_called()


def test_additional_engine_restart_creates_one_alert_without_auth_state(tmp_path):
    fixture = fixture_for('AUTH-SEQ-001')
    path = tmp_path/'extra.sqlite'
    arguments = dict(state_path=path,start=BASE,lateness_seconds=60,scanner=fixture.scan,
                     additional_rule_ids=['AUTH-SEQ-001'])
    first = run_incremental(fixture.client, now=BASE+timedelta(seconds=500), **arguments)
    assert first['created'] == 1
    with closing(sqlite3.connect(path)) as db:
        old = json.loads(db.execute('SELECT body FROM runtime').fetchone()[0])
    second = run_incremental(fixture.client, now=BASE+timedelta(seconds=550), **arguments)
    assert second['created'] == 0
    assert not path.with_name(path.name+'.early.sqlite').exists()
    statuses = [call.kwargs for call in fixture.client.index.call_args_list
                if call.kwargs['index'] == 'soc-pipeline-status']
    assert statuses and {call['id'] for call in statuses} == {'detector-additional'}
    assert statuses[-1]['document']['detection'] == 'AUTH-SEQ-001'
    with pytest.raises(ValueError, match='rule_or_scope_changed_requires_new_state'):
        run_incremental(fixture.client,state_path=path,start=BASE,now=BASE+timedelta(seconds=600),
                        lateness_seconds=60,scanner=fixture.scan)
    with closing(sqlite3.connect(path)) as db:
        assert json.loads(db.execute('SELECT body FROM runtime').fetchone()[0])['identity'] == old['identity']


def test_additional_profile_refuses_auth_notice_ownership_before_state_creation(tmp_path):
    fixture = fixture_for('AUTH-SEQ-001');path=tmp_path/'extra.sqlite'
    with pytest.raises(ValueError):
        run_incremental(fixture.client,state_path=path,start=BASE,early_auth=True,
                        additional_rule_ids=['AUTH-SEQ-001'])
    assert not path.exists()


def test_failed_additional_worker_cannot_appear_healthy():
    reader = Operations(None)
    values={'normalizer':{'state':'success','health':'healthy'},'detector':{'state':'success','health':'healthy'},
            'detector-additional':{'state':'failed','health':'failed'}}
    with patch.object(reader,'worker_status',side_effect=lambda name:values[name]):
        report = reader.pipeline()
    assert report['coverage'] == {'state':'blocked','reason':'additional_detector_failed'}
    assert report['detector']['state'] == 'success'


def test_absent_additional_worker_does_not_change_coverage():
    reader = Operations(None)
    values={'normalizer':{'state':'success','health':'healthy'},'detector':{'state':'success','health':'healthy'},
            'detector-additional':{'state':'not_started'}}
    with patch.object(reader,'worker_status',side_effect=lambda name:values[name]):
        report = reader.pipeline()
    assert report['coverage']['state'] == 'observed'
    assert 'additional_detector' not in report
