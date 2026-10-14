"""Explicit catch-up tuning never skips a partial range or rewinds checkpoints."""
from datetime import timedelta
import sqlite3
from unittest.mock import Mock, patch

import pytest

from cloud_soc.processing.__main__ import main
from cloud_soc.processing.worker import run_once
from test_processing import START, NOW


@pytest.mark.parametrize('window', [0, 61, True, 1.5, '30'])
def test_worker_refuses_unsafe_window_before_state_creation(tmp_path, window):
    state = tmp_path / 'state.sqlite'
    with pytest.raises(ValueError):
        run_once(Mock(), state, START, now=NOW, window_minutes=window)
    assert not state.exists()


def test_larger_window_preserves_overlap_finality_and_existing_start(tmp_path):
    client = Mock(); client.options.return_value = client
    state = tmp_path / 'state.sqlite'
    seen = []
    def empty(client, start, end):
        seen.append((start, end))
        return []
    first = run_once(client, state, START, now=NOW, scanner=empty)
    assert first['checkpoint'] == '2026-09-22T01:05:00Z'
    result = run_once(client, state, START, now=NOW, scanner=empty, window_minutes=60)
    assert result['checkpoint'] == '2026-09-22T01:19:30Z'
    assert seen[-1] == (START, result['checkpoint'])
    resumed = run_once(client, state, START, now=NOW + timedelta(seconds=60), scanner=empty, window_minutes=60)
    assert seen[-1][0] == '2026-09-22T01:04:30Z'
    assert resumed['checkpoint'] == '2026-09-22T01:20:30Z'
    with sqlite3.connect(state) as db:
        assert db.execute('SELECT initial_start FROM config').fetchone()[0] == START


@pytest.mark.parametrize('option,value', [('--interval','9'),('--interval','3601'),('--window-minutes','0'),('--window-minutes','61')])
def test_cli_invalid_tuning_has_no_connection(option, value):
    with patch('cloud_soc.processing.__main__.Elasticsearch') as client:
        assert main(['--start', START, option, value]) == 1
        client.assert_not_called()


def test_cli_passes_tuning_and_waits_before_retrying(tmp_path):
    ca = tmp_path / 'ca'; ca.write_text('fixture')
    args = ['--run', '--start', START, '--state', str(tmp_path/'state.sqlite'),
            '--es-url', 'https://example.test:9200', '--ca-file', str(ca), '--api-key-file', 'fixture',
            '--interval', '10', '--window-minutes', '60']
    with patch('cloud_soc.processing.__main__.Elasticsearch'), \
         patch('cloud_soc.processing.__main__.protected_key', return_value='fixture'), \
         patch('cloud_soc.processing.__main__.run_once', side_effect=RuntimeError('failure')) as run, \
         patch('cloud_soc.processing.__main__.time.sleep', side_effect=KeyboardInterrupt) as sleep:
        with pytest.raises(KeyboardInterrupt):
            main(args)
        assert run.call_args.kwargs['window_minutes'] == 60
        sleep.assert_called_once_with(10)
