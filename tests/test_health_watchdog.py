"""Availability failures must not become false recovery or duplicate Slack posts."""
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from cloud_soc.health.watchdog import DEFAULTS, collect, dispatch, save, transition, validate_policy, webhook


def sample(**updates):
    return {'at': 1000, 'disk': 50, 'input': {'recent': 200, 'baseline': 300, 'last_age': 10},
            'workers': {k: {'state': 'success', 'age': 30} for k in ('normalizer', 'normalizer-priority')}} | updates


def advance(state, value, times=2):
    for _ in range(times):
        transition(state, value, DEFAULTS)
    return state


def test_normal_start_sends_nothing():
    assert advance({}, sample())['events'] == []


def test_encrypted_destination_is_used_only_when_enabled():
    from cryptography.fernet import Fernet, InvalidToken
    key = Fernet.generate_key()
    secret = Fernet(key).encrypt(b'destination-for-mocked-sender')
    value = {'enabled': True, 'key': key.decode(), 'secret': secret.decode()}
    assert webhook(value) == 'destination-for-mocked-sender'
    assert webhook(value | {'enabled': False}) is None
    assert webhook(None) is None
    with pytest.raises(InvalidToken):
        webhook(value | {'key': Fernet.generate_key().decode()})


def test_disk_debounce_escalation_hysteresis_and_recovery():
    state = {}
    advance(state, sample(disk=80), 1)
    assert not state['events']
    advance(state, sample(disk=80), 1)
    advance(state, sample(disk=80), 5)
    assert len(state['events']) == 1
    advance(state, sample(disk=90))
    assert len(state['events']) == 2
    advance(state, sample(disk=72), 3)
    assert state['incidents']['disk']['active']
    advance(state, sample(disk=65))
    assert not state['incidents']['disk']['active']
    assert len(state['events']) == 3
    assert '복구' in state['events'][-1]['payload']['text']


def test_low_volume_needs_sufficient_baseline():
    quiet = sample(input={'recent': 2, 'baseline': 3, 'last_age': 15})
    assert advance({}, quiet)['events'] == []
    drop = sample(input={'recent': 10, 'baseline': 500, 'last_age': 15})
    state = advance({}, drop)
    assert [e['key'] for e in state['events']] == ['volume']


def test_receipt_gap_and_stuck_checkpoint_even_with_fresh_worker_success():
    value = sample(input={'recent': 0, 'baseline': 300, 'last_age': 800})
    value['workers']['normalizer']['age'] = 900
    state = advance({}, value)
    assert {e['key'] for e in state['events']} == {'volume', 'receipt', 'normalizer'}


def test_es_outage_never_recovers_prior_incidents_and_resets_consecutive_counts():
    old = sample(input={'recent': 0, 'baseline': 300, 'last_age': 900})
    state = advance({}, old)
    before = len(state['events'])
    advance(state, sample(input=None, workers=None), 4)
    assert state['incidents']['receipt']['active']
    assert state['incidents']['volume']['active']
    assert not any('복구' in e['payload']['text'] for e in state['events'][before:])
    advance(state, sample(), 1)
    assert state['incidents']['receipt']['active']
    advance(state, sample(), 1)
    assert not state['incidents']['receipt']['active']


def test_unknown_disk_and_clock_skew_are_not_healthy():
    value = sample(disk=float('nan'), input={'recent': 3, 'baseline': 3, 'last_age': -900})
    state = advance({}, value)
    assert {'disk', 'receipt'} <= {e['key'] for e in state['events']}


def test_durable_intent_and_ambiguous_post_not_retried(tmp_path):
    path = tmp_path / 'state.json'
    state = advance({}, sample(disk=90))
    calls = []
    def sender(url, payload):
        assert json.loads(path.read_text())['events'][0]['status'] == 'sending'
        calls.append(payload)
        return SimpleNamespace(outcome='unknown', code='delivery_unconfirmed', retry_after=0)
    dispatch(state, path, sender=sender, destination=lambda: 'secret-not-logged', clock=lambda: 1000)
    dispatch(state, path, sender=sender, destination=lambda: 'secret-not-logged', clock=lambda: 9999)
    assert len(calls) == 1
    assert state['events'][0]['status'] == 'unknown'
    assert 'secret-not-logged' not in path.read_text()


def test_definite_retry_and_disabled_destination(tmp_path):
    state = advance({}, sample(disk=90))
    path = tmp_path / 'state.json'
    dispatch(state, path, sender=lambda *_: pytest.fail('disabled destination'), destination=lambda: None, clock=lambda: 1000)
    assert state['events'][0]['status'] == 'blocked'
    def retry(*_):
        return SimpleNamespace(outcome='retry', code='slack_rate_limited', retry_after=120)
    dispatch(state, path, sender=retry, destination=lambda: 'redacted', clock=lambda: 1060)
    assert state['events'][0]['next_try'] == 1180
    state = json.loads(path.read_text())
    def sent(*_):
        return SimpleNamespace(outcome='sent', code='slack_accepted', retry_after=0)
    dispatch(state, path, sender=sent, destination=lambda: 'redacted', clock=lambda: 1180)
    assert state['events'][0]['status'] == 'sent'


@pytest.mark.parametrize('attempts, outcome', [(0, 'retry'), (7, 'permanent')])
def test_retry_after_holds_other_events_across_timer_runs(tmp_path, attempts, outcome):
    state = advance({}, sample(disk=80))
    advance(state, sample(disk=90))
    first, second = state['events']
    first['attempts'] = attempts
    path = tmp_path / 'state.json'
    now = 1000

    def clock():
        return now

    def rate_limited(_url, payload):
        nonlocal now
        assert payload == first['payload']
        now += 7  # Slack's delay starts when the response is received.
        return SimpleNamespace(outcome='retry', code='slack_rate_limited', retry_after=120)

    def destination():
        return 'secret-not-logged'

    dispatch(state, path, sender=rate_limited, destination=destination, clock=clock)
    state = json.loads(path.read_text())
    assert state['events'][0]['status'] == outcome
    assert state['slack_retry_until'] == 1127
    assert 'secret-not-logged' not in path.read_text()

    for now in (1060, 1126):
        dispatch(state, path, sender=lambda *_: pytest.fail('Slack cooldown still active'),
                 destination=destination, clock=clock)
        assert state['events'][1] == second

    now = 1127
    sent = []

    def sender(_url, payload):
        sent.append(payload)
        return SimpleNamespace(outcome='sent', code='slack_accepted', retry_after=0)

    dispatch(state, path, sender=sender, destination=destination, clock=clock)
    assert sent == [first['payload'] if outcome == 'retry' else second['payload']]


def test_retry_after_from_legacy_event_holds_watchdog_queue(tmp_path):
    state = advance({}, sample(disk=80))
    advance(state, sample(disk=90))
    state['events'][0].update(status='retry', code='slack_rate_limited', next_try=1120)
    dispatch(state, tmp_path / 'state.json', sender=lambda *_: pytest.fail('Legacy Slack cooldown still active'),
             destination=lambda: 'redacted', clock=lambda: 1060)
    assert state['events'][1]['status'] == 'queued'


@pytest.mark.parametrize('cooldown', [False, True])
def test_crash_during_post_persists_unknown_after_restart(tmp_path, cooldown):
    path = tmp_path / 'state.json'
    state = advance({}, sample(disk=90))

    def interrupted(*_):
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        dispatch(state, path, sender=interrupted, destination=lambda: 'redacted', clock=lambda: 1000)
    state = json.loads(path.read_text())
    original = state['events'][0].copy()
    assert original['status'] == 'sending' and original['attempts'] == 1
    if cooldown:
        state['slack_retry_until'] = 1200
        queued = advance({}, sample(disk=80))['events'][0] | {'id': 'another-alert'}
        state['events'].append(queued)
        save(path, state)

    for now in (1060, 1120):
        dispatch(state, path, sender=lambda *_: pytest.fail('Unexpected Slack POST'),
                 destination=lambda: pytest.fail('Destination read before dispatch was due'), clock=lambda: now)
        state = json.loads(path.read_text())
        assert state['events'][0] == original | {'status': 'unknown', 'code': 'delivery_unconfirmed'}
        if cooldown:
            assert state['events'][1] == queued
            assert state['slack_retry_until'] == 1200


def test_partial_search_is_unavailable_and_worker_read_independent():
    class Client:
        indices = SimpleNamespace(resolve_index=lambda **_: {'indices': [{'name': 'soc-host-raw-test'}]})
        def search(self, **kwargs):
            assert kwargs['allow_partial_search_results'] is False
            return {'_shards': {'failed': 1}}
        def mget(self, **kwargs):
            return {'docs': [{'_id': k, '_source': {'state': 'success', 'checkpoint': '1970-01-01T00:16:30Z'}}
                             for k in kwargs['ids']]}
    value = collect(Client(), 1000, 50)
    assert value['input'] is None
    assert value['workers']['normalizer']['age'] == 10


def test_incomplete_worker_set_fails_closed():
    class Client:
        indices = SimpleNamespace(resolve_index=lambda **_: {'indices': []})
        def mget(self, **_):
            return {'docs': []}
    assert collect(Client(), 1000, 50)['workers'] is None


@pytest.mark.parametrize('changes', [{'disk_critical': 70}, {'bad_cycles': 0}, {'last_receipt': -1}, {'window': 60}])
def test_invalid_policy_rejected(changes):
    with pytest.raises(ValueError):
        validate_policy(deepcopy(DEFAULTS) | changes)
