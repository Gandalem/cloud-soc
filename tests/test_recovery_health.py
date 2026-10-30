"""Health deadlines, truthful recovery receipts, and real isolated HTTP/TLS probes."""
from copy import deepcopy
import json
from unittest.mock import Mock

import pytest

from cloud_soc.deployment import host, recovery_health as health
from cloud_soc.deployment.image_safety import DeploymentSafetyError
from test_recovery_compose_files import interrupted as interrupted


class Clock:
    now = 0

    def __call__(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


def row(status='healthy', **state):
    return {'Name': '/cloud-soc-central-portal-1', 'Image': 'sha256:old',
            'State': {'Running': True, 'Health': {'Status': status, 'Log': ['PRIVATE_CANARY']}, **state},
            'Config': {'Healthcheck': {'Test': ['CMD', 'synthetic-check']},
                       'Env': ['SOC_PUBLIC_URL=https://portal.test']}}


def wait(engine, clock, probe):
    return health.wait_for_recovery(engine, 'cloud-soc-central', {'portal': 'sha256:old'},
                                    timeout=3, interval=1, clock=clock, sleep=clock.sleep, probe=probe)


@pytest.mark.parametrize('state', [row('unhealthy'), row('starting'), row('unknown'),
    row(Running=False), row(Paused=True), row(Restarting=True),
    {**row(), 'State': {'Running': True}}, {}, {'Name': None}])
def test_nonready_or_missing_health_never_passes_and_wait_is_bounded(state):
    clock = Clock();engine = Mock();engine.json.return_value = [state];probe = Mock(return_value=True)
    with pytest.raises(DeploymentSafetyError) as error:
        wait(engine, clock, probe)
    assert clock.now == 3
    assert 'PRIVATE_CANARY' not in str(error.value)
    probe.assert_not_called()
    assert all(0 < call.kwargs['timeout'] <= 3 for call in engine.json.call_args_list)


def test_starting_and_unhealthy_may_recover_before_deadline():
    clock = Clock();engine = Mock();probe = Mock(return_value=True)
    engine.json.side_effect = [[row('starting')], [row('unhealthy')], [row()]]
    wait(engine, clock, probe)
    assert clock.now == 2 and engine.json.call_count == 3
    probe.assert_called_once()
    assert probe.call_args.args[-1] == 1


def test_image_mismatch_is_not_waited_away():
    clock = Clock();engine = Mock();probe = Mock()
    engine.json.return_value = [{**row(), 'Image': 'sha256:unexpected'}]
    with pytest.raises(DeploymentSafetyError, match='이미지'):
        wait(engine, clock, probe)
    assert clock.now == 0
    probe.assert_not_called()


def test_all_services_share_one_wait_and_kibana_must_be_healthy():
    clock = Clock();engine = Mock();probe = Mock(return_value=True)
    kibana = row('unhealthy')
    kibana.update(Name='/cloud-soc-central-kibana-1', Image='sha256:kibana')
    ready_kibana = deepcopy(kibana);ready_kibana['State']['Health']['Status'] = 'healthy'
    engine.json.side_effect = [[row(), kibana], [row(), ready_kibana]]
    health.wait_for_recovery(engine, 'cloud-soc-central', {'portal': 'sha256:old', 'kibana': 'sha256:kibana'},
                             timeout=3, interval=1, clock=clock, sleep=clock.sleep, probe=probe)
    assert clock.now == 1 and probe.call_count == 1
    assert set(probe.call_args.args[2]) == {'portal', 'kibana'}


@pytest.mark.parametrize('service', ['elasticsearch', 'kibana'])
def test_infrastructure_cannot_claim_ready_without_health_evidence(service):
    clock = Clock();engine = Mock();probe = Mock(return_value=True)
    engine.json.return_value = [{'Name': '/cloud-soc-central-' + service + '-1',
                                'Image': 'sha256:old', 'Config': {}, 'State': {'Running': True}}]
    with pytest.raises(DeploymentSafetyError):
        health.wait_for_recovery(engine, 'cloud-soc-central', {service: 'sha256:old'},
                                 timeout=3, interval=1, clock=clock, sleep=clock.sleep, probe=probe)
    probe.assert_not_called()


@pytest.mark.parametrize('http_ok', [False, True])
def test_http_probe_shares_deadline_and_late_success_is_refused(http_ok):
    clock = Clock();engine = Mock();engine.json.return_value = [row()]
    def probe(*args):
        assert args[-1] <= 3
        if http_ok:
            clock.now += 4
        return http_ok
    with pytest.raises(DeploymentSafetyError):
        wait(engine, clock, probe)
    assert clock.now <= 4


def test_transient_inspection_error_retries_without_accepting_absence():
    clock = Clock();engine = Mock();probe = Mock(return_value=True)
    engine.json.side_effect = [RuntimeError('PRIVATE_CANARY'), [], [row()]]
    wait(engine, clock, probe)
    assert clock.now == 2 and probe.call_count == 1


@pytest.mark.parametrize('configuration', [{}, {'Healthcheck': None}])
def test_worker_without_healthcheck_requires_running_but_no_fake_health(configuration):
    clock = Clock();engine = Mock();probe = Mock(return_value=True)
    obj = row();obj['Config'] = configuration;obj['State'].pop('Health')
    engine.json.return_value = [obj]
    wait(engine, clock, probe)
    assert clock.now == 0 and probe.call_count == 1


@pytest.mark.parametrize('status,http_ok', [('unhealthy', True), ('healthy', False), ('healthy', True)])
def test_recover_receipt_and_pending_depend_on_actual_readiness(interrupted, monkeypatch, status, http_ok):
    state, runtime, run, _, _, engine = interrupted
    clock = Clock();probe = Mock(return_value=http_ok)
    engine.json.side_effect = lambda args, **_: [row(status)] if args[0] == 'inspect' else [{'Id': 'sha256:old'}]
    monkeypatch.setattr(host, 'wait_for_recovery', lambda eng, project, pins: health.wait_for_recovery(
        eng, project, pins, timeout=3, interval=1, clock=clock, sleep=clock.sleep, probe=probe))
    if status == 'healthy' and http_ok:
        assert host.recover(engine, state)['recovery_startup_verified'] is True
        assert json.loads((run / 'recovered.json').read_text())['recovery_startup_verified'] is True
        assert not (runtime / 'pending.json').exists()
    else:
        with pytest.raises(DeploymentSafetyError):
            host.recover(engine, state)
        assert (runtime / 'pending.json').exists()
        assert not (run / 'recovered.json').exists()
        assert not (run / 'failed.json').exists()
        assert not (runtime / 'compose.active.json').exists()


def test_probe_uses_restored_image_ca_and_bounded_exec_without_secret_environment():
    objects = {'portal': row(), 'gateway': deepcopy(row()), 'kibana': row()}
    objects['gateway']['Config']['Env'] = ['SOC_PUBLIC_HOST=portal.test',
        'SOC_ADMIN_ALLOWED_CIDRS=192.0.2.0/24', 'PRIVATE_PASSWORD=CANARY']
    engine = Mock();engine.run.return_value = 'recovery_http_ready\n'
    assert health.probe_http(engine, 'cloud-soc-central', objects, .5)
    args, kwargs = engine.run.call_args.args[0], engine.run.call_args.kwargs
    assert args[:4] == ['exec', '-i', 'cloud-soc-central-portal-1', 'python']
    assert kwargs['timeout'] == .5 and 'CANARY' not in kwargs['input']
    payload = json.loads(kwargs['input'])
    assert payload['gateway_ports'] == [443, 5601] and payload['allowed'] == '192.0.2.0/24'
    assert 'CERT_NONE' not in health.HTTP_PROBE and 'check_hostname=False' not in health.HTTP_PROBE


def test_active_execution_without_any_image_evidence_cannot_claim_ready(interrupted):
    state, runtime, run, _, saved, engine = interrupted
    saved.update(old_names=[], image_pins={})
    (run / 'recovery.json').write_text(json.dumps(saved))
    with pytest.raises(DeploymentSafetyError):
        host.recover(engine, state)
    engine.run.assert_not_called()
    assert (runtime / 'pending.json').exists()
