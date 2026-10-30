"""Real file drift with a Docker double: refuse it before stopping any service."""
from contextlib import nullcontext
import hashlib
import json
from pathlib import Path
from unittest.mock import Mock, call

import pytest

from cloud_soc.deployment import host, image_safety


@pytest.fixture
def interrupted(tmp_path, monkeypatch):
    state = tmp_path / 'state/server'
    runtime = state / 'runtime'
    run = runtime / 'upgrades/interrupted'
    run.mkdir(parents=True)
    base = tmp_path / 'previous-release/compose.yaml'
    base.parent.mkdir()
    base.write_bytes(b'services: {portal: {image: "sha256:old"}}\n')
    checksum = hashlib.sha256(base.read_bytes()).hexdigest()
    site = runtime / 'site.json'
    site.write_bytes(b'{"services":{"portal":{"environment":{"SITE":"original"}}}}\n')
    backup = host.save_previous_site(runtime, run)
    site.write_bytes(b'{"services":{"portal":{"image":"sha256:new"}}}\n')
    active = ['--project-name', 'cloud-soc-central', '-f', str(base), '-f', str(site)]
    saved = {'previous_compose': active, 'previous_compose_sha256': {str(base): checksum},
             'old_names': ['portal'], 'old_site': backup, 'old_contract': None, 'old_current': None,
             'image_pins': {'portal': 'sha256:old'}, 'image_mode': 'site',
             'canonical': ['compose', '--project-name', 'cloud-soc-central']}
    (run / 'recovery.json').write_text(json.dumps(saved))
    (runtime / 'pending.json').write_text(json.dumps({'run': str(run)}))
    engine = Mock()
    engine.json.return_value = [{'Id': 'sha256:old'}]
    monkeypatch.setattr(host, 'lock', lambda _: nullcontext())
    # These fixtures isolate file guards; readiness has separate state and HTTP/TLS acceptance tests.
    monkeypatch.setattr(host, 'wait_for_recovery', Mock())
    monkeypatch.setattr(host, 'containers', lambda *_: {
        'portal': {'Image': 'sha256:old', 'State': {'Running': True}}})
    return state, runtime, run, base, saved, engine


@pytest.mark.parametrize('fault', ['changed', 'missing', 'directory', 'symlink', 'parent_symlink',
                                   'missing_proof', 'incomplete_proof', 'wrong_proof', 'extra_proof'])
def test_untrusted_base_retains_pending_and_never_stops_service(interrupted, fault):
    state, runtime, run, base, saved, engine = interrupted
    site_before = (runtime / 'site.json').read_bytes()
    if fault == 'changed':
        base.write_bytes(b'services: {portal: {environment: {UNREVIEWED: true}}}\n')
    elif fault == 'missing':
        base.unlink()
    elif fault == 'directory':
        base.unlink();base.mkdir()
    elif fault in ('symlink', 'parent_symlink'):
        target = base.with_name('moved.yaml') if fault == 'symlink' else base.parent.with_name('moved-release')
        original = base if fault == 'symlink' else base.parent
        original.rename(target)
        try:
            original.symlink_to(target, target_is_directory=fault == 'parent_symlink')
        except OSError:
            pytest.skip('Symlink creation unavailable')
    elif fault == 'missing_proof':
        saved.pop('previous_compose_sha256')
    elif fault == 'incomplete_proof':
        saved['previous_compose_sha256'] = {}
    elif fault == 'wrong_proof':
        saved['previous_compose_sha256'][str(base)] = '0'*64
    else:
        saved['previous_compose_sha256'][str(base.with_name('unreviewed.yaml'))] = '0'*64
    (run / 'recovery.json').write_text(json.dumps(saved))
    journal_before = (run / 'recovery.json').read_bytes()
    with pytest.raises(image_safety.DeploymentSafetyError):
        host.recover(engine, state)
    engine.run.assert_not_called()
    assert (runtime / 'pending.json').is_file()
    assert not (run / 'recovered.json').exists()
    assert (runtime / 'site.json').read_bytes() == site_before
    assert (run / 'recovery.json').read_bytes() == journal_before


@pytest.mark.parametrize('journal', ['current', 'legacy_plan', 'legacy_review'])
def test_unchanged_recorded_base_restores_original_settings(interrupted, journal):
    state, runtime, run, base, saved, engine = interrupted
    hashes = saved['previous_compose_sha256']
    if journal != 'current':
        saved.pop('previous_compose_sha256')
        if journal == 'legacy_plan':
            (run / 'plan.json').write_text(json.dumps({
                'previous_compose': saved['previous_compose'], 'protected_sha256': hashes}))
        else:
            frozen = runtime / 'compose-reviews/previous/compose.json'
            frozen.parent.mkdir(parents=True)
            base.rename(frozen)
            saved['previous_compose'] = [str(frozen) if word == str(base) else word
                                         for word in saved['previous_compose']]
            base = frozen
            hashes = {str(base): hashlib.sha256(base.read_bytes()).hexdigest()}
            saved['reviewed_compose_files'] = hashes
        (run / 'recovery.json').write_text(json.dumps(saved))
    def execute(args, **_):
        if 'up' in args:
            assert args == ['compose', *saved['previous_compose'], 'up', '-d',
                            '--no-build', '--pull', 'never', 'portal']
            assert hashlib.sha256(base.read_bytes()).hexdigest() == hashes[str(base)]
            assert json.loads((runtime / 'site.json').read_text())['services']['portal'] == {
                'image': 'sha256:old', 'environment': {'SITE': 'original'}}
    engine.run.side_effect = execute
    assert host.recover(engine, state)['old_execution_restored']
    assert any('up' in call.args[0] for call in engine.run.call_args_list)
    assert not (runtime / 'pending.json').exists()


def test_base_is_rechecked_after_container_inspection_before_stop(interrupted, monkeypatch):
    state, runtime, _, base, _, engine = interrupted
    def containers(*_):
        base.write_text('services: {changed: {}}')
        return {'portal': {'Image': 'sha256:old', 'State': {'Running': True}}}
    monkeypatch.setattr(host, 'containers', containers)
    with pytest.raises(image_safety.DeploymentSafetyError):
        host.recover(engine, state)
    engine.run.assert_not_called()
    assert (runtime / 'pending.json').exists()


def test_base_is_checked_again_before_up_after_site_restore(interrupted, monkeypatch):
    state, runtime, _, base, _, engine = interrupted
    restore = host.restore_previous_site
    def restore_and_change(*args):
        restore(*args)
        base.write_text('services: {changed: {}}')
    monkeypatch.setattr(host, 'restore_previous_site', restore_and_change)
    with pytest.raises(image_safety.DeploymentSafetyError):
        host.recover(engine, state)
    assert engine.run.call_args_list == [call(['stop', 'cloud-soc-central-portal-1'])]
    assert (runtime / 'pending.json').exists()


def test_previous_base_hash_participates_in_plan_fingerprint(tmp_path, monkeypatch):
    state = tmp_path / 'state';state.mkdir()
    (state / 'compose.env').write_text('SOC_STATE_DIR=fixture')
    base = tmp_path / 'old-compose.yaml';base.write_text('services: {}')
    active = ['-f', str(base), '-f', str(state / 'runtime/site.json')]
    objects = {'portal': {'Id': 'old', 'Image': 'sha256:old', 'Config': {'Cmd': []}}}
    monkeypatch.setattr(host, 'containers', lambda *_: objects)
    monkeypatch.setattr(host, 'active_command', lambda *_, **__: active)
    monkeypatch.setattr(host, 'worker_inventory', lambda *_: {})
    monkeypatch.setattr(host, 'build_contract', lambda *_, **__: ({}, {}))
    monkeypatch.setattr(host, 'hardware', lambda *_: {})
    monkeypatch.setattr(host, 'resource_check', lambda *_, **__: {'ok': True})
    monkeypatch.setattr(host, 'protected_hashes', lambda *_: {})
    monkeypatch.setattr(host, 'source_files', lambda *_: {})
    monkeypatch.setattr(host, 'site_overlay', lambda *_: {})
    monkeypatch.setattr(host, 'compose_environment', lambda *_: {})
    monkeypatch.setattr(host, 'inspect_prerequisites', lambda *_: {})
    monkeypatch.setattr(host, 'validate_rendered', lambda *_: {})
    monkeypatch.setattr(host.image_safety, 'infrastructure_images', lambda *_, **__: {})
    engine = Mock()
    engine.run.return_value = 'verified'
    engine.json.side_effect = lambda args, **_: [{'Id': 'sha256:candidate'}] if args[0] == 'image' else {'services': {}}
    workspace = Path(__file__).resolve().parents[1]
    before = host.snapshot(engine, workspace, state, 'candidate:verified')
    assert before['previous_compose_sha256'] == {str(base): hashlib.sha256(base.read_bytes()).hexdigest()}
    base.write_text('services: {changed: {}}')
    after = host.snapshot(engine, workspace, state, 'candidate:verified')
    assert before['fingerprint'] != after['fingerprint']
    assert str(state / 'runtime/site.json') not in before['previous_compose_sha256']
