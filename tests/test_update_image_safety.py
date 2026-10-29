"""Independent failure fixtures for pre-stop image and storage boundaries."""
from copy import deepcopy
import importlib.util
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from cloud_soc.deployment import downloads, host, image_safety as safety
from cloud_soc.deployment.contract import policy

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('image_safety_manage', ROOT / 'deploy/server/manage.py')
manage = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manage)


@pytest.mark.parametrize('purpose,key', [('build', 'upgrade_free_bytes'), ('download', 'fresh_free_bytes'),
                                        ('reserve', 'headroom_bytes')])
def test_storage_budget_uses_actual_docker_filesystem_and_boundary(purpose, key):
    engine = Mock()
    engine.json.return_value = {'OSType': 'linux', 'DockerRootDir': '/synthetic/docker-volume'}
    required = policy(ROOT)['resources'][key]
    if purpose == 'build':
        required += policy(ROOT)['resources']['headroom_bytes']
    with patch.object(safety.shutil, 'disk_usage', return_value=SimpleNamespace(free=required - 1)) as disk:
        with pytest.raises(safety.DeploymentSafetyError, match='공간'):
            safety.check_disk_budget(engine, ROOT, purpose)
        disk.assert_called_once_with('/synthetic/docker-volume')
    with patch.object(safety.shutil, 'disk_usage', return_value=SimpleNamespace(free=required)):
        assert safety.check_disk_budget(engine, ROOT, purpose)['required_bytes'] == required
    engine.run.assert_not_called()


def test_build_low_space_or_unknown_storage_never_pulls_or_builds():
    engine = Mock()
    for info in ({'OSType': 'linux', 'DockerRootDir': '/synthetic/docker'}, {'OSType': 'windows'}):
        engine.json.return_value = info
        with patch.object(safety.shutil, 'disk_usage', return_value=SimpleNamespace(free=0)):
            with pytest.raises(safety.DeploymentSafetyError):
                downloads.build_runtime_image(engine, ROOT, 'fixture:never-built')
        engine.run.assert_not_called()


def test_space_loss_before_retry_prevents_second_build():
    engine = Mock()
    engine.run.side_effect = ['cached', host.DockerCommandError(['build'], timed_out=True)]
    with patch.object(downloads, 'check_disk_budget', side_effect=[None, None, safety.DeploymentSafetyError('空间')]), \
            patch.object(downloads.time, 'sleep'), patch.object(downloads, 'retain_images'):
        with pytest.raises(safety.DeploymentSafetyError):
            downloads.build_runtime_image(engine, ROOT, 'fixture:never-built')
    assert [c.args[0][0] for c in engine.run.call_args_list] == ['image', 'build']


def test_missing_infrastructure_blocks_plan_preflight_without_mutation():
    rendered = {'services': {n: {'image': 'fixture:' + n} for n in safety.INFRASTRUCTURE}}
    engine = Mock()
    engine.json.side_effect = host.DockerCommandError(['image', 'inspect'], stderr='No such image: synthetic')
    with pytest.raises(safety.DeploymentSafetyError, match='prepare-images'):
        safety.infrastructure_images(engine, rendered)
    engine.run.assert_not_called()
    engine.json.side_effect = host.DockerCommandError(['image', 'inspect'], stderr='permission denied PRIVATE')
    with pytest.raises(host.DockerCommandError):
        safety.infrastructure_images(engine, rendered, allow_missing=True)


def test_missing_download_budget_blocks_prepare_but_cached_images_need_no_budget():
    engine = Mock()
    rows = {n: {'image_id': None} for n in safety.INFRASTRUCTURE}
    with patch.object(safety, 'infrastructure_images', return_value=rows), \
            patch.object(safety, 'check_disk_budget', side_effect=safety.DeploymentSafetyError('disk')):
        with pytest.raises(safety.DeploymentSafetyError):
            manage.prepare_install_images(engine, ROOT, ROOT / 'state/server', {})
    engine.run.assert_not_called()
    for row in rows.values():
        row['image_id'] = 'sha256:cached'
    with patch.object(safety, 'infrastructure_images', return_value=rows), \
            patch.object(safety, 'check_disk_budget') as disk:
        manage.prepare_install_images(engine, ROOT, ROOT / 'state/server', {})
    disk.assert_not_called()
    assert all(c.args[0][-4:-1] == ['pull', '--policy', 'missing'] for c in engine.run.call_args_list)


@pytest.mark.parametrize('wrong_image', [False, True])
def test_rollback_uses_observed_image_not_reused_tag_and_verifies_restoration(tmp_path, monkeypatch, wrong_image):
    runtime = tmp_path / 'runtime'
    run = runtime / 'upgrades/fixture'
    run.mkdir(parents=True)
    site = runtime / 'site.json'
    original = {'services': {'portal': {'image': 'fixture:reused', 'environment': {'SITE': 'keep'}}}}
    site.write_text(json.dumps(original))
    backup = host.save_previous_site(runtime, run)
    site.write_text('{"services":{"portal":{"image":"sha256:new"}}}')
    saved = {'previous_compose': ['--project-name', 'cloud-soc-central', '-f', str(site)],
             'canonical': ['compose', '--project-name', 'cloud-soc-central'],
             'old_names': ['portal'], 'image_pins': {'portal': 'sha256:old'}, 'image_mode': 'site',
             'old_site': backup, 'old_contract': None, 'old_current': None}
    engine = Mock()
    engine.json.side_effect = lambda args, **kw: [{'Id': 'sha256:new' if args[-1] == 'fixture:reused' else args[-1]}]
    actual = {'portal': {'Image': 'sha256:new' if wrong_image else 'sha256:old', 'State': {'Running': True}}}
    monkeypatch.setattr(host, 'containers', lambda *_: actual)
    if wrong_image:
        with pytest.raises(safety.DeploymentSafetyError, match='복구'):
            host._restore_execution(engine, runtime, run, saved)
        assert not (runtime / 'compose.active.json').exists()
    else:
        host._restore_execution(engine, runtime, run, saved)
    expected = deepcopy(original)
    expected['services']['portal']['image'] = 'sha256:old'
    assert json.loads(site.read_text()) == expected
    assert json.loads((run / 'site.before.json').read_text()) == original
    assert all(c.args[0] != ['image', 'inspect', 'fixture:reused'] for c in engine.json.call_args_list)


def test_legacy_journal_without_image_evidence_retains_pending_before_stop(tmp_path, monkeypatch):
    runtime = tmp_path / 'runtime'
    run = runtime / 'upgrades/fixture'
    run.mkdir(parents=True)
    pending = runtime / 'pending.json'
    pending.write_text(json.dumps({'run': str(run)}))
    (run / 'plan.json').write_text('{"observed":{}}')
    (run / 'recovery.json').write_text(json.dumps({'previous_compose': ['-f', 'legacy.yml'], 'old_names': ['portal']}))
    engine = Mock()
    from contextlib import nullcontext
    monkeypatch.setattr(host, 'lock', lambda _: nullcontext())
    with pytest.raises(safety.DeploymentSafetyError):
        host.recover(engine, tmp_path)
    assert pending.exists()
    engine.run.assert_not_called()


def test_activation_overlay_pins_app_bootstrap_and_infrastructure_without_losing_site(tmp_path):
    plan = {'image': 'fixture:mutable', 'image_id': 'sha256:new',
            'site': {'services': {'gateway': {'environment': {'HOST': 'keep'}}}},
            'infrastructure_images': {'gateway': {'reference': 'fixture:gateway', 'image_id': 'sha256:gateway'}}}
    result = host.configure_site(plan, tmp_path)
    assert all(result['services'][name]['image'] == 'sha256:new' for name in (*host.APP_SERVICES, 'bootstrap'))
    assert result['services']['gateway'] == {'image': 'sha256:gateway', 'environment': {'HOST': 'keep'}}
    assert plan['site']['services']['gateway'] == {'environment': {'HOST': 'keep'}}


def test_unpinnable_legacy_configuration_refused_and_frozen_digest_verified(tmp_path):
    engine = Mock()
    objects = {'portal': {'Image': 'sha256:old'}}
    with pytest.raises(safety.DeploymentSafetyError):
        safety.recovery_mode(engine, tmp_path, ['-f', '/legacy.yml'], objects,
                             {'services': {'portal': {'image': 'fixture:mutable'}}})
    engine.json.return_value = [{'Id': 'sha256:old'}]
    assert safety.recovery_mode(engine, tmp_path, ['-f', '/frozen.yml'], objects,
                                {'services': {'portal': {'image': 'sha256:old'}}}) == 'immutable'
    engine.run.assert_not_called()


def test_build_preserves_last_reference_before_tag_reuse_and_reuses_retention(monkeypatch):
    identity = 'sha256:' + 'a' * 64
    reference = 'cloud-soc-recovery:' + 'a' * 64
    monkeypatch.setattr(host, 'containers', lambda *_: {'portal': {'Image': identity}, 'detector': {'Image': identity}})
    engine = Mock()
    def lookup(args):
        if args[-1] == reference:
            raise host.DockerCommandError(args, stderr='No such image: synthetic')
        return [{'Id': identity}]
    engine.json.side_effect = lookup
    safety.retain_images(engine)
    engine.run.assert_called_once_with(['image', 'tag', identity, reference])
    engine.reset_mock()
    engine.json.side_effect = lambda _: [{'Id': identity}]
    safety.retain_images(engine)
    engine.run.assert_not_called()
