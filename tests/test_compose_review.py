"""Adopt only the observed Portal/gateway drift; reject changes before activation."""
from copy import deepcopy
import json
import importlib.util
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from cloud_soc.deployment import compose_review as review
from cloud_soc.deployment.contract import SERVICES
from cloud_soc.deployment.host import _restore_execution, active_command
from cloud_soc.deployment.migrations import atomic_json


def fixture(tmp_path):
    state = tmp_path / 'state/server'
    runtime = state / 'runtime'
    runtime.mkdir(parents=True)
    base = tmp_path / 'deploy/compose.json'
    base.parent.mkdir()
    files = [base, runtime / 'site.json', tmp_path / 'external/ngrok.json', tmp_path / 'external/entry.json']
    files[2].parent.mkdir()
    for p in files:
        p.write_text('{"services":{}}')
    files[2].write_text(json.dumps({'services': {'portal': {'environment': {'SOC_PUBLIC_URL': 'https://portal.example'}},
                                               'gateway': {'environment': {'SOC_PORTAL_LAN_ORIGIN': 'https://portal.example'}}}}))
    files[3].write_text('{"services":{"portal":{"image":"portal:entry"}}}')
    (state / 'compose.env').write_text('SOC_TEST=value\n')
    atomic_json(runtime / 'compose.active.json', ['docker', 'compose', '--project-name', 'cloud-soc-central',
                                                '--env-file', str(state / 'compose.env'), '-f', str(files[0]), '-f', str(files[1])])
    objects = {}
    model = {'name': 'cloud-soc-central', 'services': {}, 'networks': {'default': {'name': 'cloud-soc-central_default'}}}
    for i, name in enumerate(SERVICES):
        count = 4 if name == 'portal' else 3 if name == 'gateway' else 2
        image = 'sha256:' + str(i % 10) * 64
        objects[name] = {'Id': name + '-id', 'Image': image, 'State': {'Running': True},
            'NetworkSettings': {'Networks': {'cloud-soc-central_default': {}}}, 'Config': {
            'Env': ['SOC_PUBLIC_URL=https://portal.example'] if name == 'portal' else [],
            'Labels': {'com.docker.compose.project': 'cloud-soc-central', 'com.docker.compose.service': name,
                       'com.docker.compose.project.working_dir': str(base.parent),
                       'com.docker.compose.project.config_files': ','.join(str(p) for p in files[:count]),
                       'com.docker.compose.config-hash': format(i, '064x')}}}
        model['services'][name] = {'image': name + ':old', 'networks': {'default': None},
                                   'environment': {'SOC_PUBLIC_URL': 'https://portal.example'} if name == 'portal' else {}}

    class Engine:
        def __init__(self):
            self.calls = []
            self.changed_hash = False
            self.changed_model = False
            self.changed_image = False

        def run(self, args, **kw):
            self.calls.append(args)
            if args[0] == 'compose' and '--hash' in args:
                return '\n'.join(n + ' ' + ('f'*64 if self.changed_hash and n == 'portal' else format(i, '064x'))
                                 for i, n in enumerate(SERVICES))
            raise AssertionError('No mutating Docker call expected: ' + repr(args))

        def json(self, args, **kw):
            self.calls.append(args)
            if args[:2] == ['image', 'inspect']:
                name = args[2].split(':')[0]
                return [{'Id': 'sha256:changed' if self.changed_image else objects[name]['Image']}]
            assert args[0] == 'compose' and 'config' in args
            names = [args[i+1] for i, v in enumerate(args[:-1]) if v == '-f']
            if len(names) == 1:
                return json.loads(Path(names[0]).read_text())
            result = deepcopy(model)
            if self.changed_model:
                result['services']['portal']['environment']['SOC_PUBLIC_URL'] = 'https://changed.example'
            return result

    return state, files, objects, model, Engine()


@pytest.fixture(autouse=True)
def portable_protection(monkeypatch):
    # Real mode/ownership enforcement is exercised by the Linux manual acceptance.
    original = review.regular
    monkeypatch.setattr(review, 'regular', lambda p, **kw: original(p, protected=False))
    monkeypatch.setattr(review, 'private_directory', lambda _: None)


def test_review_handles_two_three_four_file_labels_and_freezes_exact_images(tmp_path):
    state, files, objects, model, engine = fixture(tmp_path)
    previous = (state / 'runtime/compose.active.json').read_bytes()
    result = review.create(engine, state, files, objects)
    args, fingerprints = review.load(engine, state, result['review'], objects, 'cloud-soc-central')
    assert result['applied'] is False and result['services_stopped'] is False
    assert set(result['config_file_counts'].values()) == {2, 3, 4}
    frozen = json.loads(Path(args[args.index('-f')+1]).read_text())
    assert frozen == review.pin_images(model, review.observed(objects, list(map(str, files)), str(files[0].parent), 'cloud-soc-central'))
    assert len(fingerprints) == 2 and (state / 'runtime/compose.active.json').read_bytes() == previous
    assert all('up' not in call and 'stop' not in call for call in engine.calls)


@pytest.mark.parametrize('fault', ['source', 'receipt', 'container', 'hash', 'image', 'reference', 'frozen', 'foreign_project', 'file_order'])
def test_changed_review_cannot_be_used_for_plan_or_activation(tmp_path, fault):
    state, files, objects, _, engine = fixture(tmp_path)
    path = Path(review.create(engine, state, files, objects)['review'])
    if fault == 'source': files[2].write_text('{"services":{},"changed":true}')
    if fault == 'receipt': (state / 'runtime/compose.active.json').write_text('[]')
    if fault == 'container': objects['portal']['Id'] = 'replaced'
    if fault == 'hash': engine.changed_hash = True
    if fault == 'image': engine.changed_image = True
    if fault == 'reference': engine.changed_model = True
    if fault == 'frozen': (path.parent / 'compose.json').write_text('{"services":{}}')
    if fault == 'foreign_project': objects['gateway']['Config']['Labels']['com.docker.compose.project'] = 'other'
    if fault == 'file_order': objects['portal']['Config']['Labels']['com.docker.compose.project.config_files'] = ','.join(map(str, reversed(files)))
    before = len(engine.calls)
    with pytest.raises((review.ComposeReviewError, ValueError)):
        review.load(engine, state, path, objects, 'cloud-soc-central')
    assert all('up' not in call and 'stop' not in call for call in engine.calls[before:])


@pytest.mark.parametrize('fault', ['environment', 'mount', 'port', 'network', 'memory', 'command'])
def test_stale_labels_do_not_hide_actual_runtime_changes(tmp_path, fault):
    state, files, objects, model, engine = fixture(tmp_path)
    obj = objects['portal']
    if fault == 'environment': obj['Config']['Env'] = ['SOC_PUBLIC_URL=https://unexpected.example']
    if fault == 'mount': obj['Mounts'] = [{'Destination': '/extra', 'Type': 'bind', 'Source': '/unexpected', 'RW': True}]
    if fault == 'port': obj['HostConfig'] = {'PortBindings': {'80/tcp': [{'HostIp': '0.0.0.0', 'HostPort': '8080'}]}}
    if fault == 'network': obj['NetworkSettings']['Networks']['unexpected'] = {}
    if fault == 'memory':
        model['services']['portal']['mem_limit'] = 1234
        obj['HostConfig'] = {'Memory': 5678}
    if fault == 'command':
        model['services']['portal']['command'] = ['python', 'portal.py']
        obj['Config']['Cmd'] = ['python', 'unexpected.py']
    with pytest.raises(review.ComposeReviewError): review.create(engine, state, files, objects)
    assert all('up' not in call and 'stop' not in call for call in engine.calls)


@pytest.mark.parametrize('override', [
    {'services': {'portal': {'command': ['unsafe']}}},
    {'services': {'gateway': {'ports': ['0.0.0.0:8080:80']}}},
    {'services': {'detector': {'image': 'other:version'}}},
    {'services': {'portal': {'environment': {'PRIVATE_PASSWORD': 'SENSITIVE_CANARY'}}}},
    {'services': {'gateway': {'image': 'other:version'}}},
    {'include': ['other.json'], 'services': {}},
])
def test_scope_cannot_expand_through_external_overrides(tmp_path, override):
    state, files, objects, _, engine = fixture(tmp_path)
    files[2].write_text(json.dumps(override))
    with pytest.raises(review.ComposeReviewError) as error:
        review.create(engine, state, files, objects)
    assert 'SENSITIVE_CANARY' not in str(error.value) and not engine.calls


def test_original_unreviewed_external_receipt_still_refused(tmp_path):
    state, _, objects, _, _ = fixture(tmp_path)
    with pytest.raises(review.ComposeReviewError, match='review-compose'):
        active_command(state, objects)


@pytest.mark.parametrize('fault', ['none', 'other_release', 'extra_file', 'reversed'])
def test_canonical_external_release_is_limited_to_explicit_workspace(tmp_path, fault):
    state = tmp_path / 'checkout/state/server'
    (state / 'runtime').mkdir(parents=True)
    workspace = tmp_path / 'reviewed-release'
    base = workspace / 'deploy/server/compose.yaml'
    base.parent.mkdir(parents=True)
    base.write_text('services: {}')
    site = state / 'runtime/site.json'
    site.write_text('{"services":{}}')
    files = [str(base), str(site)]
    if fault == 'extra_file':
        extra = workspace / 'external.json'
        extra.write_text('{"services":{}}')
        files.append(str(extra))
    if fault == 'reversed': files.reverse()
    args = ['--project-name', 'cloud-soc-central', '-f', files[0]]
    for name in files[1:]: args += ['-f', name]
    atomic_json(state / 'runtime/compose.active.json', ['docker', 'compose', *args])
    objects = {'portal': {'Config': {'Labels': {'com.docker.compose.project.config_files': ','.join(files)}}}}
    selected = tmp_path / 'different-release' if fault == 'other_release' else workspace
    if fault == 'none':
        assert active_command(state, objects, workspace=selected) == args
    else:
        with pytest.raises(ValueError, match='approved root'):
            active_command(state, objects, workspace=selected)


@pytest.mark.parametrize('fault', ['none', 'base_changed', 'missing_run', 'different_current',
                                    'wrong_image', 'source_manifest', 'wrong_state', 'extra_file',
                                    'different_command', 'unprotected_receipt'])
def test_next_workspace_requires_protected_successful_previous_release(tmp_path, monkeypatch, fault):
    import hashlib
    from cloud_soc.deployment.contract import digest
    state = tmp_path / 'checkout/state/server'
    runtime = state / 'runtime'
    run = runtime / 'upgrades/accepted'
    run.mkdir(parents=True)
    old = tmp_path / 'previous-release'
    base = old / 'deploy/server/compose.yaml'
    base.parent.mkdir(parents=True)
    base.write_text('services: {}')
    site = runtime / 'site.json'
    site.write_text('{}')
    source = {'deploy/server/compose.yaml': hashlib.sha256(base.read_bytes()).hexdigest()}
    current = {'runtime_ready': True, 'image_id': 'sha256:accepted', 'source_sha256': digest(source)}
    args = ['--project-name', 'cloud-soc-central', '--env-file', str(state / 'compose.env'),
            '-f', str(base), '-f', str(site)]
    command = ['docker', 'compose', *args]
    atomic_json(runtime / 'current.json', current)
    atomic_json(run / 'applied.json', current)
    plan = {'workspace': str(old), 'state': str(state), 'project': 'cloud-soc-central',
            'image_id': current['image_id'], 'source_sha256': digest(source), 'source': source}
    if fault == 'source_manifest': plan['source']['deploy/server/compose.yaml'] = '0'*64
    if fault == 'wrong_state': plan['state'] = str(tmp_path / 'other-state')
    atomic_json(run / 'plan.json', plan)
    saved = {'canonical': ['compose', *args]}
    if fault == 'different_command': saved['canonical'] += ['--profile', 'unexpected']
    atomic_json(run / 'recovery.json', saved)
    if fault == 'base_changed': base.write_text('services: {unexpected: {}}')
    if fault == 'missing_run': (run / 'applied.json').unlink()
    if fault == 'different_current': atomic_json(runtime / 'current.json', {**current, 'utc': 'different'})
    if fault == 'extra_file': command += ['-f', str(old / 'extra.json')]
    atomic_json(runtime / 'compose.active.json', command)
    names = [command[i+1] for i, v in enumerate(command[:-1]) if v == '-f']
    objects = {'portal': {'Image': 'sha256:other' if fault == 'wrong_image' else current['image_id'],
                          'Config': {'Labels': {'com.docker.compose.project.config_files': ','.join(names)}}}}
    if fault == 'unprotected_receipt':
        regular = review.regular
        def refuse(path, **kwargs):
            if Path(path) == runtime / 'compose.active.json' and kwargs.get('protected'):
                raise review.ComposeReviewError('unprotected receipt')
            return regular(path, **kwargs)
        monkeypatch.setattr(review, 'regular', refuse)
    if fault == 'none':
        assert active_command(state, objects, workspace=tmp_path / 'new-release') == args
    else:
        with pytest.raises(ValueError):
            active_command(state, objects, workspace=tmp_path / 'new-release')


@pytest.mark.parametrize('fault', ['port', 'mount', 'origin'])
def test_new_plan_must_preserve_existing_site_settings(tmp_path, fault):
    _, _, objects, old, _ = fixture(tmp_path)
    old['services']['gateway']['ports'] = [{'target': 443, 'published': '443', 'host_ip': '127.0.0.1'}]
    old['services']['portal']['volumes'] = [{'target': '/data', 'source': '/protected/portal', 'type': 'bind'}]
    desired = deepcopy(old)
    if fault == 'port': desired['services']['gateway']['ports'][0]['host_ip'] = '0.0.0.0'
    if fault == 'mount': desired['services']['portal']['volumes'][0]['source'] = '/new-data'
    if fault == 'origin': desired['services']['portal']['environment']['SOC_PUBLIC_URL'] = 'https://changed.example'
    with pytest.raises(review.ComposeReviewError): review.preserved_site(old, desired, objects)


def test_modified_recovery_copy_refused_before_stopping_services(tmp_path):
    runtime = tmp_path / 'runtime'
    folder = runtime / 'compose-reviews/test'
    folder.mkdir(parents=True)
    copy = folder / 'compose.json'
    copy.write_text('{}')
    saved = {'previous_compose': [], 'reviewed_compose_files': {str(copy): '0'*64}}
    with pytest.raises(ValueError, match='recovery configuration changed'):
        _restore_execution(None, runtime, tmp_path, saved)


def test_symbolic_configuration_paths_are_not_adopted(tmp_path):
    state, files, objects, _, engine = fixture(tmp_path)
    linked = tmp_path / 'linked.json'
    try: linked.symlink_to(files[2])
    except OSError: pytest.skip('Symlink creation unavailable')
    files[2] = linked
    with pytest.raises(review.ComposeReviewError): review.create(engine, state, files, objects)


def test_apply_revalidates_explicit_review_before_any_service_change(tmp_path, monkeypatch):
    from contextlib import nullcontext
    from cloud_soc.deployment import host
    state = tmp_path / 'state'
    state.mkdir()
    snapshot = Mock(side_effect=review.ComposeReviewError('검토 후 설정 변경'))
    monkeypatch.setattr(host, 'snapshot', snapshot)
    monkeypatch.setattr(host, 'lock', lambda _: nullcontext())
    plan = {'state': str(state), 'workspace': str(tmp_path), 'image': 'candidate:local',
            'project': 'cloud-soc-central', 'resources': {'ok': True}, 'compose_review': '/protected/review.json'}
    engine = Mock()
    with pytest.raises(review.ComposeReviewError): host.apply(engine, plan)
    snapshot.assert_called_once_with(engine, tmp_path, state, 'candidate:local', 'cloud-soc-central',
                                     compose_review='/protected/review.json')
    assert not engine.mock_calls


def manage_module(monkeypatch, args):
    import sys
    source = Path(__file__).resolve().parents[1] / 'deploy/server/manage.py'
    spec = importlib.util.spec_from_file_location('review_manage_test', source)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.setattr(module, 'os', SimpleNamespace(name='posix', geteuid=lambda: 0))
    monkeypatch.setattr(sys, 'argv', ['manage.py', *args])
    return module


def test_cli_plan_passes_review_and_does_not_apply(tmp_path, monkeypatch):
    state, _, _, _, _ = fixture(tmp_path)
    module = manage_module(monkeypatch, ['plan', '--state', str(state), '--compose-review', '/protected/review.json'])
    snapshot = Mock(return_value={'resources': {'ok': True}})
    monkeypatch.setattr(module, 'snapshot', snapshot)
    monkeypatch.setattr(module, 'summary', lambda _: {'plan_ready': True})
    engine = Mock()
    monkeypatch.setattr(module, 'Docker', lambda: engine)
    assert module.main() == 0
    assert snapshot.call_args.kwargs == {'compose_review': Path('/protected/review.json')}
    assert not engine.mock_calls and (state / 'runtime-plan.json').exists()


def test_cli_cannot_use_review_option_to_bypass_another_action(tmp_path, monkeypatch):
    module = manage_module(monkeypatch, ['install', '--state', str(tmp_path), '--compose-review', '/protected/review.json'])
    with pytest.raises(ValueError, match='do not apply'): module.main()


def test_cli_review_creates_only_private_review_not_active_receipt(tmp_path, monkeypatch, capsys):
    from contextlib import nullcontext
    from cloud_soc.deployment import host
    state, files, objects, _, engine = fixture(tmp_path)
    args = ['review-compose', '--state', str(state)]
    for p in files: args += ['--compose-file', str(p)]
    module = manage_module(monkeypatch, args)
    monkeypatch.setattr(module, 'Docker', lambda: engine)
    monkeypatch.setattr(module, 'containers', lambda *_: objects)
    monkeypatch.setattr(host, 'lock', lambda _: nullcontext())
    receipt = (state / 'runtime/compose.active.json').read_bytes()
    assert module.main() == 0
    output = json.loads(capsys.readouterr().out)
    assert Path(output['review']).is_file() and not output['applied'] and not output['services_stopped']
    assert (state / 'runtime/compose.active.json').read_bytes() == receipt


def test_missing_previous_image_stops_recovery_before_any_service_change(tmp_path):
    engine = Mock()
    engine.json.return_value = [{'Id': 'sha256:different'}]
    with pytest.raises(ValueError, match='not available locally'):
        _restore_execution(engine, tmp_path, tmp_path, {'previous_compose': [], 'previous_images': ['sha256:original']})
    engine.run.assert_not_called()


def test_runtime_memory_numeric_string_and_readonly_secret_mount(tmp_path):
    _, _, objects, model, _ = fixture(tmp_path)
    model['secrets'] = {'fixture': {'file': '/protected/fixture'}}
    model['services']['portal'].update(mem_limit='1234', read_only=True, secrets=[{'source': 'fixture', 'target': 'fixture'}])
    objects['portal']['HostConfig'] = {'Memory': 1234, 'ReadonlyRootfs': True}
    objects['portal']['Mounts'] = [{'Type': 'bind', 'Destination': '/run/secrets/fixture', 'Source': '/protected/fixture', 'RW': False}]
    review.verify_runtime(model, objects)
    objects['portal']['Mounts'][0]['RW'] = True
    with pytest.raises(review.ComposeReviewError): review.verify_runtime(model, objects)
