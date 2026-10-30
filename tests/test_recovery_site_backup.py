"""Pre-stop site backup checks and restoration of the bytes actually validated."""
import hashlib
import json

import pytest

from cloud_soc.deployment import host
from test_recovery_compose_files import interrupted as interrupted


@pytest.mark.parametrize('fault', [
    'changed', 'missing', 'directory', 'symlink', 'broken_json', 'utf8', 'utf16',
    'list_root', 'null_root', 'services_list', 'service_scalar', 'duplicate', 'nan',
    'missing_uid', 'boolean_uid', 'oversized_gid', 'bad_checksum',
])
def test_invalid_backup_is_refused_before_stop_and_preserves_evidence(interrupted, fault):
    state, runtime, run, _, saved, engine = interrupted
    backup = run / 'site.before.json'
    replacements = {
        'broken_json': b'{"services":', 'utf8': b'\xff', 'utf16': '{}'.encode('utf-16'),
        'list_root': b'[]', 'null_root': b'null', 'services_list': b'{"services":[]}',
        'service_scalar': b'{"services":{"portal":null}}',
        'duplicate': b'{"services":{},"services":{"portal":{}}}',
        'nan': b'{"services":{"portal":{"environment":{"UNSAFE":NaN}}}}',
    }
    if fault in replacements:
        backup.write_bytes(replacements[fault])
        # Separate format validation from checksum validation.
        saved['old_site']['sha256'] = hashlib.sha256(backup.read_bytes()).hexdigest()
    elif fault == 'changed':
        backup.write_bytes(b'{"services":{"unreviewed":{}}}')
    elif fault == 'missing':
        backup.unlink()
    elif fault == 'directory':
        backup.unlink();backup.mkdir()
    elif fault == 'symlink':
        original = backup.with_name('original.json')
        backup.rename(original)
        try:
            backup.symlink_to(original)
        except OSError:
            pytest.skip('Symlink creation unavailable')
    elif fault == 'missing_uid':
        saved['old_site'].pop('uid')
    elif fault == 'boolean_uid':
        saved['old_site']['uid'] = True
    elif fault == 'oversized_gid':
        saved['old_site']['gid'] = 2**40
    else:
        saved['old_site']['sha256'] = 'not-a-checksum'
    (run / 'recovery.json').write_text(json.dumps(saved))
    before = {path: path.read_bytes() for path in (
        runtime / 'site.json', runtime / 'pending.json', run / 'recovery.json')}
    with pytest.raises(ValueError):
        host.recover(engine, state)
    engine.run.assert_not_called()
    assert all(path.read_bytes() == body for path, body in before.items())
    assert not (run / 'recovered.json').exists()
    assert not (runtime / 'compose.active.json').exists()


def test_backup_is_checked_after_inspection_before_stop(interrupted, monkeypatch):
    state, runtime, run, _, _, engine = interrupted
    def inspect(*_):
        (run / 'site.before.json').write_bytes(b'{"unreviewed":true}')
        return {'portal': {'Image': 'sha256:old', 'State': {'Running': True}}}
    monkeypatch.setattr(host, 'containers', inspect)
    with pytest.raises(ValueError, match='backup changed'):
        host.recover(engine, state)
    engine.run.assert_not_called()
    assert (runtime / 'pending.json').exists()


@pytest.mark.parametrize('after_stop', ['changed', 'removed'])
def test_restore_uses_validated_bytes_even_if_backup_changes_after_stop(interrupted, after_stop):
    state, runtime, run, _, _, engine = interrupted
    backup = run / 'site.before.json'
    original = json.loads(backup.read_text())
    calls = []
    def execute(args, **_):
        calls.append(args)
        if args[0] == 'stop':
            if after_stop == 'changed':
                backup.write_bytes(b'{"services":{"unreviewed":{}}}')
            else:
                backup.unlink()
        elif 'up' in args:
            restored = json.loads((runtime / 'site.json').read_text())
            assert restored['services']['portal']['environment'] == original['services']['portal']['environment']
            assert restored['services']['portal']['image'] == 'sha256:old'
            assert 'unreviewed' not in restored['services']
    engine.run.side_effect = execute
    assert host.recover(engine, state)['old_execution_restored']
    assert calls[0][0] == 'stop' and 'up' in calls[-1]
    assert not (runtime / 'pending.json').exists()


def test_validated_snapshot_restores_exact_bytes_and_mode(interrupted):
    _, runtime, run, _, saved, _ = interrupted
    backup = run / 'site.before.json'
    original = backup.read_bytes()
    mode = backup.stat().st_mode & 0o777
    verified = host.validate_previous_site(runtime, run, saved['old_site'])
    backup.unlink()
    host.restore_previous_site(runtime, run, saved['old_site'], verified)
    assert (runtime / 'site.json').read_bytes() == original
    assert (runtime / 'site.json').stat().st_mode & 0o777 == mode


def test_utf8_site_values_survive_validation_and_image_pinning(interrupted):
    state, runtime, run, _, saved, engine = interrupted
    content = json.dumps({'services': {'portal': {'environment': {'TITLE': '운영 포털'}}}}, ensure_ascii=False).encode('utf-8')
    (run / 'site.before.json').write_bytes(content)
    saved['old_site']['sha256'] = hashlib.sha256(content).hexdigest()
    (run / 'recovery.json').write_text(json.dumps(saved))
    assert host.recover(engine, state)['old_execution_restored']
    site = json.loads((runtime / 'site.json').read_text(encoding='utf-8'))
    assert site['services']['portal'] == {'environment': {'TITLE': '운영 포털'}, 'image': 'sha256:old'}
