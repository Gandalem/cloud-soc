"""7-C: real engine snapshots, existing detail route, no live ES or deployment."""
from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from cloud_soc.correlation.security_mall import Scope
from cloud_soc.correlation.store import CorrelationStore
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.portal.mall_investigation import MallInvestigation
from cloud_soc.portal import mall_investigation as module
from cloud_soc.triage.store import TriageStore
from test_security_mall_portal import SCOPE, dataset, portal as portal_fixture
from test_integration_security import login

START, END = '2026-10-01T00:00:00Z', '2026-10-02T00:00:00Z'
PRINCIPAL = LogPrincipal('view', 'viewer', ('synthetic',), ())
portal = portal_fixture


@pytest.fixture
def snapshot(tmp_path):
    tmp_path.chmod(0o700)
    data, access, _ = dataset()
    source = data[SCOPE['alerts'], access]
    ref = source['cloud_soc']['provenance']['evidence'][0]['normalized']
    event = data[ref['index'], ref['id']]
    scope = Scope('synthetic', 'shop-lab', event['host']['id'], 'security-mall',
        (SCOPE['normalized'],), (SCOPE['raw'],), ('soc-host-raw-mall-edge-fixture',), (SCOPE['alerts'],))
    ledger = CorrelationStore(tmp_path / 'correlation.sqlite', scope)
    ledger.ingest([{'_index': ref['index'], '_id': ref['id'], '_source': event}],
                  [{'_index': SCOPE['alerts'], '_id': access, '_source': source}])
    path = tmp_path / 'triage.sqlite'
    store = TriageStore(path, scope)
    store.replace(ledger.snapshot(PRINCIPAL), START, END)
    config = {'database': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest(),
              'scope': json.loads(json.dumps(asdict(scope))), 'start': START, 'end': END}
    return config, data, access


@pytest.fixture
def connected(snapshot, monkeypatch, request):
    config, data, access = snapshot
    reader = MallInvestigation(config, SCOPE)
    monkeypatch.setattr(MallInvestigation, 'from_file', lambda *_: reader)
    return request.getfixturevalue('portal')


def test_detail_uses_existing_api_and_keeps_risk_evidence_private(connected, snapshot):
    app, es, data, access, _ = connected
    before = deepcopy(data)
    path = Path(snapshot[0]['database']); digest = hashlib.sha256(path.read_bytes()).hexdigest()
    http, _ = login(app, 'view')
    body = http.get('/api/alerts/detail?id=' + access).json
    assert body['risk']['score'] == 20 and body['risk']['level'] == 'low'
    assert body['alert']['severity'] == 'low'
    triage = body['investigation']
    assert (triage['state'], triage['triage_score'], triage['triage_priority']) == ('available', 20, 'low')
    assert triage['evidence_confidence'] == 'limited' and triage['completeness'] == 'partial'
    assert triage['streams'] == {'app': 'observed', 'web': 'unconfirmed', 'waf': 'unconfirmed'}
    assert triage['event_count'] == triage['evidence_count'] == triage['verified_alert_references'] == 1
    assert not {'evidence_references', 'account_id', 'source_ip', 'linked_request_ids'} & triage.keys()
    assert 'PRIVATE_CANARY' not in json.dumps(body)
    assert data == before and hashlib.sha256(path.read_bytes()).hexdigest() == digest
    assert not any(c[0] in ('index', 'bulk', 'update', 'delete') for c in es.method_calls)


def test_foreign_org_and_parameter_tampering_do_not_disclose(connected):
    app, _, _, access, _ = connected
    http, _ = login(app, 'other')
    denied = http.get('/api/alerts/detail?id=' + access)
    missing = http.get('/api/alerts/detail?id=missing')
    assert denied.status_code == missing.status_code == 404 and denied.json == missing.json
    for arg in ('organization=synthetic', 'index=' + SCOPE['alerts'], 'snapshot=/tmp/other'):
        assert http.get('/api/alerts/detail?id=' + access + '&' + arg).status_code == 400


def test_triage_does_not_grant_protected_raw_access(connected):
    app, _, data, access, _ = connected
    http, headers = login(app, 'view')
    ref = data[SCOPE['alerts'], access]['cloud_soc']['provenance']['evidence'][0]['raw']
    assert http.post('/api/logs/source', json=dict(ref, purpose='investigation'), headers=headers).status_code == 403
    assert http.get('/api/alerts/detail?id=' + access).json['investigation']['state'] == 'available'


@pytest.mark.parametrize('mutation', ['hash', 'raw_org', 'normalized_org', 'risk', 'severity', 'alert_ref'])
def test_changed_evidence_or_alert_does_not_show_stale_analysis(connected, mutation):
    app, _, data, access, _ = connected
    source = data[SCOPE['alerts'], access]
    ref = source['cloud_soc']['provenance']['evidence'][0]
    if mutation == 'hash':
        data[ref['normalized']['index'], ref['normalized']['id']]['event']['outcome'] = 'success'
    elif mutation.endswith('_org'):
        locator = ref['raw' if mutation == 'raw_org' else 'normalized']
        data[locator['index'], locator['id']]['organization']['id'] = 'foreign'
    elif mutation == 'alert_ref':
        ref['event_hash'] = 'a' * 64
    else:
        source['cloud_soc']['risk_score' if mutation == 'risk' else 'severity'] = 99 if mutation == 'risk' else 'high'
    http, _ = login(app, 'view')
    response = http.get('/api/alerts/detail?id=' + access)
    assert response.status_code == 200
    assert response.json['investigation']['state'] != 'available'
    assert 'triage_score' not in response.json['investigation']


def test_absent_snapshot_preserves_existing_detail(portal):
    app, _, _, access, _ = portal
    http, _ = login(app, 'view')
    body = http.get('/api/alerts/detail?id=' + access + '&evidence=0').json
    assert body['investigation'] == {'state': 'unavailable'}
    assert body['evidence']['integrity'] == 'normalized_hash_verified'


@pytest.mark.parametrize('change', ['organization', 'site', 'host', 'service', 'digest', 'missing', 'symlink', 'hardlink', 'range'])
def test_snapshot_binding_and_file_fail_closed(snapshot, tmp_path, change):
    config = deepcopy(snapshot[0])
    if change in ('organization', 'site', 'host', 'service'):
        config['scope'][change] = 'other'
    elif change == 'digest':
        config['sha256'] = '0' * 64
    elif change == 'range':
        config['end'] = '2026-10-03T00:00:00Z'
    elif change == 'missing':
        config['database'] += '.missing'
    else:
        link = tmp_path / 'alias.sqlite'
        if change == 'hardlink':
            os.link(config['database'], link)
        else:
            try:
                link.symlink_to(config['database'])
            except OSError:
                pytest.skip('OS does not permit symlink creation')
        config['database'] = str(link)
    with pytest.raises((ValueError, OSError)):
        MallInvestigation(config, SCOPE)


def test_config_file_readonly_and_foreign_principal(snapshot, tmp_path):
    config, data, access = snapshot
    path = tmp_path / 'snapshot.json'
    path.write_text(json.dumps(config));path.chmod(0o600)
    reader = MallInvestigation.from_file(str(path), SCOPE)
    foreign = LogPrincipal('other', 'admin', ('foreign',), ('synthetic',))
    assert reader.detail(foreign, SCOPE['alerts'], access, data[SCOPE['alerts'], access],
                         lambda _: pytest.fail('foreign evidence read')) == {'state': 'unavailable'}
    assert not (tmp_path / 'triage.sqlite-wal').exists()


def test_wrong_private_permissions_rejected(snapshot, tmp_path):
    if os.name != 'posix':
        pytest.skip('POSIX ownership/mode enforcement; Windows relies on private ACL')
    Path(snapshot[0]['database']).chmod(0o644)
    with pytest.raises(ValueError):
        MallInvestigation(snapshot[0], SCOPE)


@pytest.mark.parametrize('owner,mode', [(1, 0o600), (0, 0o644)])
def test_posix_permission_guard_on_windows_too(snapshot, monkeypatch, owner, mode):
    path = Path(snapshot[0]['database'])
    real_stat = Path.stat
    def metadata(value, **kwargs):
        info = real_stat(value, **kwargs)
        if value in (path, path.parent):
            return SimpleNamespace(st_uid=owner, st_mode=mode)
        return info
    monkeypatch.setattr(Path, 'stat', metadata)
    monkeypatch.setattr(module, 'os', SimpleNamespace(**{**os.__dict__, 'name': 'posix', 'getuid': lambda: 0}))
    with pytest.raises(ValueError, match='snapshot_private_required'):
        module.private_bytes(path, 32 * 1024 * 1024)


def test_corrupt_config_keeps_existing_api(monkeypatch, request):
    def invalid(*_):
        raise ValueError('PRIVATE_CANARY')
    monkeypatch.setattr(MallInvestigation, 'from_file', invalid)
    app, _, _, access, _ = request.getfixturevalue('portal')
    http, _ = login(app, 'view')
    response = http.get('/api/alerts/detail?id=' + access)
    assert response.status_code == 200 and response.json['investigation'] == {'state': 'unavailable'}
    assert 'PRIVATE_CANARY' not in response.text


def test_no_matching_alert_and_metadata_text_not_forwarded(snapshot):
    config, data, access = snapshot
    reader = MallInvestigation(config, SCOPE)
    source = data[SCOPE['alerts'], access]
    assert reader.detail(PRINCIPAL, SCOPE['alerts'], 'unknown', source, lambda _: True) == {'state': 'not_found'}
    row = next(i for i in reader.frame['items'] if i['linked_alert_ids'])
    row['explanation'] = row['account_id'] = 'PRIVATE_CANARY'
    result = reader.detail(PRINCIPAL, SCOPE['alerts'], access, source, lambda _: True)
    assert result['state'] == 'available' and 'PRIVATE_CANARY' not in json.dumps(result)


def test_unsupported_sqlite_build_fails_safely(snapshot, monkeypatch):
    monkeypatch.setattr(module.sqlite3, 'connect', lambda *_: SimpleNamespace(close=lambda: None))
    with pytest.raises(ValueError, match='snapshot_sqlite_deserialize_required'):
        MallInvestigation(snapshot[0], SCOPE)
