"""Fast rules: real normalizer/engine/SQLite, synthetic remote HTTP contract."""
from copy import deepcopy
from datetime import timedelta
from unittest.mock import Mock

from elasticsearch import ConflictError, NotFoundError
import pytest

from cloud_soc.detection.authoring import example
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.detection.managed import ManagedWorker, configuration
from cloud_soc.portal.rule_library import RuleLibrary, aware
from security_mall_fixtures import BASE, mall
from test_generic_waf import normalized as waf_normalized, BASE as WAF_BASE
from test_pipeline_reliability import api_error
from test_rule_library import ADMIN, action


class Remote:
    def __init__(self, hits=()):
        self.hits = list(hits)
        self.documents = {}
        self.lose_response = False
        self.forbid = False
        self.indices = Mock()
        self.indices.resolve_index.side_effect = lambda **kw: {'indices': [{'name': n} for n in kw['name'].split(',')]}
        self.indices.get_mapping.side_effect = lambda **kw: {kw['index']: {'mappings': {'properties': {
            'cloud_soc': {'properties': {'provenance': {'type': 'object', 'enabled': False}}}}}}}

    def get(self, *, index, id):
        if (index, id) not in self.documents:
            raise api_error(404, NotFoundError)
        return {'_source': deepcopy(self.documents[index, id])}

    def create(self, *, index, id, document, **kw):
        if self.forbid:
            raise api_error(403)
        if (index, id) in self.documents:
            raise api_error(409, ConflictError)
        self.documents[index, id] = deepcopy(document)
        if self.lose_response:
            self.lose_response = False
            raise ConnectionError('synthetic response loss')
        return {'result': 'created'}

    def scan(self, client, *, index, query, **kw):
        filters = query['bool']['filter']
        bounds = filters[0]['range']['cloud_soc.normalized_at']
        org = filters[1]['term']['organization.id']
        return [deepcopy(h) for h in self.hits if h['_index'] == index and h['_source']['organization']['id'] == org
                and aware(bounds['gte']) <= aware(h['_source']['cloud_soc']['normalized_at']) <= aware(bounds['lte'])]


def hit(event, received=None):
    e = deepcopy(event)
    meta = e.pop('_cloud_soc_meta')
    if received is not None:
        e['cloud_soc']['normalized_at'] = received.isoformat()
    return {'_index': meta['index'], '_id': meta['document_id'], '_source': e}


def config(events):
    return {'organizations': list({e['organization']['id'] for e in events}),
            'normalized_indices': sorted({e['_cloud_soc_meta']['index'] for e in events}),
            'raw_indices': sorted({e['cloud_soc']['provenance']['raw']['index'] for e in events}),
            'alerts_index': 'security-alerts', 'revisions_index': 'soc-managed-alert-revisions-v1',
            'max_events': 100, 'max_alerts': 1000, 'late_seconds': 60, 'future_seconds': 0}


def setup(tmp_path, definition, events, start=BASE):
    library = RuleLibrary(tmp_path / 'cases.sqlite', {e['organization']['id'] for e in events})
    org = events[0]['organization']['id']
    row = library.create({'organization': org, 'definition': definition}, ADMIN)
    row = action(library, row, 'approve')
    row = action(library, row, 'apply', effective_from=start.isoformat())
    worker = ManagedWorker(library.path, config(events))
    return library, row, worker, Remote([hit(e) for e in events])


def test_single_event_alert_has_no_five_minute_wait_and_preserves_evidence(tmp_path):
    events = [mall(1, action='order_view', organization='synthetic')]
    before = event_fingerprint(events[0])
    library, row, worker, remote = setup(tmp_path, example('access_denied'), events)
    result = worker.run(remote, now=BASE + timedelta(seconds=11), scanner=remote.scan)
    assert result['failed'] == 0 and result['created'] == 1
    alert = next(iter(remote.documents.values()))
    assert alert['cloud_soc']['risk_score'] is None and alert['cloud_soc']['risk_level'] == 'unassessed'
    assert alert['cloud_soc']['provenance']['evidence'][0]['raw'] == events[0]['cloud_soc']['provenance']['raw']
    assert event_fingerprint(events[0]) == before
    assert worker.run(remote, now=BASE + timedelta(seconds=12), scanner=remote.scan)['created'] == 0
    assert len(remote.documents) == 1
    assert library.detail(row['id'], ADMIN)['observed_state'] == 'running'


def test_threshold_across_cycles_and_restart_with_negative_and_foreign_inputs(tmp_path):
    events = [mall(i, organization='synthetic') for i in range(1, 11)]
    d = example()
    d.update(source='mall', conditions=[{'field': 'event.outcome', 'operator': 'equals', 'value': 'failure'}])
    library, row, worker, remote = setup(tmp_path, d, events)
    remote.hits = [hit(e) for e in events[:9]]
    assert worker.run(remote, now=BASE + timedelta(seconds=11), scanner=remote.scan)['created'] == 0
    remote.hits.append(hit(events[-1], BASE + timedelta(seconds=12)))
    remote.hits.append(hit(mall(12, organization='foreign'), BASE + timedelta(seconds=12)))
    worker = ManagedWorker(library.path, config(events))
    result = worker.run(remote, now=BASE + timedelta(seconds=13), scanner=remote.scan)
    assert result['failed'] == 0 and result['created'] == 1
    assert next(iter(remote.documents.values()))['organization']['id'] == 'synthetic'


def test_sequence_requires_success_and_preserves_window(tmp_path):
    events = [mall(i, organization='synthetic') for i in range(1, 6)]
    events.append(mall(6, seconds=20, outcome='success', organization='synthetic'))
    d = example('login_sequence')
    d['source'] = 'mall'
    d['group_by'] = ['host.id', 'source.ip']
    library, _, worker, remote = setup(tmp_path, d, events)
    remote.hits = [hit(e) for e in events[:5]]
    assert worker.run(remote, now=BASE + timedelta(seconds=11), scanner=remote.scan)['created'] == 0
    remote.hits.append(hit(events[-1], BASE + timedelta(seconds=21)))
    assert worker.run(remote, now=BASE + timedelta(seconds=22), scanner=remote.scan)['created'] == 1
    assert len(next(iter(remote.documents.values()))['cloud_soc']['provenance']['evidence']) == 6


@pytest.mark.parametrize('failure', ['response_lost', 'commit_failed', 'permission'])
def test_remote_and_local_failure_retries_preserve_checkpoint_and_no_duplicates(tmp_path, failure):
    events = [mall(1, action='order_view', organization='synthetic')]
    library, row, worker, remote = setup(tmp_path, example('access_denied'), events)
    if failure == 'response_lost':
        remote.lose_response = True
    elif failure == 'permission':
        remote.forbid = True
    else:
        with library.connect() as db:
            db.execute("CREATE TRIGGER fail_state BEFORE INSERT ON managed_worker_state BEGIN SELECT RAISE(ABORT,'synthetic'); END")
    assert worker.run(remote, now=BASE + timedelta(seconds=11), scanner=remote.scan)['failed'] == 1
    with library.connect() as db:
        assert db.execute('SELECT count(*) FROM managed_worker_state').fetchone()[0] == 0
        if failure == 'commit_failed':
            db.execute('DROP TRIGGER fail_state')
    remote.forbid = False
    result = worker.run(remote, now=BASE + timedelta(seconds=12), scanner=remote.scan)
    assert result['failed'] == 0 and len(remote.documents) == 1
    assert library.detail(row['id'], ADMIN)['observed_state'] == 'running'


def test_out_of_order_evidence_creates_linked_revision_not_overwrite(tmp_path):
    events = [mall(i, organization='synthetic') for i in (1, 2, 3)]
    d = example()
    d.update(source='mall', count=2, cooldown_seconds=0)
    _, _, worker, remote = setup(tmp_path, d, events)
    remote.hits = [hit(e) for e in (events[0], events[2])]
    assert worker.run(remote, now=BASE + timedelta(seconds=11), scanner=remote.scan)['created'] == 1
    first = deepcopy(remote.documents)
    remote.hits.append(hit(events[1], BASE + timedelta(seconds=12)))
    result = worker.run(remote, now=BASE + timedelta(seconds=13), scanner=remote.scan)
    assert result['failed'] == 0 and result['revisions'] == 1
    assert all(remote.documents[k] == v for k, v in first.items())
    assert worker.run(remote, now=BASE + timedelta(seconds=14), scanner=remote.scan)['revisions'] == 0


def test_delete_fence_and_generation_replacement(tmp_path):
    events = [mall(1, action='order_view', organization='synthetic')]
    library, row, worker, remote = setup(tmp_path, example('access_denied'), events)
    old = library.desired_releases(['synthetic'])[0]
    row = action(library, row, 'delete')
    with pytest.raises(ValueError, match='release_changed'):
        worker.cycle(remote, old, now=BASE + timedelta(seconds=11), scanner=remote.scan)
    assert not remote.documents
    assert worker.run(remote, now=BASE + timedelta(seconds=12), scanner=remote.scan)['failed'] == 0
    assert library.detail(row['id'], ADMIN)['status'] == 'deleted'


def test_capacity_partial_scan_and_future_input_do_not_fake_completion(tmp_path):
    events = [mall(1, action='order_view', organization='synthetic')]
    library, _, worker, remote = setup(tmp_path, example('access_denied'), events)
    def partial(*args, **kwargs):
        yield remote.hits[0]
        raise ConnectionError('synthetic partial read')
    assert worker.run(remote, now=BASE + timedelta(seconds=11), scanner=partial)['failed'] == 1
    assert not remote.documents
    future = deepcopy(remote.hits[0])
    future['_source']['@timestamp'] = (BASE + timedelta(days=1)).isoformat()
    remote.hits = [future]
    result = worker.run(remote, now=BASE + timedelta(seconds=12), scanner=remote.scan)
    assert result['issues'] == 1 and result['created'] == 0
    with library.connect() as db:
        assert db.execute('SELECT reason FROM managed_input_issues').fetchone()[0] == 'future_event_time'


def test_waf_validates_metadata_and_scopes_sites(tmp_path):
    events = [waf_normalized(0)]
    library, _, worker, remote = setup(tmp_path, example('waf_sqli'), events, start=WAF_BASE)
    result = worker.run(remote, now=WAF_BASE + timedelta(seconds=61), scanner=remote.scan)
    assert result['failed'] == 0 and result['created'] == 1
    alert = next(iter(remote.documents.values()))
    assert alert['service']['id'] == 'site-a' and alert['cloud_soc']['provenance']['assessment']['waf']
    fake = deepcopy(events[0])
    fake['cloud_soc']['detail']['fields']['sqli'] = False
    # The source-specific validator is still applied to custom IDs.
    from cloud_soc.detection.authoring import compile_rule
    from cloud_soc.detection.telemetry import evaluate
    assert evaluate(fake, compile_rule(example('waf_sqli'), fake['organization']['id']))[0] != 'matched'


def test_config_refuses_wildcards_overlap_and_unbounded_state():
    e = mall(1, organization='synthetic')
    c = config([e])
    for field, value in [('normalized_indices', ['*']), ('revisions_index', c['alerts_index']), ('late_seconds', -1)]:
        changed = {**c, field: value}
        with pytest.raises(ValueError):
            configuration(changed)


def test_group_error_is_visible_and_multiple_indexes_keep_same_id_separate(tmp_path):
    e = mall(1, action='order_view', organization='synthetic')
    second = mall(1, action='order_view', organization='synthetic', host='second-host')
    second['_cloud_soc_meta']['index'] = 'soc-normalized-mall-second'
    second['cloud_soc']['provenance']['raw']['index'] = 'soc-host-raw-mall-second'
    second['cloud_soc']['provenance']['raw']['id'] = 'independent-raw'
    _, _, worker, remote = setup(tmp_path, example('access_denied'), [e, second])
    assert worker.run(remote, now=BASE + timedelta(seconds=11), scanner=remote.scan)['created'] == 2
    bad = hit(mall(3, action='order_view', organization='synthetic'), BASE + timedelta(seconds=12))
    bad['_source']['source']['ip'] = 'not-an-ip'
    remote.hits.append(bad)
    result = worker.run(remote, now=BASE + timedelta(seconds=13), scanner=remote.scan)
    assert result['issues'] == 1 and result['created'] == 0


def test_cooldown_is_durable_with_reordered_input(tmp_path):
    events = [mall(i, organization='synthetic') for i in (1, 2, 3)]
    d = example()
    d.update(source='mall', count=2, cooldown_seconds=300)
    _, _, worker, remote = setup(tmp_path, d, events)
    remote.hits = [hit(events[0]), hit(events[2])]
    assert worker.run(remote, now=BASE + timedelta(seconds=11), scanner=remote.scan)['created'] == 1
    remote.hits.append(hit(events[1], BASE + timedelta(seconds=12)))
    result = worker.run(remote, now=BASE + timedelta(seconds=13), scanner=remote.scan)
    assert result['created'] == 0 and result['revisions'] == 1
    assert sum(index == 'security-alerts' for index, _ in remote.documents) == 1


def test_legacy_mall_waf_with_custom_rule_id_keeps_contract(tmp_path):
    from test_security_mall_waf_detection import waf, BASE as EDGE_BASE
    _, event = waf()
    d = example('waf_sqli')
    d['source'] = 'mall_waf'
    d['group_by'] = ['host.id', 'source.ip']
    _, _, worker, remote = setup(tmp_path, d, [event], start=EDGE_BASE)
    result = worker.run(remote, now=EDGE_BASE + timedelta(seconds=3), scanner=remote.scan)
    assert result['failed'] == 0 and result['created'] == 1
    alert = next(iter(remote.documents.values()))
    assert alert['rule']['id'] == 'CUSTOM-WAF-001'
    assert alert['cloud_soc']['provenance']['assessment']['blocked'] is False


def test_cli_explicit_tls_auth_timeout_close_and_redaction(tmp_path, monkeypatch, capsys):
    import json
    from cloud_soc.detection import managed_cli
    events = [mall(1, action='order_view', organization='synthetic')]
    library, _, _, _ = setup(tmp_path, example('access_denied'), events)
    configuration_file = tmp_path / 'worker.json'
    configuration_file.write_text(json.dumps(config(events)), encoding='utf-8')
    configuration_file.chmod(0o600)
    ca, key = tmp_path / 'ca.crt', tmp_path / 'worker.key'
    ca.write_text('SYNTHETIC CA')
    key.write_text('SYNTHETIC_SECRET_CANARY')
    key.chmod(0o600)
    client = Mock()
    manager = Mock()
    manager.__enter__ = Mock(return_value=client)
    manager.__exit__ = Mock(return_value=False)
    factory = Mock(return_value=manager)
    monkeypatch.setattr(managed_cli, 'Elasticsearch', factory)
    worker = Mock()
    worker.run.return_value = {'failed': 0, 'created': 1}
    worker_factory = Mock(return_value=worker)
    monkeypatch.setattr(managed_cli, 'ManagedWorker', worker_factory)
    args = ['--config', str(configuration_file), '--library', str(library.path), '--es-url',
            'https://example.invalid:9200', '--ca-file', str(ca), '--api-key-file', str(key), '--once']
    assert managed_cli.main(args) == 0
    assert factory.call_args.kwargs['verify_certs'] is True
    assert factory.call_args.kwargs['max_retries'] == 0 and factory.call_args.kwargs['request_timeout'] == 15
    manager.__exit__.assert_called_once()
    worker.run.side_effect = RuntimeError('SYNTHETIC_SECRET_CANARY')
    assert managed_cli.main(args) == 1
    assert 'SYNTHETIC_SECRET_CANARY' not in capsys.readouterr().out
