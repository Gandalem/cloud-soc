"""Consolidated authoring/lifecycle contract checks using disposable local state."""
from copy import deepcopy
import json
import sqlite3

import pytest

from cloud_soc.detection.authoring import (AuthoringError, compile_rule, csv_template, example,
    normalize, parse_import)
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.portal.rule_library import RuleLibrary
from cloud_soc.portal.rule_management import RuleError
from test_integration_security import make_session_portal, login

ADMIN = LogPrincipal('admin', 'admin', None, ())
OTHER = LogPrincipal('other', 'admin', ('foreign',), ())


@pytest.fixture
def library(tmp_path):
    return RuleLibrary(tmp_path / 'cases.sqlite', ('synthetic', 'foreign'))


def create(library, definition=None):
    return library.create({'organization': 'synthetic', 'definition': definition or example()}, ADMIN)


def action(library, row, name, **extra):
    return library.action(row['id'], name, {'version': row['version'], 'content_hash': row['content_hash'], **extra}, ADMIN)


def test_templates_compile_with_enforced_scope_and_existing_engine():
    for template in ('ssh_failures', 'web_errors', 'login_sequence', 'waf_sqli', 'access_denied'):
        d = example(template)
        r = compile_rule(d, 'synthetic')
        assert {'field': 'organization.id', 'operator': 'equals', 'value': 'synthetic'} in r['conditions']
        assert r['group_by'][0] == 'organization.id' and 'host.id' in r['group_by']
        if d['source'] in ('web', 'waf'):
            assert 'service.id' in r['group_by']
    assert compile_rule(example('waf_sqli'), 'synthetic')['distinct']['count'] == 1


@pytest.mark.parametrize('change', ['field', 'operator', 'count', 'source', 'extra', 'sequence', 'groups'])
def test_invalid_forms_fail_without_coercion(change):
    d = example()
    if change == 'field':
        d['conditions'][0]['field'] = 'message'
    elif change == 'operator':
        d['conditions'][0]['operator'] = 'script'
    elif change == 'count':
        d['count'] = True
    elif change == 'source':
        d['source'] = 'arbitrary'
    elif change == 'extra':
        d['pipeline'] = 'x'
    elif change == 'sequence':
        d['kind'], d['success_seconds'] = 'sequence', 60
    else:
        d['group_by'] = ['organization.id']
    with pytest.raises(AuthoringError):
        normalize(d)


def test_versions_are_immutable_and_active_release_survives_edit(library):
    row = action(library, create(library), 'approve')
    original = row['definition']
    approved_hash = row['content_hash']
    row = action(library, row, 'apply', effective_from='2026-01-01T00:00:00Z')
    library.acknowledge(row['id'], row['generation'], 'running')
    assert library.detail(row['id'], ADMIN)['active']
    changed = deepcopy(original)
    changed['count'] = 20
    row = action(library, row, 'edit', definition=changed)
    assert row['status'] == 'draft' and row['active']
    with library.connect() as db:
        saved = db.execute('SELECT * FROM managed_versions').fetchone()
        assert saved['content_hash'] == approved_hash and json.loads(saved['definition']) == original
    assert json.loads(library.desired_releases(['synthetic'])[0]['engine_rule'])['threshold']['count'] == 10
    with pytest.raises(RuleError):
        action(library, row, 'apply', effective_from='2026-01-01T00:00:00Z')


def test_delete_requires_stop_ack_and_preserves_history(library):
    row = action(library, create(library), 'approve')
    row = action(library, row, 'apply', effective_from='2026-01-01T00:00:00Z')
    old_generation = row['generation']
    row = action(library, row, 'delete')
    assert row['status'] == 'delete_pending'
    with pytest.raises(RuleError):
        library.acknowledge(row['id'], old_generation, 'running')
    library.acknowledge(row['id'], row['generation'], 'deleted')
    assert library.listing(ADMIN)['rules'] == []
    assert library.detail(row['id'], ADMIN)['versions']
    with pytest.raises(RuleError) as error:
        create(library)
    assert error.value.code == 'rule_key_unavailable'


def test_permissions_stale_edits_and_reserved_ids(library):
    row = create(library)
    with pytest.raises(RuleError):
        library.detail(row['id'], OTHER)
    row2 = action(library, row, 'edit', definition=row['definition'])
    with pytest.raises(RuleError) as error:
        action(library, row, 'delete')
    assert error.value.code == 'rule_changed'
    assert action(library, row2, 'delete')['status'] == 'deleted'
    d = example()
    d['key'] = 'AUTH-001'
    with pytest.raises(RuleError):
        create(library, d)


def test_reapply_same_approved_definition_after_stop(library):
    row = action(library, create(library), 'approve')
    row = action(library, row, 'apply', effective_from='2026-01-01T00:00:00Z')
    row = action(library, row, 'stop')
    library.acknowledge(row['id'], row['generation'], 'stopped')
    row = action(library, row, 'apply', effective_from='2026-01-01T00:00:00Z')
    assert row['generation'] == 3


def batch(rows, request_id='batch-request-001'):
    return {'organization': 'synthetic', 'format': 'json',
            'content': json.dumps({'schema_version': 1, 'rules': rows}), 'request_id': request_id}


def test_atomic_import_idempotency_and_row_errors(library):
    d = example('web_errors')
    body = batch([example(), d])
    assert library.import_rules(body, ADMIN, preview=True)['valid']
    result = library.import_rules(body, ADMIN)
    assert len(result['created']) == 2 and library.import_rules(body, ADMIN) == result
    with pytest.raises(RuleError):
        library.import_rules(batch([example()]), ADMIN)
    invalid = batch([example('access_denied'), example('access_denied')], 'second-batch-request')
    preview = library.import_rules(invalid, ADMIN, preview=True)
    assert not preview['valid'] and preview['items'][1]['code'] == 'duplicate_import_key'
    with pytest.raises(RuleError):
        library.import_rules(invalid, ADMIN)
    assert len(library.listing(ADMIN)['rules']) == 2


def test_import_commit_failure_rolls_back_entire_batch(library):
    with library.connect() as db:
        db.execute("CREATE TRIGGER fail_batch BEFORE INSERT ON managed_batches BEGIN SELECT RAISE(ABORT,'synthetic'); END")
    with pytest.raises(sqlite3.Error):
        library.import_rules(batch([example()]), ADMIN)
    assert library.listing(ADMIN)['rules'] == []


def test_csv_template_and_json_strictness():
    assert normalize(parse_import('csv', csv_template())[0]) == example()
    with pytest.raises(AuthoringError):
        parse_import('json', '{"schema_version":1,"schema_version":1,"rules":[]}')
    with pytest.raises(AuthoringError):
        parse_import('csv', 'wrong,columns\na,b')


def test_worker_failure_not_reported_active(library):
    row = action(library, create(library), 'approve')
    row = action(library, row, 'apply', effective_from='2026-01-01T00:00:00Z')
    library.acknowledge(row['id'], row['generation'], 'failed')
    assert not library.detail(row['id'], ADMIN)['active']
    assert library.detail(row['id'], ADMIN)['runtime_state'] == 'failed'
    with library.connect() as db:
        db.execute("UPDATE managed_rules SET observed_state='running', observed_at='2020-01-01T00:00:00+00:00'")
    assert library.detail(row['id'], ADMIN)['runtime_state'] == 'stale'


def test_api_admin_csrf_and_import_contract(tmp_path):
    app, _, _, _ = make_session_portal(tmp_path)
    http, headers = login(app, 'admin')
    assert http.get('/api/settings/rule-library').status_code == 200
    body = {'organization': 'synthetic', 'definition': example()}
    assert http.post('/api/settings/rule-library', json=body).status_code == 403
    response = http.post('/api/settings/rule-library', json=body, headers=headers)
    assert response.status_code == 201 and response.json['summary']
    assert http.get('/api/settings/rule-library/template.csv').status_code == 200
    assert http.get('/api/settings/rule-library/export').json['schema_version'] == 1
    assert http.get('/api/settings/rule-library?organization=foreign').status_code == 400
    other, other_headers = login(app, 'investigate')
    assert other.get('/api/settings/rule-library').status_code == 403
    assert other.post('/api/settings/rule-library', json=body, headers=other_headers).status_code == 403


def test_selected_import_rows_and_concurrent_request(library):
    from concurrent.futures import ThreadPoolExecutor
    body = batch([example(), example('web_errors')])
    body['selected_rows'] = [2]
    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: library.import_rules(body, ADMIN), range(2)))
    assert results[0] == results[1] and len(library.listing(ADMIN)['rules']) == 1
    assert library.listing(ADMIN)['rules'][0]['definition']['source'] == 'web'


def test_concurrent_stale_actions_only_one_wins(library):
    from concurrent.futures import ThreadPoolExecutor
    row = create(library)
    def approve(_):
        try:
            return action(library, row, 'approve')['status']
        except RuleError as error:
            return error.code
    with ThreadPoolExecutor(max_workers=2) as pool:
        assert sorted(pool.map(approve, range(2))) == ['approved', 'rule_changed']


def test_import_api_accepts_bounded_file_above_legacy_8k(tmp_path):
    app, _, _, _ = make_session_portal(tmp_path)
    http, headers = login(app, 'admin')
    rows = []
    for i in range(30):
        d = example()
        d['key'] = f'IMPORT-ROW-{i:03d}'
        rows.append(d)
    body = batch(rows)
    assert len(body['content']) > 8192
    response = http.post('/api/settings/rule-library/import/preview', json=body, headers=headers)
    assert response.status_code == 200 and response.json['valid']
    assert http.get('/rule-editor.js').status_code == 200
    viewer, _ = login(app, 'view')
    assert viewer.get('/rule-editor.js').status_code == 403
