"""One-shot read-only ES validation. Only new private SQLite/result files are written.

Run on the lab VM with staged latest src on PYTHONPATH. No provisioning or
service commands, privileged credentials, raw log files or Portal DB access.
"""
import argparse
import base64
from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import ssl
import stat
import time
import urllib.error
import urllib.request
from urllib.parse import quote

from cloud_soc.correlation.security_mall import Scope
from cloud_soc.correlation.store import CorrelationStore
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.portal.log_contract import field
from cloud_soc.portal.mall_scope import validate_scope
from cloud_soc.processing.contract import normalize
from cloud_soc.processing.mall_runtime import private_json
from cloud_soc.triage.policy import Policy
from cloud_soc.triage.engine import time_range
from cloud_soc.triage.store import TriageStore

BASE = Path('/home/kopo/soc-mall-lab')
MAX_HITS = 500
FORBIDDEN = {'message', 'original', 'password', 'cookie', 'authorization', 'session_id',
             'session_token', 'api_key', 'apiKey', 'username', 'email', 'address', 'phone'}
PRIVILEGES = ['read', 'view_index_metadata', 'write', 'index', 'create_doc', 'delete', 'manage']
APPROVED_HISTORY = (
    'soc-host-raw-mall-isolated-20261016-8a070063',
    'soc-normalized-mall-isolated-20261016-8a070063',
    'soc-mall-alerts-lab-live-20261016-f56deb49',
)
APPROVED_CURRENT = (
    'soc-host-raw-mall-isolated-continuous-20261017-42062f13',
    'soc-host-raw-mall-edge-isolated-continuous-20261017-42062f13',
    'soc-normalized-mall-continuous-20261017-42062f13',
)
APPROVED_INDICES = APPROVED_HISTORY + APPROVED_CURRENT


class ValidationError(ValueError):
    def __init__(self, reason, *, http_status=None, operation=None):
        super().__init__(reason)
        self.http_status = http_status
        self.operation = operation


def require(condition, code):
    if not condition:
        raise ValidationError(code)


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


def validation_credential(path):
    """Linux-only, descriptor-relative traversal; never fall back to service keys."""
    path = Path(path)
    directory = BASE / 'validation-7ab/secrets'
    require(path.is_absolute() and path.parent == directory and
            re.fullmatch(r'reader-[A-Za-z0-9][A-Za-z0-9_-]{0,95}\.json', path.name) is not None,
            'reader_path_forbidden')
    require(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW') and hasattr(os, 'O_DIRECTORY'),
            'reader_posix_permissions_required')
    fd = None
    try:
        fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        for part in path.parent.parts[1:]:
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd);fd = next_fd
        info = os.fstat(fd)
        require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700,
                'reader_directory_permissions')
        key_fd = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        try:
            info = os.fstat(key_fd)
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and
                    0 < info.st_size <= 8192, 'reader_file_invalid')
            require(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o600,
                    'reader_file_permissions')
            raw = os.read(key_fd, 8193)
            require(len(raw) <= 8192, 'reader_file_invalid')
        finally:
            os.close(key_fd)
    except FileNotFoundError:
        raise ValidationError('reader_file_missing') from None
    except OSError:
        raise ValidationError('reader_file_unsafe_or_unreadable') from None
    finally:
        if fd is not None:
            os.close(fd)
    try:
        value = json.loads(raw)
        require(isinstance(value, dict) and set(value) == {'id', 'encoded', 'expiration'}, 'reader_file_invalid')
        require(isinstance(value['id'], str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}', value['id']) is not None,
                'reader_file_invalid')
        encoded = value['encoded']
        require(isinstance(encoded, str) and 0 < len(encoded) <= 4096, 'reader_file_invalid')
        decoded = base64.b64decode(encoded, validate=True).decode('ascii')
        identifier, secret = decoded.split(':', 1)
        require(identifier == value['id'] and bool(secret) and
                re.fullmatch(r'[A-Za-z0-9_-]+', secret) is not None, 'reader_file_invalid')
        require(type(value['expiration']) is int, 'reader_file_invalid')
    except (ValueError, UnicodeError, KeyError, TypeError):
        raise ValidationError('reader_file_invalid') from None
    require(value['expiration'] > int(time.time() * 1000), 'reader_expired')
    return value


class Reader:
    """Fixed TLS endpoint and read-only operation allowlist, even with a wrong key."""
    def __init__(self, key, ca):
        value = validation_credential(key)
        self.auth = 'ApiKey ' + value['encoded']
        self.key_id = value['id']
        self.expiration = value['expiration']
        try:
            context = ssl.create_default_context(cafile=str(ca))
        except (OSError, ssl.SSLError):
            raise ValidationError('reader_ca_invalid') from None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context))

    def request(self, method, path, body=None):
        permitted = (method == 'GET' and getattr(self, 'key_id', None) is not None and
                     path == '/_security/api_key?id=' + self.key_id or
                     method == 'POST' and path == '/_security/user/_has_privileges' or
                     method == 'POST' and path in {
                         '/' + index + '/' + operation for index in APPROVED_INDICES for operation in ('_search', '_mget')})
        require(permitted, 'es_operation_forbidden')
        if path.endswith('/_mget'):
            require(isinstance(body, dict) and set(body) == {'ids'} and
                    isinstance(body['ids'], list) and 0 < len(body['ids']) <= MAX_HITS and
                    all(isinstance(identifier, str) and identifier for identifier in body['ids']),
                    'es_operation_forbidden')
        require(self.expiration > int(time.time() * 1000), 'reader_expired')
        req = urllib.request.Request('https://127.0.0.1:19200' + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': self.auth, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=15) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
                require(len(raw) <= 16 * 1024 * 1024, 'es_response_limit')
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            operation = ('self_api_key_metadata' if method == 'GET' else 'effective_privileges'
                         if path == '/_security/user/_has_privileges' else 'index_search'
                         if path.endswith('/_search') else 'document_recheck')
            raise ValidationError({401: 'reader_authentication_failed', 403: 'reader_permission_denied'}.get(error.code, 'es_http_error'),
                                  http_status=error.code, operation=operation) from None
        except ssl.SSLCertVerificationError:
            raise ValidationError('es_tls_verification_failed') from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                reason = 'es_tls_verification_failed'
            elif isinstance(error.reason, TimeoutError):
                reason = 'es_connection_timeout'
            else:
                reason = 'es_connection_failed'
            raise ValidationError(reason) from None
        except TimeoutError:
            raise ValidationError('es_connection_timeout') from None
        except (ValueError, UnicodeError):
            raise ValidationError('es_response_invalid') from None


def plan(profile):
    portal = validate_scope(private_json(BASE / 'portal-lab/config/mall-scope.json'))
    config = private_json(BASE / 'collection-services/config/collection.json')
    history = [portal['raw'], portal['normalized'], portal['alerts']]
    current = [config[key] for key in ('app_index', 'edge_index', 'normalized_index')]
    require(tuple(history) == APPROVED_HISTORY and tuple(current) == APPROVED_CURRENT,
            'unapproved_configured_index')
    require(config['organization_id'] == 'mall-isolated' and config['host_id'] == 'mall-host-isolated',
            'unapproved_configured_scope')
    scope = Scope(config['organization_id'], 'soc-mall-lab', config['host_id'], 'security-mall',
                  (portal['normalized'],) if profile == 'history' else (portal['normalized'], current[2]),
                  (portal['raw'],) if profile == 'history' else (portal['raw'], current[0]),
                  (current[1],), (portal['alerts'],))
    return scope, history if profile == 'history' else history + current


def permissions(client, names):
    require(names and len(names) == len(set(names)) and set(names) <= set(APPROVED_INDICES),
            'unapproved_privilege_index')
    data = client.request('POST', '/_security/user/_has_privileges', {'cluster': ['all', 'manage'],
        'index': [{'names': names, 'privileges': PRIVILEGES}]})
    require(not any(data['cluster'].values()), 'reader_has_management_privileges')
    missing = []
    for name in names:
        row = data['index'][name]
        require(not any(row[p] for p in PRIVILEGES if p not in ('read', 'view_index_metadata')), 'reader_has_write_privileges')
        if not row['read'] or not row['view_index_metadata']:
            missing.append(name)
    return missing


def reader_policy(client):
    """Assigned-role upper bound from this key only; effective rights checked next.

    ES 9.5.2 cannot enumerate effective user privileges for assigned-role keys.
    Its same-key metadata API needs no additional security/cluster privilege.
    """
    value = client.request('GET', '/_security/api_key?id=' + client.key_id)
    require(isinstance(value, dict) and isinstance(value.get('api_keys'), list) and len(value['api_keys']) == 1,
            'reader_privilege_response_invalid')
    key = value['api_keys'][0]
    require(isinstance(key, dict) and key.get('id') == client.key_id and key.get('invalidated') is False and
            key.get('expiration') == client.expiration, 'reader_key_metadata_mismatch')
    roles = key.get('role_descriptors')
    require(isinstance(roles, dict) and bool(roles), 'reader_assigned_roles_missing')
    for role in roles.values():
        require(isinstance(role, dict) and set(role) <= {'cluster', 'global', 'indices', 'applications', 'run_as',
            'remote_indices', 'remote_cluster', 'data_source', 'restriction', 'metadata', 'transient_metadata', 'description'},
            'reader_privilege_response_invalid')
        require(all(role.get(name) == [] for name in ('cluster', 'applications', 'run_as')) and
                all(not role.get(name) for name in ('global', 'remote_indices', 'remote_cluster', 'data_source', 'restriction')),
                'reader_excess_privileges')
        rows = role.get('indices')
        require(isinstance(rows, list) and bool(rows), 'reader_scope_missing')
        for row in rows:
            require(isinstance(row, dict) and set(row) <= {'names', 'privileges', 'allow_restricted_indices', 'query', 'field_security'},
                    'reader_privilege_response_invalid')
            names = row.get('names');grants = row.get('privileges')
            require(isinstance(names, list) and bool(names) and all(n in APPROVED_INDICES for n in names),
                    'reader_excess_index_scope')
            require(isinstance(grants, list) and bool(grants) and
                    all(p in ('read', 'view_index_metadata') for p in grants) and
                    row.get('allow_restricted_indices') is False, 'reader_excess_privileges')


def search(client, index, scope, frame, cutoff, kind):
    filters = [{'term': {'organization.id': scope.organization}},
               {'range': {'@timestamp': {'gte': frame['start'], 'lt': frame['end']}}}]
    if kind == 'alert':
        filters.append({'terms': {'rule.id': ['WEB-ACCESS-01', 'WEB-AUTH-01']}})
    else:
        filters.extend([{'term': {'host.id': scope.host}},
                        {'range': {'event.ingested': {'lte': cutoff}}}])
        service = 'service.name' if kind == 'normalized' else (
            'security_mall_edge.service_name' if index in scope.edge_indices else 'security_mall.audit.service_name')
        filters.append({'term': {service: scope.service}})
        if kind == 'normalized':
            filters.append({'range': {'cloud_soc.normalized_at': {'lte': cutoff}}})
    result = client.request('POST', '/' + quote(index, safe='') + '/_search',
        {'query': {'bool': {'filter': filters}}, 'size': MAX_HITS, 'track_total_hits': True,
         'sort': [{'@timestamp': 'asc'}], 'seq_no_primary_term': True, 'version': True})
    require(not result.get('timed_out') and not result.get('terminated_early') and
            result.get('_shards', {}).get('failed', 0) == 0, 'partial_es_search')
    total = result['hits']['total']
    require(total['relation'] == 'eq' and total['value'] <= MAX_HITS and
            len(result['hits']['hits']) == total['value'], 'bounded_search_limit')
    require(all(hit.get('_index') == index for hit in result['hits']['hits']), 'unexpected_response_index')
    return result['hits']['hits']


def signature(hit):
    return event_fingerprint({key: hit[key] for key in ('_index', '_id', '_source', '_seq_no', '_primary_term', '_version')})


def no_original(value):
    if isinstance(value, dict):
        return not set(value) & FORBIDDEN and all(no_original(v) for v in value.values())
    if isinstance(value, list):
        return all(no_original(v) for v in value)
    return True


def provenance(raw_hits, normalized):
    lookup = {(h['_index'], h['_id']): h for h in raw_hits}
    checked = 0
    paths = ['@timestamp', 'event.id', 'event.action', 'event.outcome', 'event.ingested',
             'organization.id', 'host.id', 'service.name', 'source.ip', 'http.request.id',
             'cloud_soc.security_mall.account_id', 'cloud_soc.security_mall.account_key_id',
             'cloud_soc.security_mall.resource_type', 'cloud_soc.security_mall.authorization_reason',
             'cloud_soc.security_mall_edge']
    for hit in normalized:
        source = hit['_source'];ref = field(source, 'cloud_soc.provenance.raw')
        raw = lookup.get((ref['index'], ref['id']))
        require(raw is not None, 'raw_reference_not_in_bounded_read')
        identifier, record, event = normalize(raw, field(source, 'cloud_soc.normalized_at'))
        require(event is not None and record['status'] == 'normalized' and identifier == hit['_id'], 'raw_normalized_identity_mismatch')
        require(all(field(source, path) == field(event, path) for path in paths), 'raw_normalized_metadata_mismatch')
        checked += 1
    return checked


def expect(code, operation):
    try:
        operation()
    except ValueError as error:
        require(str(error) == code, 'unexpected_negative_result')
        return True
    raise ValidationError('negative_check_not_rejected')


def process(normalized, alerts, scope, directory, frame):
    principal = LogPrincipal('lab-readonly-validation', 'investigator', (scope.organization,), ())
    foreign = LogPrincipal('lab-unrelated', 'investigator', ('unrelated-validation-org',), ())
    ledger = CorrelationStore(directory / 'correlation.sqlite', scope)
    queue = TriageStore(directory / 'triage.sqlite', scope)
    split = max(0, len(normalized) - 1)
    ledger.ingest(normalized[:split], alerts)
    first = ledger.snapshot(principal);queue.replace(first, frame['start'], frame['end'])
    old_queue = queue.queue(frame['start'], frame['end'], principal)
    ledger.ingest(normalized[split:])
    latest = ledger.snapshot(principal)
    checks = {}
    if latest['revision_order']['sequence'] > first['revision_order']['sequence']:
        with queue.connect() as db:
            db.execute("CREATE TRIGGER fail_replace BEFORE UPDATE ON frames BEGIN SELECT RAISE(ABORT,'isolated_write_failure'); END")
        try:
            queue.replace(latest, frame['start'], frame['end'])
        except Exception as error:
            import sqlite3
            require(isinstance(error, sqlite3.IntegrityError), 'unexpected_storage_error')
        else:
            raise ValidationError('storage_failure_not_reproduced')
        require(queue.queue(frame['start'], frame['end'], principal) == old_queue, 'atomic_rollback_failed')
        checks['atomic_rollback'] = True
        with queue.connect() as db:
            db.execute('DROP TRIGGER fail_replace')
        queue.replace(latest, frame['start'], frame['end'])
        checks['stale_rejected'] = expect('triage_stale_revision', lambda: queue.replace(first, frame['start'], frame['end']))
        conflict = deepcopy(first);conflict['revision_order']['sequence'] = latest['revision_order']['sequence']
        checks['conflict_rejected'] = expect('triage_revision_conflict', lambda: queue.replace(conflict, frame['start'], frame['end']))
    else:
        checks.update(atomic_rollback=None, stale_rejected=None, conflict_rejected=None)
    ledger.ingest(normalized, alerts)
    require(ledger.snapshot(principal) == latest, 'source_replay_changed')
    checks['replay_noop'] = not queue.replace(latest, frame['start'], frame['end'])['applied']
    changed = deepcopy(latest);changed['revision_order']['publisher_id'] = '0' * 32
    checks['publisher_rejected'] = expect('triage_publisher_changed', lambda: queue.replace(changed, frame['start'], frame['end']))
    checks['foreign_principal_empty'] = ledger.snapshot(foreign) == {'requests': [], 'alert_links': []} and queue.queue(
        frame['start'], frame['end'], foreign) == {'items': []}
    for part in ('organization', 'site', 'host', 'service'):
        wrong = deepcopy(latest);wrong['scope'][part] = 'unrelated-scope'
        checks[part + '_rejected'] = expect('triage_scope_mismatch', lambda: queue.replace(wrong, frame['start'], frame['end']))
    final = queue.queue(frame['start'], frame['end'], principal)
    require(CorrelationStore(ledger.path, scope).snapshot(principal) == latest and
            TriageStore(queue.path, scope).queue(frame['start'], frame['end'], principal) == final, 'reopen_changed')
    checks['reopen_durable'] = True
    old_alert_ids = {i['id'] for i in old_queue['items'] if i['linked_alert_ids']}
    new_alert_ids = {i['id'] for i in final['items'] if i['linked_alert_ids']}
    checks['alert_item_ids_stable'] = old_alert_ids == new_alert_ids
    links = latest['alert_links']
    return {'request_bundles': len(latest['requests']),
        'states': {s: sum(b['state'] == s for b in latest['requests']) for s in ('complete', 'incomplete', 'unlinked', 'ambiguous')},
        'three_stream_bundles': sum(all(b['present'].values()) for b in latest['requests']),
        'web_waf_only': sum(b['present']['web'] and b['present']['waf'] and not b['present']['app'] for b in latest['requests']),
        'alert_links_complete': sum(link['state'] == 'complete' for link in links),
        'alert_links_incomplete': sum(link['state'] != 'complete' for link in links),
        'matched_hash_references': sum(len(link['evidence']) - len(link['unresolved']) for link in links),
        'unresolved_references': sum(len(link['unresolved']) for link in links),
        'queue_items': len(final['items']), 'sequence': latest['revision_order']['sequence'], 'revision_checks': checks,
        'alert_triage': [{key: item[key] for key in ('rule_ids', 'base_risk_score', 'original_severity', 'original_risk_level',
            'triage_score', 'triage_priority', 'independent_request_count', 'repeated_independent_request_count',
            'evidence_confidence', 'evidence_completeness', 'uncertainty_factors')} for item in final['items'] if item['linked_alert_ids']]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=('history', 'continuous'), required=True)
    parser.add_argument('--start', required=True);parser.add_argument('--end', required=True)
    parser.add_argument('--output-dir', type=Path, required=True)
    parser.add_argument('--api-key-file', type=Path, required=True,
                        help='VM validation-7ab/secrets/reader-<run>.json only; never a service key')
    args = parser.parse_args(argv)
    started = time.monotonic();report = {'integration_complete': False, 'profile': args.profile,
        'stage': 'output_preparation', 'index_queries': [], 'correlation_triage_started': False,
        'correlation_triage_completed': False};created = False
    try:
        os.umask(0o077)
        target = args.output_dir
        require(target.is_absolute() and target.is_relative_to(BASE / 'validation-7ab') and
                '..' not in target.parts and
                not any(p.is_symlink() for p in (target, *target.parents)), 'isolated_output_required')
        target.mkdir(mode=0o700, parents=True, exist_ok=False)
        created = True
        report['stage'] = 'scope_and_time_validation'
        scope, names = plan(args.profile)
        frame = time_range(args.start, args.end, Policy())
        cutoff = iso(datetime.now(timezone.utc));require(parse_time(frame['end']) <= parse_time(cutoff), 'future_range_forbidden')
        report['stage'] = 'credential_tls_setup'
        client = Reader(args.api_key_file, BASE / 'portal-lab/config/ca.crt')
        report.update(checked_at=cutoff, range=frame, indices=names,
                      endpoint='https://127.0.0.1:19200', cluster_version_rechecked=False)
        report['stage'] = 'api_key_policy'
        reader_policy(client)
        report.update(reader_metadata_verified=True, tls_verified=True)
        report['stage'] = 'effective_permissions'
        missing = permissions(client, list(APPROVED_INDICES))
        report.update(readonly_reader=True, tls_verified=True)
        if missing:
            report.update(reason='reader_scope_missing', unreadable_indices=missing)
            code = 4
        else:
            queried = {}
            report['stage'] = 'index_search'
            for index in names:
                kind = 'alert' if index in scope.alert_indices else 'normalized' if index in scope.normalized_indices else 'raw'
                progress = {'index': index, 'kind': kind, 'status': 'attempted', 'document_count': None}
                report['index_queries'].append(progress)
                queried[index] = search(client, index, scope, frame, cutoff, kind)
                progress.update(status='succeeded', document_count=len(queried[index]))
                report.setdefault('counts', {})[index] = len(queried[index])
            raw = [h for index, hits in queried.items() if index in scope.app_indices + scope.edge_indices for h in hits]
            normalized = [h for index, hits in queried.items() if index in scope.normalized_indices for h in hits]
            alerts = [h for index, hits in queried.items() if index in scope.alert_indices for h in hits]
            report['counts'] = {name: len(hits) for name, hits in queried.items()}
            report['stage'] = 'source_and_provenance_validation'
            require(raw and normalized, 'no_scoped_events')
            require(all(no_original(h['_source']) for h in raw + normalized), 'unexpected_private_source_field')
            report['raw_normalized_verified'] = provenance(raw, normalized)
            report.update(stage='correlation_triage', correlation_triage_started=True)
            report.update(process(normalized, alerts, scope, target, frame))
            report.update(correlation_triage_completed=True, stage='existing_document_recheck')
            for index, hits in queried.items():
                if hits:
                    result = client.request('POST', '/' + quote(index, safe='') + '/_mget',
                                            {'ids': [hit['_id'] for hit in hits]})
                    require(all(hit.get('_index') == index for hit in result['docs']), 'unexpected_response_index')
                    require(all(hit.get('found') for hit in result['docs']), 'existing_document_missing')
                    require({h['_id']: signature(h) for h in hits} == {h['_id']: signature(h) for h in result['docs']},
                            'existing_document_changed')
            report.update(counts={name: len(hits) for name, hits in queried.items()}, existing_documents_unchanged=True,
                access_alerts=sum(field(h['_source'], 'rule.id') == 'WEB-ACCESS-01' for h in alerts),
                auth_alerts=sum(field(h['_source'], 'rule.id') == 'WEB-AUTH-01' for h in alerts),
                synthetic_indices_read=False, account_identifiers_emitted=False)
            report['integration_complete'] = args.profile == 'continuous' and report['three_stream_bundles'] > 0 and not report['unresolved_references']
            code = 0 if report['integration_complete'] else 4
            report['reason'] = 'verified' if code == 0 else 'partial_scope_three_stream_validation_unavailable'
            report['stage'] = 'completed'
    except ValidationError as error:
        report['reason'] = str(error)
        report['exception_type'] = type(error).__name__
        if error.http_status is not None:
            report.update(http_status=error.http_status, failed_operation=error.operation)
        code = 1
    except (ValueError, OSError, KeyError, TypeError) as error:
        report['reason'] = 'input_or_engine_validation_failed'
        report['exception_type'] = type(error).__name__
        code = 1
    except Exception as error:
        report['exception_type'] = type(error).__name__
        report['reason'] = 'validation_tool_failed';code = 3
    report.update(exit_code=code, elapsed_seconds=round(time.monotonic() - started, 3))
    if code in (1, 3):
        report['failed_stage'] = report['stage']
        if report['stage'] == 'index_search' and report['index_queries']:
            report['index_queries'][-1]['status'] = 'failed'
    if created:
        # Summary only: never serialize ES hits, principal, credentials or raw messages.
        try:
            with (target / 'summary.json').open('x') as output:
                json.dump(report, output, indent=2)
        except OSError:
            report.update(reason='summary_write_failed', integration_complete=False, exit_code=1,
                          failed_stage='summary_write', stage='summary_write', exception_type='OSError')
            code = 1
    print(json.dumps(report));return code


if __name__ == '__main__':
    raise SystemExit(main())
