"""Bounded one-shot Mall adapter. Default dry-run; no worker/status/notification IO."""
import argparse
import base64
from collections import Counter
from contextlib import ExitStack
from copy import deepcopy
import json
from pathlib import Path
import ssl
import time

from elasticsearch import ApiError, Elasticsearch

from cloud_soc.detection.engine import detect_events, event_evidence
from cloud_soc.detection.worker import approved_rules
from cloud_soc.elastic.pagination import fetch_all_hits
from cloud_soc.elastic.repository import ensure_provenance_mapping, save_security_alert
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.portal.agent_status import parse_time
from cloud_soc.portal.log_contract import field
from cloud_soc.portal.mall_investigation import private_bytes
from cloud_soc.portal.mall_scope import scope_indices, validate_scope
from cloud_soc.portal.operations import Operations

RULES = frozenset({'WEB-ACCESS-01', 'WEB-AUTH-01', 'WEB-WAF-01'})
PRIVILEGES = ('read', 'view_index_metadata', 'create_doc', 'create', 'index', 'write',
              'delete', 'manage', 'create_index')


class LabError(ValueError):
    """Fixed public reason codes only; never include inputs or ES error bodies."""


def require(value, reason):
    if not value:
        raise LabError(reason)


def configuration(value):
    required = {'es_url', 'ca_file', 'reader_key_file', 'scope', 'organization', 'host', 'rule_ids'}
    require(isinstance(value, dict) and required <= value.keys() and
            set(value) <= required | {'writer_key_file', 'max_documents'}, 'config_invalid')
    require(value['es_url'] == 'https://127.0.0.1:19200', 'isolated_https_required')
    result = deepcopy(value)
    result['scope'] = validate_scope(value['scope'])
    require(result['scope'] is not None, 'lab_scope_required')
    for key in ('organization', 'host'):
        require(isinstance(value[key], str) and 0 < len(value[key]) <= 128 and
                value[key].isascii() and all(c.isalnum() or c in '._-' for c in value[key]), 'scope_invalid')
    for key in ('ca_file', 'reader_key_file', 'writer_key_file'):
        if key in value:
            require(isinstance(value[key], str) and Path(value[key]).is_absolute(), 'file_path_invalid')
    ids = value['rule_ids']
    require(isinstance(ids, list) and ids and all(isinstance(v, str) and v in RULES for v in ids)
            and len(set(ids)) == len(ids), 'mall_rules_required')
    result['max_documents'] = value.get('max_documents', 1000)
    require(type(result['max_documents']) is int and 1 <= result['max_documents'] <= 10000, 'capacity_invalid')
    return result


def client(config, role):
    """Separate private reader/create-only key files; no password/env/argv keys."""
    require(role + '_key_file' in config, 'writer_key_required')
    credential = json.loads(private_bytes(config[role + '_key_file'], 16384))
    expiration = credential.get('expires_at', credential.get('expiration'))
    require(type(expiration) is int and expiration > int(time.time() * 1000), 'key_expired_or_invalid')
    if 'expiration' in credential and 'expires_at' in credential:
        require(credential['expiration'] == credential['expires_at'], 'key_expiration_mismatch')
    try:
        encoded = credential['encoded']
        decoded = base64.b64decode(encoded, validate=True).decode('ascii')
        identifier, secret = decoded.split(':', 1)
        require(identifier and secret and not any(c.isspace() for c in decoded), 'key_invalid')
    except (KeyError, TypeError, ValueError, UnicodeError):
        raise LabError('key_invalid') from None
    # Both the certificate chain and the endpoint SAN/hostname remain verified.
    context = ssl.create_default_context(cafile=config['ca_file'])
    return Elasticsearch(config['es_url'], api_key=encoded, ssl_context=context,
                         request_timeout=15, max_retries=0, retry_on_timeout=False)


def permissions(es, scope, role):
    names = scope_indices(scope)
    response = es.security.has_privileges(
        cluster=['all', 'manage', 'manage_security', 'manage_api_key'],
        index=[{'names': list(names), 'privileges': list(PRIVILEGES)}])
    require(response.get('cluster') and not any(response['cluster'].values()), 'cluster_privilege_refused')
    for name in names:
        required = ({'read', 'view_index_metadata'} if role == 'reader' else
                    {'create_doc', 'view_index_metadata'} if name == scope['alerts'] else set())
        actual = response.get('index', {}).get(name, {})
        require(all(type(actual.get(p)) is bool and actual[p] == (p in required) for p in PRIVILEGES),
                'key_privilege_mismatch')


def run(reader, config, start, end, *, writer=None, write_alerts=False):
    """Validate the entire snapshot before any immutable alert create call."""
    config = configuration(config)
    lower, upper = parse_time(start), parse_time(end)
    require(lower is not None and upper is not None and 0 < (upper - lower).total_seconds() <= 86400,
            'bounded_time_range_required')
    scope = config['scope']
    permissions(reader, scope, 'reader')
    names = scope_indices(scope)
    resolved = reader.indices.resolve_index(name=','.join(names), expand_wildcards='none')
    require(not resolved.get('aliases') and not resolved.get('data_streams') and
            sorted(x['name'] for x in resolved.get('indices', [])) == sorted(names), 'concrete_indices_required')
    ensure_provenance_mapping(reader, scope['alerts'], apply=False)
    if write_alerts:
        require(writer is not None, 'writer_required')
        permissions(writer, scope, 'writer')
    query = {'bool': {'filter': [
        {'range': {'@timestamp': {'gte': lower.isoformat(), 'lt': upper.isoformat()}}},
        {'term': {'organization.id': config['organization']}}, {'term': {'host.id': config['host']}},
        {'term': {'service.name': 'security-mall'}}]}}
    events = []
    verifier = Operations(reader, organizations=[config['organization']], mall_scope=scope)
    for index in scope_indices(scope, 'normalized'):
        hits = fetch_all_hits(reader, index=index, query=query, max_documents=config['max_documents'])
        require(len(events) + len(hits) <= config['max_documents'], 'capacity_exceeded')
        for hit in hits:
            require(hit.get('_index') == index and isinstance(hit.get('_id'), str) and hit['_id'],
                    'normalized_reference_invalid')
            event = deepcopy(hit['_source'])
            stamp = parse_time(event.get('@timestamp'))
            require(stamp is not None and lower <= stamp < upper and
                    field(event, 'organization.id') == config['organization'] and
                    field(event, 'host.id') == config['host'] and field(event, 'service.name') == 'security-mall',
                    'event_scope_mismatch')
            raw = field(event, 'cloud_soc.provenance.raw')
            require(isinstance(raw, dict) and set(raw) == {'index', 'id'} and
                    raw['index'] in scope_indices(scope, 'raw'), 'raw_reference_invalid')
            event['_cloud_soc_meta'] = {'index': index, 'document_id': hit['_id']}
            evidence = event_evidence(event)
            require(evidence['complete'], 'incomplete_provenance')
            verified = verifier.evidence(evidence, organization=config['organization'])
            require(verified.get('state') == 'exact_reference' and
                    verified.get('integrity') == 'normalized_hash_verified' and
                    verified.get('security', {}).get('status') == 'recognized' and
                    verified['security']['adapter'] in ('security_mall_audit_v1', 'security_mall_edge_v1'),
                    'evidence_verification_failed')
            events.append(event)
    rejected = []
    detections = detect_events(events, approved_rules(additional_rule_ids=config['rule_ids']), rejected=rejected)
    require(not rejected, 'invalid_detection_input')
    # Build everything before the first create; no mappings/status/incident writes.
    alerts = [(make_alert_id(d), build_security_alert(d)) for d in detections]
    counts = {'mode': 'write_alerts' if write_alerts else 'dry_run', 'events': len(events),
              'detections': len(alerts), 'rules': dict(Counter(d['rule_id'] for d in detections)),
              'created': 0, 'existing': 0}
    if write_alerts:
        for identifier, document in alerts:
            response = save_security_alert(writer, document, index_name=scope['alerts'],
                document_id=identifier, index_prepared=True, refresh=False)
            result = response.get('result')
            require(result in ('created', 'existing'), 'immutable_write_failed')
            counts[result] += 1
    return counts


def main(argv=None, *, client_factory=client):
    parser = argparse.ArgumentParser(description='One-shot isolated Mall detection; default is read-only dry-run.')
    parser.add_argument('--config', required=True, type=Path)
    parser.add_argument('--start', required=True)
    parser.add_argument('--end', required=True)
    parser.add_argument('--write-alerts', action='store_true', help='Explicitly create immutable alerts with a separate key')
    args = parser.parse_args(argv)
    try:
        config = configuration(json.loads(private_bytes(args.config, 16384)))
        with ExitStack() as stack:
            reader = client_factory(config, 'reader')
            stack.callback(reader.close)
            writer = None
            if args.write_alerts:
                writer = client_factory(config, 'writer')
                stack.callback(writer.close)
            result = run(reader, config, args.start, args.end, writer=writer, write_alerts=args.write_alerts)
        print(json.dumps(result, sort_keys=True))
        return 0
    except LabError as error:
        print(json.dumps({'state': 'failed', 'reason': str(error)}))
        return 1
    except ApiError as error:
        status = error.meta.status
        print(json.dumps({'state': 'failed', 'reason': 'authentication_failed' if status == 401 else
            'permission_denied' if status == 403 else 'es_request_failed', 'http_status': status}))
        return 1
    except (OSError, ValueError, TypeError):
        print(json.dumps({'state': 'failed', 'reason': 'private_config_key_or_tls_invalid'}))
        return 1
    except Exception:
        print(json.dumps({'state': 'failed', 'reason': 'lab_detection_failed'}))
        return 1
if __name__ == '__main__':
    raise SystemExit(main())
