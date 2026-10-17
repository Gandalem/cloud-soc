"""Request evidence projections, separate from immutable evidence and human cases."""
from dataclasses import dataclass
from datetime import timedelta
import re

from cloud_soc.detection.engine import event_evidence, event_fingerprint
from cloud_soc.parsers.security_mall import ADAPTER as APP, VERSION as APP_VERSION, parse
from cloud_soc.parsers.security_mall_edge import ADAPTER as EDGE, VERSION as EDGE_VERSION, REQUEST_ID, validate, identifier as edge_identifier
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_access import LogPrincipal
from cloud_soc.portal.log_contract import document_reference, field

VERSION = 'mall-request-evidence-v1'
STREAMS = ('web', 'waf', 'app')
LIMITATIONS = ['request_id_not_origin_authentication', 'application_id_may_be_spoofed',
               'observed_ip_may_be_proxy', 'correlation_not_compromise_confirmation',
               'same_id_reuse_within_window_cannot_be_excluded']


def require(condition, code):
    if not condition:
        raise ValueError(code)


def token(value, limit=128):
    require(isinstance(value, str) and len(value) <= limit and
            re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]*', value) is not None, 'invalid_identifier')
    return value


def exact_index(value):
    require(isinstance(value, str) and len(value) <= 255 and
            re.fullmatch(r'[a-z0-9][a-z0-9_.-]*', value) is not None, 'invalid_index')
    return value


@dataclass(frozen=True)
class Scope:
    """Trusted deployment binding, never read from an event's site/collector claims."""
    organization: str
    site: str
    host: str
    service: str
    normalized_indices: tuple
    app_indices: tuple
    edge_indices: tuple
    alert_indices: tuple
    window_seconds: int = 30
    max_events: int = 10000

    def __post_init__(self):
        for value in (self.organization, self.site, self.host, self.service):
            token(value)
        require(type(self.window_seconds) is int and 1 <= self.window_seconds <= 120, 'invalid_window')
        require(type(self.max_events) is int and 1 <= self.max_events <= 100000, 'invalid_capacity')
        for names in (self.normalized_indices, self.app_indices, self.edge_indices, self.alert_indices):
            require(type(names) is tuple and 0 < len(names) <= 32 and len(set(names)) == len(names), 'exact_scope_required')
            for value in names:
                exact_index(value)
        require(not set(self.app_indices) & set(self.edge_indices), 'source_scope_overlap')
        for name in self.app_indices + self.edge_indices:
            document_reference(name, 'scope-check')

    @property
    def identity(self):
        return {'organization': self.organization, 'site': self.site, 'host': self.host, 'service': self.service}

    def visible(self, principal):
        # Same server-owned principal organization semantics as Operations/CaseStore.
        return isinstance(principal, LogPrincipal) and (principal.organizations is None or
                                                       self.organization in principal.organizations)


def reference(value, allowed):
    require(isinstance(value, dict) and set(value) == {'index', 'id'}, 'invalid_reference')
    require(value['index'] in allowed, 'reference_scope_mismatch')
    return {'index': exact_index(value['index']), 'id': token(value['id'], 512)}


def select_event(hit, scope):
    """Only validated metadata leaves this boundary, never raw fields or messages."""
    source = hit.get('_source')
    require(isinstance(source, dict), 'event_source_missing')
    require(field(source, 'organization.id') == scope.organization and
            field(source, 'host.id') == scope.host and field(source, 'service.name') == scope.service,
            'event_scope_mismatch')
    normalized = reference({'index': hit.get('_index'), 'id': hit.get('_id')}, scope.normalized_indices)
    adapter = field(source, 'cloud_soc.detail.adapter')
    require(field(source, 'cloud_soc.parse_status') == 'recognized' and field(source, 'event.kind') == 'event',
            'event_not_recognized')
    require(field(source, 'cloud_soc.normalizer_version') == {APP: APP_VERSION, EDGE: EDGE_VERSION}.get(adapter)
            and adapter in (APP, EDGE), 'event_adapter_unsupported')
    raw = field(source, 'cloud_soc.provenance.raw')
    raw = reference(raw, scope.app_indices if adapter == APP else scope.edge_indices)
    require(field(source, 'cloud_soc.provenance.schema_version') == 1, 'provenance_invalid')
    occurred, ingested = (parse_time(field(source, path)) for path in ('@timestamp', 'event.ingested'))
    require(occurred is not None and ingested is not None, 'event_time_invalid')
    request_id = field(source, 'http.request.id')
    require(request_id is None or isinstance(request_id, str) and REQUEST_ID.fullmatch(request_id), 'request_id_invalid')
    identifier = token(field(source, 'event.id'), 128)
    if adapter == APP:
        app = field(source, 'cloud_soc.security_mall')
        require(isinstance(app, dict), 'application_metadata_missing')
        body = {key: app[key] for key in ('schema_version', 'account_id', 'account_key_id',
                 'resource_type', 'authorization_reason') if key in app}
        body.update({'@timestamp': iso(occurred), 'event_id': identifier, 'service_name': scope.service,
                     'source_ip': field(source, 'source.ip'), 'event_action': field(source, 'event.action'),
                     'event_outcome': field(source, 'event.outcome'), 'request_id': request_id})
        parsed = parse(body)
        metadata = {name: parsed[name] for name in ('action', 'outcome', 'account_id', 'account_key_id',
                     'resource_type', 'authorization_reason') if name in parsed}
        stream = 'app'
    else:
        require(adapter == EDGE, 'event_adapter_unsupported')
        body = field(source, 'cloud_soc.security_mall_edge')
        # Exact allowlist enforced by the existing native/access metadata parser.
        body = validate(body)
        require(body['request_id'] == request_id and parse_time(body['timestamp']) == occurred and
                body['source_ip'] == field(source, 'source.ip') and body['service_name'] == scope.service,
                'edge_metadata_mismatch')
        require(identifier == edge_identifier(body, scope.organization, scope.host), 'edge_identity_mismatch')
        stream = 'web' if body['stream'] == 'access' else 'waf'
        require(field(source, 'event.action') == ('http_access' if stream == 'web' else 'waf_rule_match'),
                'edge_action_mismatch')
        metadata = ({'method': body['method'], 'path': body['path'], 'status_code': body['status_code'],
                     'duration_us': body['duration_us']} if stream == 'web' else
                    {'rules': body['rules'], 'engine_mode': body['engine_mode'], 'blocked': body['blocked']})
    hashed = dict(source, _cloud_soc_meta={'index': normalized['index'], 'document_id': normalized['id']})
    evidence = event_evidence(hashed)
    require(evidence['complete'], 'evidence_incomplete')
    result = {'event_id': identifier, 'stream': stream, 'request_id': request_id,
              'occurred_at': iso(occurred), 'source_ip': field(source, 'source.ip'), 'metadata': metadata}
    # Receipt time and provenance can differ on a duplicate delivery; retain both observations.
    result['key'] = event_fingerprint([scope.identity, stream, identifier, result['occurred_at']])
    return result, dict(evidence, ingested_at=iso(ingested))


def select_alert(hit, scope):
    source = hit.get('_source')
    require(isinstance(source, dict) and field(source, 'organization.id') == scope.organization, 'alert_scope_mismatch')
    ref = reference({'index': hit.get('_index'), 'id': hit.get('_id')}, scope.alert_indices)
    rule = field(source, 'rule.id')
    require(rule in ('WEB-ACCESS-01', 'WEB-AUTH-01'), 'alert_rule_unsupported')
    evidence = field(source, 'cloud_soc.provenance.evidence')
    require(isinstance(evidence, list) and 0 < len(evidence) <= scope.max_events, 'alert_evidence_invalid')
    selected = []
    for item in evidence:
        require(isinstance(item, dict), 'alert_evidence_invalid')
        digest = item.get('event_hash')
        require(digest is None or isinstance(digest, str) and re.fullmatch('[0-9a-f]{64}', digest), 'evidence_hash_invalid')
        selected.append({'normalized': reference(item.get('normalized'), scope.normalized_indices),
                         'raw': reference(item.get('raw'), scope.app_indices + scope.edge_indices), 'event_hash': digest})
    severity, score, level = (field(source, 'cloud_soc.' + name) for name in ('severity', 'risk_score', 'risk_level'))
    require(severity in ('low', 'medium', 'high', 'critical') and type(score) is int and 0 <= score <= 100 and
            level in ('low', 'medium', 'high', 'critical'), 'alert_risk_invalid')
    stamp = parse_time(source.get('@timestamp'))
    require(stamp is not None, 'alert_time_invalid')
    return {'alert': ref, 'rule_id': rule, 'occurred_at': iso(stamp), 'rule_severity': severity,
            'risk_score': score, 'risk_level': level, 'evidence': selected}


def bundle(scope, events, *, ambiguous=False):
    events = sorted(events, key=lambda e: (parse_time(e['occurred_at']), e['key']))
    present = {name: any(e['stream'] == name for e in events) for name in STREAMS}
    request_id = events[0]['request_id']
    identifier = event_fingerprint([VERSION, scope.identity, request_id, events[0]['key'], ambiguous])
    result = {'schema_version': 1, 'version': VERSION, 'id': identifier, 'scope': scope.identity,
              'request_id': request_id, 'state': 'ambiguous' if ambiguous else
              'unlinked' if request_id is None else 'complete' if all(present.values()) else 'incomplete',
              'present': present, 'missing': [name for name in STREAMS if not present[name]],
              'event_ids': sorted({e['event_id'] for e in events}), 'events': events, 'related_alerts': [],
              'basis': ['single_event_ambiguous_request_id'] if ambiguous else
                       ['exact_scope_and_request_id', 'bounded_event_time_span'] if request_id else ['single_event_no_request_id'],
              'uncertainties': list(LIMITATIONS)}
    if ambiguous:
        result['uncertainties'].append('request_id_reused_multiple_web_events_no_join')
    if not all(present.values()):
        result['uncertainties'].append('missing_streams_not_proof_of_absence')
    web403 = any(e['stream'] == 'web' and e['metadata']['status_code'] == 403 for e in events)
    denied = any(e['stream'] == 'app' and e['metadata'].get('authorization_reason') in
                 ('not_owner', 'admin_required', 'unauthenticated') and e['metadata']['outcome'] == 'failure' for e in events)
    result['assessment'] = {'application_denial_observed': denied,
                            'http_403_observed': web403, 'http_403_cause':
                            'consistent_with_application_denial' if web403 and denied else 'undetermined' if web403 else 'not_observed',
                            'waf_block_observed': False if present['waf'] else None,
                            'origin_authenticated': False, 'compromise_confirmed': False}
    return result


def correlate(scope, events, alerts):
    """Deterministic view over persisted metadata, order-independent and late-update safe."""
    keyed = {}
    requests = []
    for event in events:
        if event['request_id'] is None:
            requests.append(bundle(scope, [event]))
        else:
            keyed.setdefault(event['request_id'], []).append(event)
    for candidates in keyed.values():
        candidates.sort(key=lambda e: (parse_time(e['occurred_at']), e['key']))
        while candidates:
            first = parse_time(candidates[0]['occurred_at'])
            group = [e for e in candidates if parse_time(e['occurred_at']) - first <= timedelta(seconds=scope.window_seconds)]
            candidates = candidates[len(group):]
            # Distinct web access observations contradict a unique request anchor.
            if sum(e['stream'] == 'web' for e in group) > 1:
                requests.extend(bundle(scope, [e], ambiguous=True) for e in group)
            else:
                requests.append(bundle(scope, group))
    requests.sort(key=lambda b: b['id'])
    # Match exact provenance/hash through an index, not a request-id-only join.
    evidence_index = {}
    for request in requests:
        for event in request['events']:
            for observation in event['observations']:
                key = event_fingerprint([observation['normalized'], observation['raw'], observation['event_hash']])
                evidence_index.setdefault(key, set()).add(request['id'])
    links = []
    for alert in sorted(alerts, key=lambda a: (a['alert']['index'], a['alert']['id'])):
        linked, unresolved = set(), []
        for evidence in alert['evidence']:
            key = event_fingerprint([evidence['normalized'], evidence['raw'], evidence['event_hash']])
            found = evidence_index.get(key, ()) if evidence['event_hash'] is not None else ()
            if found:
                linked.update(found)
            else:
                unresolved.append({'reference': evidence, 'reason': 'evidence_missing_or_integrity_unverified'})
        for request in requests:
            if request['id'] in linked:
                request['related_alerts'].append(alert['alert'])
        links.append({**{k: v for k, v in alert.items() if k != 'evidence'}, 'request_bundle_ids': sorted(linked),
                      'evidence': alert['evidence'],
                      'state': 'complete' if not unresolved else 'incomplete', 'unresolved': unresolved,
                      'basis': 'exact_raw_normalized_reference_and_detector_event_hash',
                      'interpretation': 'suspicious_authentication_sequence' if alert['rule_id'] == 'WEB-AUTH-01'
                      else 'application_access_attempt_denied'})
    result = {'schema_version': 1, 'version': VERSION, 'scope': scope.identity, 'requests': requests, 'alert_links': links}
    # No wall clock in the revision: replaying identical input is idempotent.
    result['revision'] = event_fingerprint(result)
    return result
