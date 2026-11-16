"""Project the metadata of a single Kubernetes audit stage."""
import json
import re
from uuid import UUID

from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import field
from cloud_soc.privacy import REDACTED, display

SOURCE = 'eks_audit'
VERSION = 'eks-audit-v1'
ADAPTER = 'eks_audit_v1'
FIELDS = tuple('eks_audit.' + key for key in ('schema', 'id', 'stage', 'verb', 'stage_at', 'status', 'decision', 'resource'))
STAGES = ('RequestReceived', 'ResponseStarted', 'ResponseComplete', 'Panic')
VERBS = ('get', 'list', 'watch', 'create', 'update', 'patch', 'delete', 'deletecollection', 'connect', 'proxy')


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError('duplicate_audit_key')
        result[key] = value
    return result


def interpret(source):
    if field(source, 'labels.log_source') != SOURCE:
        return None
    projected = field(source, 'eks_audit')
    raw = source.get('message')
    try:
        if isinstance(projected, dict) and type(projected.get('schema')) is int and projected['schema'] == 1:
            event = {'apiVersion': 'audit.k8s.io/v1', 'kind': 'Event', 'auditID': projected.get('id'),
                     'stage': projected.get('stage'), 'verb': projected.get('verb'), 'stageTimestamp': projected.get('stage_at'),
                     'responseStatus': {'code': projected.get('status')},
                     'annotations': {'authorization.k8s.io/decision': projected.get('decision')},
                     'objectRef': {'resource': projected.get('resource')}}
        elif isinstance(raw, str) and raw and len(raw) <= 262144 and len(raw.encode()) <= 262144:
            event = json.loads(raw, object_pairs_hook=unique_object)
        else:
            return None
        if field(event, 'apiVersion') != 'audit.k8s.io/v1' or field(event, 'kind') != 'Event':
            return None
        audit_id = field(event, 'auditID')
        if not isinstance(audit_id, str) or len(audit_id) != 36 or str(UUID(audit_id)) != audit_id:
            return None
    except (ValueError, RecursionError):
        return None
    stage, verb = event.get('stage'), event.get('verb')
    stamp = parse_time(event.get('stageTimestamp'))
    if stage not in STAGES or verb not in VERBS or stamp is None:
        return None
    result = {'category': 'configuration', 'action': 'kubernetes_api_' + verb,
              'outcome': 'unknown', 'audit_id': audit_id, 'audit_stage': stage}
    if stage in ('ResponseComplete', 'Panic'):
        code = field(event, 'responseStatus.code')
        if type(code) is int and 100 <= code <= 599:
            result['http_status'] = code
            if stage == 'ResponseComplete':
                result['outcome'] = 'failure' if code >= 400 else 'success' if 200 <= code < 300 else 'unknown'
        if stage == 'Panic':
            result['outcome'] = 'failure'
    annotations = event.get('annotations')
    decision = annotations.get('authorization.k8s.io/decision') if isinstance(annotations, dict) else None
    if decision in ('allow', 'forbid'):
        result['authorization_decision'] = decision
        if stage == 'ResponseComplete' and result.get('http_status') == 403 and decision == 'forbid':
            result['action'] = 'kubernetes_authorization_denied'
    for key in ('resource', 'subresource', 'namespace'):
        value = field(event, 'objectRef.' + key)
        if isinstance(value, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{0,127}', value):
            result[key] = value
    actor = field(event, 'user.username')
    if isinstance(actor, str) and len(actor) <= 256 and display(actor) not in (None, REDACTED):
        result['actor'] = display(actor)
    return {'adapter': ADAPTER, 'status': 'recognized' if stage in ('ResponseComplete', 'Panic') and result['outcome'] != 'unknown' else 'partial',
            'fields': result, 'occurred_at': iso(stamp), 'limitations': ['kubernetes_audit_stage_only', 'not_a_detection']}
