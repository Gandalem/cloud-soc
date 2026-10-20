"""Actual runtime acceptance: missing input, partial searches and old evidence never pass."""
from datetime import datetime, timezone
import http.cookiejar
import json
from pathlib import Path
import ssl
import urllib.error
import urllib.parse
import urllib.request

from cloud_soc.deployment.contract import WORKERS, digest, policy, stamp


def checked(result):
    if result.get('timed_out') or result.get('terminated_early') or result.get('_shards', {}).get('failed', 0):
        raise ValueError('Incomplete evidence search')
    return result


def evidence(client, since, *, probe=None, now=None):
    """Read live ES documents, never insert a synthetic success or modify an original."""
    from cloud_soc.processing.contract import NORMALIZED, STATUS, normalize
    from cloud_soc.portal.operations import Operations
    now = now or datetime.now(timezone.utc)
    def search(index, **kw):
        return checked(client.search(index=index, allow_partial_search_results=False, **kw))
    result = {'workers': {}, 'issues': [], 'receipt_floor': since}
    statuses = search(STATUS, size=30, query={'match_all': {}})['hits']['hits']
    rows = {h['_id']: h['_source'] for h in statuses}
    for name in WORKERS:
        row = rows.get(name)
        ok = bool(row and row.get('state') in ('success', 'waiting', 'running') and row.get('last_success')
                  and 0 <= (now-stamp(row['last_success'])).total_seconds() <= 300 and not row.get('error'))
        if not ok:
            result['issues'].append(name + '_not_verified')
        result['workers'][name] = {'verified': ok, 'state': row.get('state') if row else 'missing',
            'checkpoint': row.get('checkpoint') if row else None,
            'lag_seconds': max(0, int((now-stamp(row['checkpoint'])).total_seconds())) if row and row.get('checkpoint') else None}
        if name in ('normalizer-priority', 'detector-priority', 'detector-additional'):
            lag = result['workers'][name]['lag_seconds']
            if lag is None or lag > 180:
                result['issues'].append(name + '_realtime_lag')
    new = search(NORMALIZED, size=20, sort=[{'cloud_soc.normalized_at': 'desc'}], track_total_hits=True,
        query={'bool': {'filter': [{'range': {'cloud_soc.normalized_at': {'gte': since}}},
                                   {'range': {'event.ingested': {'gte': since}}}]}})
    exact = 0
    for hit in new['hits']['hits']:
        ref = hit['_source']['cloud_soc']['provenance']['raw']
        raw = client.get(index=ref['index'], id=ref['id'])
        if not raw.get('found') or raw['_source'].get('organization') != hit['_source'].get('organization'):
            raise ValueError('Live normalization reference/scope mismatch')
        identifier, record, event = normalize(raw, processed_at=hit['_source']['cloud_soc']['normalized_at'])
        if identifier != hit['_id'] or record['status'] != 'normalized' or event is None:
            raise ValueError('Live raw document cannot reproduce its normalization')
        exact += 1
    result['new_normalized_count'] = new['hits']['total']['value']
    result['exact_live_normalized_references'] = exact
    if not exact:
        result['issues'].append('new_live_normalization_absent')
    # Every acceptance requires a new alert; an old AUTH alert cannot certify
    # today's installation merely because unrelated new logs were received.
    query = {'bool': {'filter': [{'term': {'rule.id': 'AUTH-001'}},
                                {'range': {'@timestamp': {'gte': since, 'lte': now.isoformat()}}}]}}
    if probe:
        query['bool']['filter'] += [{'term': {'source.ip': probe['source_ip']}}, {'range': {'@timestamp': {'gte': probe['started_at']}}}]
    alerts = search('security-alerts', size=20, query=query, sort=[{'@timestamp': 'desc'}])
    verified = []
    reader = Operations(client)
    for hit in alerts['hits']['hits']:
        references = hit['_source'].get('cloud_soc', {}).get('provenance', {}).get('evidence', [])
        if not references:
            continue
        for reference in references:
            r = reader.evidence(reference, organization=hit['_source']['organization']['id'])
            if r.get('state') != 'exact_reference' or r.get('integrity') != 'normalized_hash_verified':
                raise ValueError('Actual alert evidence failed exact-reference verification')
        verified.append({'id': hit['_id'], 'rule': 'AUTH-001', 'exact_evidence': len(references), 'generated_for_probe': bool(probe)})
    result['alerts'] = verified
    if not verified:
        result['issues'].append('actual_detection_evidence_absent')
    if probe:
        from cloud_soc.detection.engine import observation_identity, ssh_collection_mirror
        attempts = search(NORMALIZED, size=100, track_total_hits=True, query={'bool': {'filter': [
            {'term': {'source.ip': probe['source_ip']}}, {'term': {'event.outcome': 'failure'}},
            {'term': {'network.protocol': 'ssh'}},
            {'range': {'@timestamp': {'gte': probe['started_at']}}}]}})
        if attempts['hits']['total']['value'] > len(attempts['hits']['hits']):
            raise ValueError('Probe observations exceed the complete search budget')
        observations, seen = [], set()
        for hit in attempts['hits']['hits']:
            event = hit['_source'];identifier = observation_identity(event)
            if identifier in seen or any(ssh_collection_mirror(event, old) for old in observations):
                continue
            seen.add(identifier);observations.append(event)
        result['probe_raw_normalized_documents'] = attempts['hits']['total']['value']
        result['probe_normalized_attempts'] = len(observations)
        if result['probe_normalized_attempts'] != 10 or not any(a['exact_evidence'] == 10 for a in verified):
            result['issues'].append('probe_boundary_or_final_alert_not_verified')
    result['verified'] = not result['issues']
    return result


def portal(origin, ca_file, password):
    parsed = urllib.parse.urlsplit(origin)
    if parsed.scheme != 'https' or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError('Explicit HTTPS portal origin required')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}),
        urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()),
        urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca_file))))
    def request(path, body=None, csrf=None):
        headers = {}
        if body is not None:
            headers = {'Content-Type': 'application/json', 'X-Cloud-SOC': 'portal', 'Origin': origin}
            if csrf:
                headers['X-CSRF-Token'] = csrf
        req = urllib.request.Request(origin + path, data=json.dumps(body).encode() if body is not None else None, headers=headers)
        with opener.open(req, timeout=40) as response:
            if response.status != 200:
                raise ValueError('Portal API failed')
            return json.loads(response.read(4 * 1024 * 1024))
    mode = request('/api/auth/config')['mode']
    if mode == 'session':
        request('/api/auth/login', {'username': 'admin', 'password': password})
    elif mode == 'basic':
        import base64
        opener.addheaders = [('Authorization', 'Basic ' + base64.b64encode(('admin:' + password).encode()).decode())]
    else:
        raise ValueError('Unknown portal authentication mode')
    csrf = None
    try:
        me = request('/api/auth/me');csrf = me.get('csrf')
        responses = {p: request(p) for p in ('/api/healthz', '/api/runtime', '/api/operations/status', '/api/operations',
            '/api/alerts/notices', '/api/dashboards', '/api/cases', '/api/agents/status')}
        runtime = responses['/api/runtime']
        from cloud_soc.deployment.contract import ALL_WORKERS
        if runtime.get('state') != 'configured' or set(runtime.get('required_workers', [])) != set(ALL_WORKERS):
            raise ValueError('Portal does not serve the managed runtime contract')
        status = responses['/api/operations/status']
        if not all(k in status for k in ('priority_normalizer', 'priority_detector', 'additional_detector', 'late_review', 'historical_backlog')):
            raise ValueError('Dashboard API omitted required independent processing state')
        if status.get('realtime_coverage', {}).get('state') in ('blocked', 'unknown', 'not_started', 'delayed'):
            raise ValueError('Live dashboard coverage is unavailable or delayed')
        slack = request('/api/settings/notifications/slack')
        if not isinstance(slack.get('configured'), bool) or 'webhook_url' in slack:
            raise ValueError('Notification settings state is unsafe')
        heartbeat = slack.get('worker', {}).get('heartbeat')
        if heartbeat is None or datetime.now(timezone.utc).timestamp() - heartbeat > 60:
            raise ValueError('Notification worker heartbeat unavailable')
        for path in ('/', '/dashboard.html', '/dashboard.js', '/shell.js'):
            with opener.open(origin + path, timeout=30) as response:
                if response.status != 200 or not response.read():
                    raise ValueError('Dashboard asset unavailable')
        return {'verified': True, 'tls_verified': True, 'api_count': len(responses) + 2,
                'notification_worker_verified': True, 'actual_slack_channel_receipt': 'not_verified_by_http_acceptance',
                'dashboard_current_and_backlog_states_verified': True, 'saved_settings_changed': False}
    finally:
        if mode == 'session' and csrf:
            request('/api/auth/logout', {}, csrf)


def main():
    import sys
    from cloud_soc.portal.app import create_app
    data = json.load(sys.stdin);app = create_app();client = app.extensions['monitor']
    result = evidence(client, data['since'], probe=data.get('probe'))
    result['policy_sha256'] = digest(policy(Path('/app')))
    print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('runtime_acceptance_failed; credentials and source payloads omitted') from None
