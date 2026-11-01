"""Authenticated, organization-scoped multicloud audit dashboard."""
from flask import Blueprint, current_app, g, jsonify, request, send_from_directory
from pathlib import Path

blueprint = Blueprint('multicloud', __name__)
ROOT = Path(__file__).resolve().parents[3] / 'prototype'
FIELDS = ['@timestamp', 'organization.id', 'cloud.provider', 'cloud.account.id', 'cloud.region',
          'event.action', 'event.outcome', 'event.dataset', 'event.id', 'user.id', 'source.ip', 'resource.id']


@blueprint.get('/multicloud')
def page():
    return send_from_directory(ROOT, 'multicloud.html')


@blueprint.get('/multicloud/<asset>')
def asset(asset):
    from flask import abort
    if asset not in ('multicloud.js', 'multicloud.css'):
        abort(404)
    return send_from_directory(ROOT, asset)


@blueprint.get('/api/multicloud')
def summary():
    principal = g.log_principal
    if set(request.args) - {'hours', 'provider', 'outcome'}:
        return jsonify(error='지원하지 않는 필터입니다.'), 400
    try:
        hours = int(request.args.get('hours', '24'))
        if hours not in (1, 6, 24, 168):
            raise ValueError()
        provider, outcome = request.args.get('provider'), request.args.get('outcome')
        if provider and provider not in ('aws', 'azure', 'naver'):
            raise ValueError()
        if outcome and outcome not in ('success', 'failure', 'unknown'):
            raise ValueError()
    except ValueError:
        return jsonify(error='필터 값이 올바르지 않습니다.'), 400
    filters = [{'range': {'@timestamp': {'gte': f'now-{hours}h', 'lte': 'now'}}}]
    if principal.organizations is not None:
        filters.append({'terms': {'organization.id': list(principal.organizations)}})
    if provider:
        filters.append({'term': {'cloud.provider': provider}})
    if outcome:
        filters.append({'term': {'event.outcome': outcome}})
    es = current_app.extensions.get('monitor')
    if es is None:
        return jsonify(error='로그 조회 연결이 설정되지 않았습니다.'), 503
    try:
        response = es.search(index='soc-multicloud-*', ignore_unavailable=True,
            size=100, track_total_hits=True, source=FIELDS,
            query={'bool': {'filter': filters}}, sort=[{'@timestamp': 'desc'}, {'event.id': 'asc'}],
            aggregations={
                'providers': {'terms': {'field': 'cloud.provider', 'size': 3}, 'aggs': {
                    'last_event': {'max': {'field': '@timestamp'}},
                    'failures': {'filter': {'term': {'event.outcome': 'failure'}}}}},
                'outcomes': {'terms': {'field': 'event.outcome', 'size': 3}},
                'timeline': {'date_histogram': {'field': '@timestamp', 'fixed_interval': '1h' if hours >= 24 else '5m', 'min_doc_count': 0}},
                'actions': {'terms': {'field': 'event.action', 'size': 10}}
            })
        if response.get('timed_out') or response.get('_shards', {}).get('failed', 0):
            return jsonify(error='일부 로그를 조회하지 못했습니다. 다시 시도하세요.'), 503
        return jsonify(total=response['hits']['total']['value'],
            events=[h['_source'] for h in response['hits']['hits']],
            metrics=response.get('aggregations', {}))
    except Exception:
        return jsonify(error='클라우드 보안 로그를 조회하지 못했습니다.'), 503
