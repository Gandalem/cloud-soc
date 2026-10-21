"""Shared, bounded form/import contract. It compiles to the existing rule engine."""
from copy import deepcopy
import csv
import io
import json
import re

from cloud_soc.detection.rule_loader import validate_rule

SCHEMA_VERSION = 1
MAX_RULES = 100
MAX_FILE_BYTES = 262144

# Field capabilities drive both the editor and server validation. No executable expressions.
FIELDS = {
    'host.id': ('호스트', 'text'), 'service.id': ('사이트 ID', 'text'),
    'service.name': ('서비스', 'text'), 'source.ip': ('출발지 IP', 'text'),
    'user.name': ('계정 이름', 'text'), 'user.id': ('계정 ID', 'text'),
    'event.action': ('행동', 'text'), 'event.outcome': ('결과', 'text'),
    'event.category': ('이벤트 종류', 'text'), 'network.protocol': ('프로토콜', 'text'),
    'http.response.status_code': ('HTTP 응답 코드', 'number'),
    'http.request.method': ('HTTP 요청 방식', 'text'),
    'cloud_soc.security_mall.resource_type': ('자원 종류', 'text'),
    'cloud_soc.security_mall.authorization_reason': ('접근 거부 사유', 'text'),
    'cloud_soc.security_mall.account_id': ('가명 계정', 'text'),
    'cloud_soc.security_mall.account_key_id': ('계정 가명화 키 버전', 'text'),
}
OPERATORS = {'equals': '같음', 'not_equals': '다름', 'contains': '포함',
             'in': '목록 중 하나', 'exists': '값 존재', 'greater_than': '초과'}
GROUPS = ('host.id', 'service.id', 'source.ip', 'user.name', 'user.id',
          'cloud_soc.security_mall.account_id', 'cloud_soc.security_mall.account_key_id')
SOURCES = {
    'ssh': {'label': 'SSH 인증', 'adapters': ['linux_ssh_v1', 'linux_ssh_v2'],
            'groups': ['host.id', 'source.ip'], 'category': 'authentication'},
    'windows': {'label': 'Windows 보안', 'adapters': ['windows_security_v1'],
                'groups': ['host.id', 'source.ip'], 'category': 'authentication'},
    'web': {'label': '웹 접근', 'adapters': ['web_access_site_v2'],
            'groups': ['host.id', 'service.id', 'source.ip'], 'category': 'web'},
    'waf': {'label': 'ModSecurity WAF', 'adapters': ['modsecurity_audit_v1'],
            'groups': ['host.id', 'service.id', 'source.ip'], 'category': 'web'},
    'mall': {'label': '애플리케이션 감사 · Security Mall', 'adapters': ['security_mall_audit_v1'],
             'groups': ['host.id', 'source.ip'], 'category': 'iam'},
    'mall_waf': {'label': 'Security Mall WAF', 'adapters': ['security_mall_edge_v1'],
                 'groups': ['host.id', 'source.ip'], 'category': 'web'},
}
SOURCE_FIELDS = {
    'ssh': {'host.id', 'source.ip', 'user.name', 'event.action', 'event.outcome', 'event.category', 'network.protocol'},
    'windows': {'host.id', 'source.ip', 'user.name', 'user.id', 'event.action', 'event.outcome', 'event.category'},
    'web': {'host.id', 'service.id', 'source.ip', 'event.action', 'http.response.status_code', 'http.request.method'},
    'waf': {'host.id', 'service.id', 'source.ip', 'event.action', 'http.request.method'},
    'mall': {'host.id', 'source.ip', 'service.name', 'event.action', 'event.outcome', 'event.category',
             'cloud_soc.security_mall.resource_type', 'cloud_soc.security_mall.authorization_reason',
             'cloud_soc.security_mall.account_id', 'cloud_soc.security_mall.account_key_id'},
    'mall_waf': {'host.id', 'source.ip', 'service.name', 'event.action'},
}
KEYS = {'schema_version', 'key', 'name', 'description', 'source', 'kind', 'conditions',
        'group_by', 'count', 'window_seconds', 'cooldown_seconds', 'success_seconds', 'severity'}
CSV_COLUMNS = ['key', 'name', 'description', 'source', 'kind', 'field', 'operator', 'value',
               'group_by', 'count', 'window_seconds', 'cooldown_seconds', 'success_seconds', 'severity']


class AuthoringError(ValueError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def need(value, code):
    if not value:
        raise AuthoringError(code)


def text(value, limit=256, *, empty=False):
    need(isinstance(value, str) and (empty or bool(value.strip())) and len(value) <= limit
         and not any(ord(c) < 32 and c not in '\n\t' for c in value), 'text_invalid')
    return value.strip()


def bounded(value, low, high):
    need(type(value) is int and low <= value <= high, 'number_out_of_range')
    return value


def normalize(value):
    need(isinstance(value, dict) and set(value) == KEYS, 'definition_fields_invalid')
    d = deepcopy(value)
    need(type(d['schema_version']) is int and d['schema_version'] == SCHEMA_VERSION, 'schema_unsupported')
    need(isinstance(d['key'], str) and re.fullmatch(r'[A-Z][A-Z0-9-]{2,63}', d['key']), 'rule_key_invalid')
    d['name'] = text(d['name'], 160)
    d['description'] = text(d['description'], 1000, empty=True)
    need(isinstance(d['source'], str) and d['source'] in SOURCES, 'source_unsupported')
    need(d['kind'] in ('single', 'threshold', 'sequence', 'waf'), 'kind_unsupported')
    need(d['severity'] in ('low', 'medium', 'high', 'critical'), 'severity_invalid')
    need(isinstance(d['group_by'], list) and all(isinstance(f, str) for f in d['group_by'])
         and len(d['group_by']) <= 6 and len(set(d['group_by'])) == len(d['group_by'])
         and all(f in GROUPS and f in SOURCE_FIELDS[d['source']] for f in d['group_by']), 'groups_invalid')
    # Site and collector boundaries cannot be removed through a form or an import.
    d['group_by'] = list(dict.fromkeys([*SOURCES[d['source']]['groups'], *d['group_by']]))
    bounded(d['count'], 1, 10000)
    bounded(d['window_seconds'], 1, 3600)
    bounded(d['cooldown_seconds'], 0, 3600)
    bounded(d['success_seconds'], 0, 3600)
    need(isinstance(d['conditions'], list) and len(d['conditions']) <= 12, 'conditions_invalid')
    for c in d['conditions']:
        need(isinstance(c, dict) and set(c) == {'field', 'operator', 'value'}, 'condition_invalid')
        f, op, v = c['field'], c['operator'], c['value']
        need(isinstance(f, str) and f in SOURCE_FIELDS[d['source']] and isinstance(op, str)
             and op in OPERATORS, 'condition_unsupported')
        if op == 'exists':
            need(type(v) is bool, 'condition_value_invalid')
        else:
            values = v if op == 'in' else [v]
            need(isinstance(values, list) and 1 <= len(values) <= 16, 'condition_value_invalid')
            for item in values:
                if FIELDS[f][1] == 'number':
                    bounded(item, 100, 599)
                else:
                    text(item, 128)
            need(op != 'greater_than' or FIELDS[f][1] == 'number', 'operator_type_invalid')
            need(op != 'contains' or FIELDS[f][1] != 'number', 'operator_type_invalid')
    if d['kind'] == 'single':
        need(d['count'] == 1 and d['cooldown_seconds'] == 0 and d['success_seconds'] == 0,
             'single_bounds_invalid')
        d['window_seconds'] = 1
    elif d['kind'] == 'sequence':
        need(d['source'] in ('ssh', 'mall') and d['success_seconds'] > 0, 'sequence_source_invalid')
        need(not any(c['field'] == 'event.outcome' for c in d['conditions']), 'sequence_outcome_reserved')
        account = ['user.name'] if d['source'] == 'ssh' else [
            'cloud_soc.security_mall.account_id', 'cloud_soc.security_mall.account_key_id']
        d['group_by'] = list(dict.fromkeys([*d['group_by'], *account]))
    elif d['kind'] == 'waf':
        need(d['source'] in ('waf', 'mall_waf') and d['success_seconds'] == 0, 'waf_source_invalid')
        if d['source'] == 'mall_waf':
            need(d['count'] == 1 and d['cooldown_seconds'] == 0, 'mall_waf_bounds_invalid')
    else:
        need(d['success_seconds'] == 0, 'success_window_not_applicable')
    need(d['source'] not in ('waf', 'mall_waf') or d['kind'] == 'waf', 'waf_kind_required')
    return d


def compile_rule(definition, organization):
    d = normalize(definition)
    need(isinstance(organization, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', organization),
         'organization_invalid')
    conditions = [
        {'field': 'organization.id', 'operator': 'equals', 'value': organization},
        {'field': 'cloud_soc.detail.adapter', 'operator': 'in', 'value': SOURCES[d['source']]['adapters']},
        *deepcopy(d['conditions']),
    ]
    rule = {'id': d['key'], 'name': d['name'], 'description': d['description'], 'enabled': True,
            'type': d['kind'], 'severity': d['severity'], 'conditions': conditions,
            'group_by': ['organization.id', *d['group_by']], 'threshold': {'count': d['count']},
            'time_window': {'seconds': d['window_seconds']}, 'cooldown': {'seconds': d['cooldown_seconds']},
            'alert': {'title': d['name'], 'message': d['description'] or summary(d),
                      'category': SOURCES[d['source']]['category'], 'tags': ['managed-rule']}}
    rule['scoring_policy'] = 'evidence-first-v1'
    if d['kind'] == 'sequence':
        rule['success_window'] = {'seconds': d['success_seconds']}
        conditions.append({'field': 'event.outcome', 'operator': 'in', 'value': ['failure', 'success']})
        if d['source'] == 'mall':
            conditions.append({'field': 'event.action', 'operator': 'equals', 'value': 'login'})
    if d['kind'] == 'waf':
        from cloud_soc.detection.profiles import catalog
        source_id = 'WEB-SITE-WAF-001' if d['source'] == 'waf' else 'WEB-WAF-01'
        base = deepcopy(next(r for r in catalog(include_applications=d['source'] == 'mall_waf') if r['id'] == source_id))
        base.update({k: rule[k] for k in ('id', 'name', 'description', 'enabled', 'severity', 'alert',
                                         'threshold', 'time_window', 'cooldown')})
        base['scoring_policy'] = rule['scoring_policy']
        base['conditions'] = [*base['conditions'], *conditions]
        if d['source'] == 'waf':
            base['metadata_profile'] = 'modsecurity_audit_v1'
            base['group_by'] = rule['group_by']
            base['distinct']['count'] = d['count']
            base['required_fields'] = list(dict.fromkeys([*base['required_fields'], *rule['group_by']]))
        else:
            base['metadata_profile'] = 'security_mall_edge_v1'
        rule = base
    validate_rule(rule)
    return rule


def summary(d):
    source = SOURCES[d['source']]['label']
    group = '·'.join(FIELDS[f][0] for f in d['group_by'])
    conditions = ' · '.join(FIELDS[c['field']][0] + ' ' + OPERATORS[c['operator']] + ' ' +
                            json.dumps(c['value'], ensure_ascii=False) for c in d['conditions']) or '해당 출처 이벤트'
    if d['kind'] == 'single':
        return f'{source}: {conditions} 관측 시 경보 · 조직별 {group}'
    suffix = f" → 마지막 해당 실패 후 {d['success_seconds']}초 안에 성공" if d['kind'] == 'sequence' else ''
    return f"{source}: 같은 {group}에서 {conditions}, 최근 {d['window_seconds']}초 내 {d['count']}회{suffix} 관측 시 경보"


def example(template='ssh_failures'):
    d = dict(schema_version=1, key='CUSTOM-AUTH-001', name='반복 로그인 실패', description='',
             source='ssh', kind='threshold', conditions=[{'field': 'event.outcome', 'operator': 'equals', 'value': 'failure'}],
             group_by=['host.id', 'source.ip'], count=10, window_seconds=300, cooldown_seconds=300,
             success_seconds=0, severity='medium')
    if template == 'web_errors':
        d.update(key='CUSTOM-WEB-001', name='반복 웹 오류', source='web', count=20,
                 conditions=[{'field': 'http.response.status_code', 'operator': 'equals', 'value': 404}])
    elif template == 'login_sequence':
        d.update(key='CUSTOM-SEQ-001', name='반복 로그인 실패 후 성공', kind='sequence', count=5,
                 conditions=[], success_seconds=600)
    elif template == 'waf_sqli':
        d.update(key='CUSTOM-WAF-001', name='SQLi 의심 요청', source='waf', kind='waf', count=1,
                 conditions=[], cooldown_seconds=0)
    elif template == 'access_denied':
        d.update(key='CUSTOM-ACCESS-001', name='타인 주문 접근 거부', source='mall', kind='single', count=1,
                 window_seconds=1, cooldown_seconds=0,
                 conditions=[{'field': 'event.action', 'operator': 'equals', 'value': 'order_view'},
                             {'field': 'event.outcome', 'operator': 'equals', 'value': 'failure'},
                             {'field': 'cloud_soc.security_mall.resource_type', 'operator': 'equals', 'value': 'order'},
                             {'field': 'cloud_soc.security_mall.authorization_reason', 'operator': 'equals', 'value': 'not_owner'}])
    elif template != 'ssh_failures':
        raise AuthoringError('template_missing')
    return normalize(d)


def capabilities():
    return {'schema_version': SCHEMA_VERSION, 'fields': {k: {'label': v[0], 'type': v[1]} for k, v in FIELDS.items()},
            'operators': OPERATORS, 'groups': list(GROUPS),
            'sources': {k: {**v, 'fields': sorted(SOURCE_FIELDS[k])} for k, v in SOURCES.items()},
            'templates': {k: example(k) for k in ('ssh_failures', 'web_errors', 'login_sequence', 'waf_sqli', 'access_denied')},
            'max_rules': MAX_RULES, 'max_file_bytes': MAX_FILE_BYTES}


def parse_import(format_name, content):
    need(isinstance(content, str) and len(content.encode('utf-8')) <= MAX_FILE_BYTES, 'file_size_invalid')
    try:
        if format_name == 'json':
            def unique(pairs):
                result = {}
                for key, value in pairs:
                    need(key not in result, 'duplicate_json_key')
                    result[key] = value
                return result
            value = json.loads(content, object_pairs_hook=unique)
            need(isinstance(value, dict) and set(value) == {'schema_version', 'rules'}
                 and type(value['schema_version']) is int and value['schema_version'] == 1, 'import_schema_invalid')
            rows = value['rules']
        elif format_name == 'csv':
            reader = csv.DictReader(io.StringIO(content.lstrip('\ufeff')))
            need(reader.fieldnames == CSV_COLUMNS, 'csv_columns_invalid')
            rows = []
            for raw in reader:
                need(None not in raw and all(v is not None for v in raw.values()), 'csv_row_invalid')
                d = {k: raw[k] for k in ('key', 'name', 'description', 'source', 'kind', 'severity')}
                d.update(schema_version=1, group_by=[v.strip() for v in raw['group_by'].split(';') if v.strip()], conditions=[])
                for k in ('count', 'window_seconds', 'cooldown_seconds', 'success_seconds'):
                    d[k] = int(raw[k])
                if raw['field']:
                    v = raw['value']
                    if raw['operator'] in ('exists', 'in') or raw['field'] == 'http.response.status_code':
                        v = json.loads(v)
                    d['conditions'] = [{'field': raw['field'], 'operator': raw['operator'], 'value': v}]
                else:
                    need(not raw['operator'] and not raw['value'], 'csv_condition_invalid')
                rows.append(d)
                need(len(rows) <= MAX_RULES, 'import_capacity')
        else:
            raise AuthoringError('format_unsupported')
        need(isinstance(rows, list) and 1 <= len(rows) <= MAX_RULES, 'import_capacity')
        return rows
    except (json.JSONDecodeError, TypeError, OverflowError, csv.Error, RecursionError):
        raise AuthoringError('import_invalid') from None
    except ValueError as error:
        if isinstance(error, AuthoringError):
            raise
        raise AuthoringError('csv_value_invalid') from None


def csv_template():
    stream = io.StringIO(newline='')
    writer = csv.writer(stream)
    writer.writerow(CSV_COLUMNS)
    d = example()
    c = d['conditions'][0]
    writer.writerow([d[k] if k not in ('field', 'operator', 'value', 'group_by') else
                     ';'.join(d['group_by']) if k == 'group_by' else c[k] for k in CSV_COLUMNS])
    return stream.getvalue()
