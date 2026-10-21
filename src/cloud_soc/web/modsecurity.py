"""Allowlisted ModSecurity v3 JSON projection; no payloads or matched values."""
from datetime import datetime
from ipaddress import ip_address
import re

from cloud_soc.web.scope import valid_site_id

VERSION = 'modsecurity-metadata-v1'
ADAPTER = 'modsecurity_audit_v1'
SOURCE_KIND = 'generic_modsecurity'
SQLI_IDS = frozenset({'942100', '942140', '942160', '942170', '942190', '942220', '942230', '942240'})
METHODS = ('GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'OPTIONS', 'PATCH')


def validate(source):
    try:
        service, http, waf = (source[key] for key in ('service', 'http', 'waf'))
        event = source['event']
        if event.get('action') != 'waf_rule_match' or event.get('dataset') != 'cloud_soc.modsecurity' or event.get('outcome') != 'unknown':
            raise ValueError()
        if (not isinstance(service, dict) or set(service) != {'id', 'name'} or not valid_site_id(service['id'])
                or not isinstance(service['name'], str) or not 1 <= len(service['name']) <= 64
                or not isinstance(waf, dict) or set(waf) != {'schema', 'engine_mode', 'interruption', 'rules'}
                or waf['schema'] != VERSION or waf['engine_mode'] not in ('On', 'DetectionOnly', 'Off')
                or waf['interruption'] not in ('observed', 'not_observed', 'unknown')
                or waf['engine_mode'] != 'On' and waf['interruption'] == 'observed'
                or not isinstance(waf['rules'], list) or not 1 <= len(waf['rules']) <= 64
                or not isinstance(http, dict) or set(http) != {'request', 'response'}
                or set(http['request']) != {'id', 'method'} or http['request']['method'] not in METHODS
                or not isinstance(http['request']['id'], str)
                or not re.fullmatch(r'[A-Za-z0-9_.:@-]{1,128}', http['request']['id'])
                or set(http['response']) != {'status_code'} or type(http['response']['status_code']) is not int
                or not 100 <= http['response']['status_code'] <= 599):
            raise ValueError()
        seen, matched = set(), []
        for item in waf['rules']:
            if (not isinstance(item, dict) or set(item) != {'id', 'crs_version'}
                    or not isinstance(item['id'], str) or not re.fullmatch(r'[1-9][0-9]{0,7}', item['id'])
                    or item['id'] in seen or item['crs_version'] is not None and (
                        not isinstance(item['crs_version'], str) or not re.fullmatch(r'[34]\.[0-9]{1,3}\.[0-9]{1,3}', item['crs_version']))):
                raise ValueError()
            seen.add(item['id'])
            if item['id'] in SQLI_IDS and item['crs_version'] is not None:
                matched.append(item['id'])
        stamp = datetime.fromisoformat(source['@timestamp'].replace('Z', '+00:00'))
        peer = source['source']['ip']
        if stamp.tzinfo is None or not isinstance(peer, str) or '%' in peer:
            raise ValueError()
        peer = str(ip_address(peer))
        return {'category': 'web', 'action': 'waf_rule_match', 'outcome': 'unknown', 'source_ip': peer,
                'service_id': service['id'], 'request_id': http['request']['id'],
                'http_method': http['request']['method'], 'http_status': http['response']['status_code'],
                'engine_mode': waf['engine_mode'], 'interruption': waf['interruption'],
                'rules': waf['rules'], 'sqli_rule_ids': sorted(matched), 'sqli': bool(matched)}
    except (KeyError, TypeError, AttributeError, ValueError):
        raise ValueError('invalid_modsecurity_metadata') from None
