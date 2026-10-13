"""Protected Filebeat access events, independent of the existing DVWA contract."""
from datetime import datetime
from ipaddress import ip_address
import re

VERSION = 'web-access-agent-v1'


def validate(source):
    if not isinstance(source, dict): raise ValueError('invalid web metadata')
    def obj(key):
        value = source.get(key, {})
        if not isinstance(value, dict): raise ValueError('invalid web metadata')
        return value
    web, service, http, event = (obj(k) for k in ('web','service','http','event'))
    if web != {'schema':VERSION,'server_type':web.get('server_type'),'ip_basis':'observed_peer'} or web['server_type'] not in ('apache','nginx','docker'):
        raise ValueError('invalid web metadata schema')
    if set(service) != {'id','name'} or not isinstance(service['id'], str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,63}',service['id']) or not isinstance(service['name'],str) or not 1<=len(service['name'])<=64:
        raise ValueError('invalid site identity')
    if set(http)-{'request','response'} or not isinstance(http.get('request'),dict) or set(http['request'])!={'method'} or http['request']['method'] not in ('GET','POST','PUT','DELETE','HEAD','OPTIONS','PATCH'):
        raise ValueError('invalid HTTP metadata')
    response = http.get('response',{})
    if not isinstance(response,dict) or set(response)-{'status_code','body'} or type(response.get('status_code')) is not int or not 100<=response['status_code']<=599:
        raise ValueError('invalid HTTP status')
    if 'body' in response:
        body=response['body']
        if not isinstance(body,dict) or set(body)!={'bytes'} or type(body['bytes']) is not int or not 0<=body['bytes']<=9007199254740991:
            raise ValueError('HTTP content is forbidden')
    if event.get('action')!='http_access' or event.get('dataset')!='cloud_soc.web_access' or event.get('outcome')!=('failure' if response['status_code']>=400 else 'success'):
        raise ValueError('invalid web event')
    try:
        timestamp=datetime.fromisoformat(source['@timestamp'].replace('Z','+00:00'))
        if timestamp.tzinfo is None:raise ValueError()
        if 'ip' in obj('source'):ip_address(obj('source')['ip'])
    except (TypeError, KeyError, AttributeError, ValueError):
        raise ValueError('invalid web time or peer IP') from None
    return source
