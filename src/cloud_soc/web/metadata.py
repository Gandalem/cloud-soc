"""Extract an allowlist before queueing. Request strings never leave this function."""
import hashlib
import ipaddress
import json
import re
from datetime import datetime, timezone, timedelta

VERSION = 'web-access-metadata-v1'
INDEX = 'soc-host-raw-web-dvwa-v1'
LIMIT = 8192
METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'}
CLASSES = {'login', 'static', 'general', 'other'}
ACCESS = re.compile(r'^(\S{1,253}) \S{1,128} \S{1,128} \[(\d{2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2} [+-]\d{4})\] "([A-Z]{1,10}) ([^"\r\n]{1,4096}) HTTP/[12](?:\.[01])?" ([1-5]\d{2}) (?:\d{1,20}|-)(?: "[^"\r\n]{0,4096}" "[^"\r\n]{0,4096}")?$')


def stamp(value):
    if not isinstance(value, str) or len(value) > 40:
        raise ValueError('invalid_timestamp')
    result = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if result.tzinfo is None or result.utcoffset() is None:
        raise ValueError('aware_timestamp_required')
    return result.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def scope(organization, host, container, region):
    if not re.fullmatch(r'[a-z0-9][a-z0-9-]{0,47}', organization or ''):
        raise ValueError('invalid_organization')
    if not re.fullmatch(r'i-[a-f0-9]{8,17}', host or '') or not re.fullmatch(r'[a-f0-9]{64}', container or ''):
        raise ValueError('invalid_host_or_container')
    if not re.fullmatch(r'[a-z]{2}(?:-gov)?-[a-z]+-\d', region or ''):
        raise ValueError('invalid_region')


def project(line, *, organization, host, container, region, generation, device, inode, offset, collected_at, docker=False):
    scope(organization, host, container, region)
    if not isinstance(line, bytes) or len(line) > LIMIT:
        return None
    try:
        value = line.decode('utf-8').rstrip('\r\n')
        if docker:
            envelope = json.loads(value)
            if set(envelope) != {'log', 'stream', 'time'} or envelope['stream'] != 'stdout':
                return None
            stamp(envelope['time']);value = envelope['log'].rstrip('\r\n')
        match = ACCESS.fullmatch(value)
        if not match or match[3] not in METHODS:
            return None
        day, month, rest = match[2].split('/', 2);date, zone = rest.split(' ')
        year, hour, minute, second = map(int, date.split(':'))
        minutes = int(zone[1:3]) * 60 + int(zone[3:])
        if int(zone[1:3]) > 23 or int(zone[3:]) > 59: return None
        occurred = datetime(year, 'Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split().index(month)+1,
            int(day), hour, minute, second, tzinfo=timezone(timedelta(minutes=minutes * (-1 if zone[0]=='-' else 1))))
        received = stamp(collected_at)
        try:
            if '%' in match[1]:raise ValueError()
            ip = str(ipaddress.ip_address(match[1]))
            if ipaddress.ip_address(ip).is_unspecified:ip = None
        except ValueError:ip = None
        path = match[4].split('?', 1)[0].split('#', 1)[0]
        kind = 'login' if path=='/login.php' else 'static' if path in ('/favicon.ico','/robots.txt') or path.startswith(('/css/','/js/','/images/')) else 'general' if path in ('/','/index.php') else 'other'
        if any(type(v) is not int or not 0 <= v < 2**128 for v in (device,inode)):raise ValueError('invalid_file_identity')
        position = {'generation': generation, 'file_id':digest([device,inode]), 'offset': offset}
        if any(type(v) is not int or not 0 <= v < 2**53 for v in (generation,offset)):raise ValueError('invalid_position')
        identifier = digest([VERSION, organization, host, container, position])
        code = int(match[5]);outcome = 'failure' if code>=400 else 'success' if code<300 else 'unknown'
        body = {'@timestamp': stamp(occurred.isoformat()), 'organization': {'id': organization},
            'host': {'id': host, 'name': 'aws-dvwa-'+host, 'os': {'type':'linux'}},
            'cloud': {'provider':'aws','region':region}, 'container':{'id':container}, 'service':{'id':'dvwa-apache','name':'DVWA'},
            'agent': {'id':digest([VERSION,organization,host,container]),'type':'web-collector','version':VERSION},
            'labels': {'log_source':'web_access_metadata','privacy_policy':'web-allowlist-v1'},
            'event': {'id':identifier,'category':['web'],'action':'http_access','outcome':outcome,'dataset':'aws.dvwa.access','created':received},
            'http': {'request':{'method':match[3]},'response':{'status_code':code}},
            'web': {'schema':1,'parser_version':VERSION,'path_class':kind,'ip_basis':'apache_peer' if ip else 'not_observed',
                'source_kind':'docker_json' if docker else 'apache_access_file','position':position}}
        if ip:body['source']={'ip':ip}
        validate(body)
        return body
    except (ValueError, TypeError, KeyError, AttributeError):
        return None


def _validate(body, *, received=False):
    """No unknown fields at any depth, including when reading a compromised spool."""
    allowed={'@timestamp','organization','host','cloud','container','service','agent','labels','event','http','web','source'}
    if received:allowed.add('cloud_soc_enrollment')
    if not isinstance(body, dict) or set(body)-allowed or allowed-{'source','cloud_soc_enrollment'}-set(body):raise ValueError('invalid_web_fields')
    stamp(body['@timestamp'])
    schemas={'organization':{'id'},'host':{'id','name','os'},'cloud':{'provider','region'},'container':{'id'},'service':{'id','name'},'agent':{'id','type','version'},'labels':{'log_source','privacy_policy'},'event':{'id','category','action','outcome','dataset','created'},'http':{'request','response'},'web':{'schema','parser_version','path_class','ip_basis','source_kind','position'}}
    if received:schemas['event'].add('ingested')
    for name, keys in schemas.items():
        if not isinstance(body[name], dict) or set(body[name])!=keys:raise ValueError('invalid_web_shape')
    scope(body['organization']['id'],body['host']['id'],body['container']['id'],body['cloud']['region'])
    if body['host']['name']!='aws-dvwa-'+body['host']['id'] or body['host']['os']!={'type':'linux'} or body['cloud']['provider']!='aws':raise ValueError('invalid_identity')
    if body['service']!={'id':'dvwa-apache','name':'DVWA'} or body['labels']!={'log_source':'web_access_metadata','privacy_policy':'web-allowlist-v1'}:raise ValueError('invalid_source')
    if body['agent']!={'id':digest([VERSION,body['organization']['id'],body['host']['id'],body['container']['id']]),'type':'web-collector','version':VERSION}:raise ValueError('invalid_collector')
    if body['web']['schema']!=1 or type(body['web']['schema']) is not int or body['web']['parser_version']!=VERSION or body['web']['path_class'] not in CLASSES or body['web']['source_kind'] not in ('apache_access_file','docker_json'):raise ValueError('invalid_contract')
    position=body['web']['position']
    if not isinstance(position,dict) or set(position)!={'generation','file_id','offset'} or not isinstance(position['file_id'],str) or not re.fullmatch(r'[a-f0-9]{64}',position['file_id']) or any(type(v) is not int or not 0<=v<2**53 for v in (position['generation'],position['offset'])):raise ValueError('invalid_position')
    if body['event']['id']!=digest([VERSION,body['organization']['id'],body['host']['id'],body['container']['id'],position]):raise ValueError('invalid_event_id')
    if body['http'].keys()!={'request','response'} or body['http']['request'].keys()!={'method'} or body['http']['response'].keys()!={'status_code'}:raise ValueError('invalid_http_shape')
    method=body['http']['request']['method'];code=body['http']['response']['status_code']
    if method not in METHODS or type(code) is not int or not 100<=code<=599:raise ValueError('invalid_http')
    expected='failure' if code>=400 else 'success' if code<300 else 'unknown'
    if any(body['event'][k]!=v for k,v in {'category':['web'],'action':'http_access','outcome':expected,'dataset':'aws.dvwa.access'}.items()):raise ValueError('invalid_event')
    stamp(body['event']['created'])
    if received:stamp(body['event']['ingested'])
    if 'source' in body:
        if not isinstance(body['source'],dict) or set(body['source'])!={'ip'} or '%' in body['source']['ip'] or str(ipaddress.ip_address(body['source']['ip']))!=body['source']['ip'] or ipaddress.ip_address(body['source']['ip']).is_unspecified:raise ValueError('invalid_ip')
    if body['web']['ip_basis']!=('apache_peer' if 'source' in body else 'not_observed'):raise ValueError('invalid_ip_basis')
    if 'cloud_soc_enrollment' in body:
        proof=body['cloud_soc_enrollment']
        if not isinstance(proof,dict) or set(proof)-{'id','key_id','scope','package_id'} or any(not isinstance(v,str) or len(v)>128 for v in proof.values()):raise ValueError('invalid_receipt_proof')
    return body


def validate(body, *, received=False):
    try:
        return _validate(body, received=received)
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise ValueError('invalid_web_metadata') from None
