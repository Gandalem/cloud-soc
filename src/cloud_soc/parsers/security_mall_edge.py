"""Versioned allowlist projection of the lab's Apache TSV and ModSecurity 2 AKZ.

No request strings, rule messages or matching values leave these parsers. Native
rules are compared with a trusted local manifest, including complete chains.
"""
from datetime import datetime, timezone
import hashlib
from ipaddress import ip_address
import json
import re
import shlex

VERSION = 'security-mall-edge-v1'
ADAPTER = 'security_mall_edge_v1'
SOURCE_KIND = 'security_mall_edge'
PAYLOAD = 'security_mall_edge'
COMMON = {'schema_version', 'stream', 'timestamp', 'request_id', 'service_name', 'source_ip'}
ACCESS = {'method', 'path', 'status_code', 'duration_us'}
WAF = {'rules', 'engine_mode', 'blocked'}
SOURCE_FIELDS = (PAYLOAD,)
REQUEST_ID = re.compile(r'[A-Za-z0-9_-]{27}')
BOUNDARY = re.compile(r'--([A-Za-z0-9]{1,64})-([A-Z])--')
METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS', 'OTHER'}
PATHS = {'/', '/login', '/logout', '/signup', '/cart', '/cart/add', '/item/:id',
         '/order/checkout', '/order/complete/:id', '/board', '/board/:id',
         '/board/mutation', '/board/mutation/:id', '/admin', '/admin/item/mutation',
         '/admin/resource/mutation/:id', '/static', '/_unclassified'}
SEVERITIES = {'emergency', 'alert', 'critical', 'error', 'warning', 'notice', 'info', 'debug'}
DIAGNOSTIC = '''SecRule REQUEST_HEADERS:X-WAF-Lab-Check "@streq privacy-check" "id:10002,phase:2,pass,log,auditlog,t:none,msg:'Lab benign privacy verification',logdata:'%{MATCHED_VAR}',chain"
SecRule ARGS:lab_marker "@rx ^[A-Za-z0-9_-]{16,80}$" "t:none"'''


class EdgeError(ValueError):
    def __init__(self, reason='edge_invalid'):
        # Never pass exceptions, paths, keys, rule text or request content here.
        super().__init__(reason)
        self.reason = reason


def timestamp(value, *, central=False):
    try:
        precision = 9 if central else 6
        pattern = r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,' + str(precision) + r'})?Z'
        if not isinstance(value, str) or not re.fullmatch(pattern, value):
            raise ValueError()
        return datetime.fromisoformat(value.replace('Z', '+00:00'))
    except (ValueError, TypeError):
        raise EdgeError('edge_time_invalid') from None


def iso(value):
    return value.astimezone(timezone.utc).isoformat().replace('+00:00', 'Z')


def _ip(value):
    try:
        if not isinstance(value, str) or '%' in value:
            raise ValueError()
        return str(ip_address(value))
    except ValueError:
        raise EdgeError('edge_peer_invalid') from None


def _base(stream, occurred, request_id, peer):
    if not isinstance(request_id, str) or not REQUEST_ID.fullmatch(request_id):
        raise EdgeError('edge_request_id_invalid')
    return {'schema_version': 1, 'stream': stream, 'timestamp': occurred,
            'request_id': request_id, 'service_name': 'security-mall', 'source_ip': _ip(peer)}


def parse_access(line):
    try:
        if not isinstance(line, str) or len(line) > 2048 or not line.endswith('\n'):
            raise EdgeError('edge_access_incomplete')
        parts = line.removesuffix('\n').split('\t')
        if len(parts) != 8 or parts[0] != 'soc-mall-access-v1':
            raise EdgeError('edge_access_shape')
        occurred = iso(datetime.strptime(parts[1], '%Y-%m-%dT%H:%M:%S%z'))
        body = _base('access', occurred, parts[7], parts[2])
        if not re.fullmatch(r'[1-5][0-9]{2}', parts[5]) or not re.fullmatch(r'[0-9]{1,15}', parts[6]):
            raise EdgeError('edge_http_invalid')
        body.update(method=parts[3], path=parts[4], status_code=int(parts[5]), duration_us=int(parts[6]))
        return validate(body)
    except EdgeError:
        raise
    except (ValueError, TypeError, OverflowError):
        raise EdgeError('edge_access_invalid') from None


def _rule(line):
    try:
        tokens = shlex.split(line, comments=False)
        if len(tokens) not in (3, 4) or tokens[0] != 'SecRule':
            raise ValueError()
        if tokens[2].strip() in {'@validateUrlEncoding', '@validateUtf8Encoding', '@unconditionalMatch', '@detectSQLi', '@detectXSS'}:
            tokens[2] = tokens[2].strip()
        # Apache's outer quoting has already been decoded. Do not interpret the
        # action text again as shell syntax (e.g. literal quotes in CRS 920490).
        # Compare every comma fragment with the installed source; never emit msg,
        # logdata or their fragments. Only bounded named metadata is selected.
        actions = [v.strip() for v in tokens[3].split(',')] if len(tokens) == 4 else []
        # Native K removes optional quoting around complete action parameters.
        normalized = []
        for action in actions:
            key, separator, value = action.partition(':')
            if separator and len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
                value = value[1:-1]
            normalized.append(key + separator + value)
        actions = normalized
        # ModSecurity adds/reorders inherited logging/default phase actions in K.
        # Compare all other actions, including messages/logdata, without emitting them.
        ignored = {'log', 'nolog', 'auditlog', 'noauditlog', 'pass'}
        canonical = [v for v in actions if v not in ignored and not v.startswith('phase:')]
        transforms = [v for v in canonical if v.startswith('t:')]
        rest = sorted(v for v in canonical if not v.startswith('t:'))
        signature = hashlib.sha256(json.dumps([tokens[:3], transforms, rest],
                                               separators=(',', ':')).encode()).hexdigest()
        ids = [v[3:].strip("'\"") for v in actions if v.startswith('id:')]
        levels = [v[9:].strip("'\"").lower() for v in actions if v.startswith('severity:')]
        disruptive = [v for v in actions if v in {'deny', 'block', 'drop', 'allow', 'pass'}]
        info = {'signature': signature, 'chain': 'chain' in actions, 'id': ids[0] if ids else None,
                'severity': levels[0] if levels else None,
                'action': disruptive[-1] if disruptive else 'pass'}
        return info
    except (ValueError, TypeError):
        raise EdgeError('edge_rule_syntax') from None


def build_manifest(texts, *, include_lab_diagnostic=False):
    """Call only with trusted installed CRS files; never with audit input as text."""
    manifest = {}
    sources = list(texts) + ([DIAGNOSTIC] if include_lab_diagnostic else [])
    for text in sources:
        logical = re.sub(r'\\\r?\n\s*', ' ', text)
        chain = []
        for line in logical.splitlines():
            if not line.strip().startswith('SecRule '):
                continue
            entry = _rule(line.strip())
            chain.append(entry)
            if not entry['chain']:
                signatures = tuple(part['signature'] for part in chain)
                for part in chain:
                    manifest[part['signature']] = {'group': signatures, 'starter': chain[0]}
                chain = []
        if chain:
            raise EdgeError('edge_manifest_chain_incomplete')
    return manifest


def parse_native(record, manifest):
    """Require exact A/K/Z framing, validated rules and complete matched chains."""
    if not isinstance(record, str) or len(record) > 1024 * 1024 or not record.endswith('\n'):
        raise EdgeError('edge_native_incomplete')
    sections, order, boundary, section = {}, [], None, None
    for line in record.splitlines():
        match = BOUNDARY.fullmatch(line)
        if match:
            token, name = match.groups()
            if boundary is None:
                boundary = token
            if token != boundary or name not in {'A', 'K', 'Z'} or name in sections:
                raise EdgeError('edge_native_boundary')
            section = name
            order.append(name)
            sections[name] = []
        elif line:
            if section is None or section == 'Z':
                raise EdgeError('edge_native_boundary')
            sections[section].append(line)
    if order != ['A', 'K', 'Z'] or len(sections['A']) != 1:
        raise EdgeError('edge_native_sections')
    # Match metadata only, never carry the rest of A or a URI/query into output.
    header = re.fullmatch(r'\[([0-9]{2}/[A-Za-z]{3}/[0-9]{4}:[0-9:]{8}(?:\.[0-9]{1,6})? [+-][0-9]{4})\] '
                          r'([A-Za-z0-9_-]{27}) ([0-9A-Fa-f:.]+) ([0-9]{1,5}) '
                          r'([0-9A-Fa-f:.]+) ([0-9]{1,5})', sections['A'][0])
    if not header:
        raise EdgeError('edge_native_header')
    _ip(header[5])
    if any(not 1 <= int(header[i]) <= 65535 for i in (4, 6)):
        raise EdgeError('edge_native_header')
    try:
        # Native month names are parsed without depending on process locale.
        day, month, rest = header[1].split('/', 2)
        numeric = f"{day}/{('Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec'.split().index(month) + 1):02}/{rest}"
        fmt = '%d/%m/%Y:%H:%M:%S.%f %z' if '.' in numeric else '%d/%m/%Y:%H:%M:%S %z'
        occurred = iso(datetime.strptime(numeric, fmt))
    except ValueError:
        raise EdgeError('edge_time_invalid') from None
    body = _base('waf', occurred, header[2], header[3])
    groups, pending = [], []
    for line in sections['K']:
        partial = line.startswith('#')
        source = line[1:] if partial else line
        if source.startswith(('SecAction ', 'SecMarker ')):
            if pending:
                raise EdgeError('edge_native_chain')
            try:
                if len(shlex.split(source, comments=False)) != 2:
                    raise ValueError()
            except ValueError:
                raise EdgeError('edge_rule_syntax') from None
            # Setup/logging actions are not security matches and are never copied.
            continue
        entry = _rule(source)
        known = manifest.get(entry['signature'])
        if known is None:
            raise EdgeError('edge_rule_untrusted')
        pending.append((entry, partial))
        if not entry['chain']:
            known = manifest[pending[0][0]['signature']]
            if tuple(part['signature'] for part, _ in pending) != known['group']:
                raise EdgeError('edge_native_chain')
            if not any(partial for _, partial in pending):
                starter = known['starter']
                # Only actual rule starters have IDs; metadata controls aren't matches.
                if starter['id'] and (starter['severity'] is not None or starter['id'] == '10002'):
                    item = {'id': starter['id'], 'action': starter['action'],
                            'diagnostic': starter['id'] == '10002'}
                    if starter['severity'] is not None:
                        item['severity'] = starter['severity']
                    groups.append(item)
            pending = []
    if pending:
        raise EdgeError('edge_native_chain')
    # A record can be relevant because of logging/setup only; don't invent a match.
    if not groups:
        raise EdgeError('edge_no_complete_rule_match')
    body.update(rules=sorted({item['id']: item for item in groups}.values(), key=lambda item: item['id']),
                engine_mode='DetectionOnly', blocked=False)
    return validate(body)


def _validate(body):
    if not isinstance(body, dict) or body.get('stream') not in {'access', 'waf'}:
        raise EdgeError('edge_schema_invalid')
    expected = COMMON | (ACCESS if body['stream'] == 'access' else WAF)
    if set(body) != expected or type(body['schema_version']) is not int or body['schema_version'] != 1:
        raise EdgeError('edge_fields_invalid')
    timestamp(body['timestamp'])
    _base(body['stream'], body['timestamp'], body['request_id'], body['source_ip'])
    if body['service_name'] != 'security-mall':
        raise EdgeError('edge_service_invalid')
    if body['stream'] == 'access':
        if body['method'] not in METHODS or body['path'] not in PATHS:
            raise EdgeError('edge_http_invalid')
        if type(body['status_code']) is not int or not 100 <= body['status_code'] <= 599:
            raise EdgeError('edge_http_invalid')
        if type(body['duration_us']) is not int or not 0 <= body['duration_us'] <= 9_000_000_000_000_000:
            raise EdgeError('edge_duration_invalid')
    else:
        if body['engine_mode'] != 'DetectionOnly' or body['blocked'] is not False:
            raise EdgeError('edge_mode_invalid')
        if not isinstance(body['rules'], list) or not 1 <= len(body['rules']) <= 1024:
            raise EdgeError('edge_rules_invalid')
        ids = set()
        for item in body['rules']:
            if not isinstance(item, dict) or set(item) not in ({'id', 'action', 'diagnostic'}, {'id', 'action', 'diagnostic', 'severity'}):
                raise EdgeError('edge_rules_invalid')
            if not isinstance(item['id'], str) or not re.fullmatch(r'[0-9]{1,9}', item['id']) or item['id'] in ids:
                raise EdgeError('edge_rules_invalid')
            ids.add(item['id'])
            if item['action'] not in {'pass', 'block', 'deny', 'drop', 'allow'} or type(item['diagnostic']) is not bool:
                raise EdgeError('edge_rules_invalid')
            if item['diagnostic'] != (item['id'] == '10002') or ('severity' in item and item['severity'] not in SEVERITIES):
                raise EdgeError('edge_rules_invalid')
    return body


def validate(body):
    try:
        return _validate(body)
    except EdgeError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
        raise EdgeError('edge_fields_invalid') from None


def identifier(body, organization, host):
    for value in [organization, host]:
        if not isinstance(value, str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,63}', value):
            raise EdgeError('edge_scope_invalid')
    validate(body)
    return hashlib.sha256(json.dumps([VERSION, organization, host, body['service_name'],
        body['stream'], body['request_id']], separators=(',', ':')).encode()).hexdigest()


def envelope(body, organization, host):
    event_id = identifier(body, organization, host)
    return {'@timestamp': body['timestamp'], 'organization': {'id': organization}, 'host': {'id': host},
            'labels': {'log_source': SOURCE_KIND}, 'event': {'id': event_id}, PAYLOAD: body}


def validate_source(source, *, received=True):
    try:
        if not isinstance(source, dict) or set(source) != {'@timestamp', 'organization', 'host', 'labels', 'event', PAYLOAD}:
            raise EdgeError('edge_envelope_invalid')
        if set(source['organization']) != {'id'} or set(source['host']) != {'id'} or source['labels'] != {'log_source': SOURCE_KIND}:
            raise EdgeError('edge_scope_invalid')
        expected = {'id', 'ingested'} if received else {'id'}
        if set(source['event']) != expected:
            raise EdgeError('edge_event_invalid')
        body = validate(source[PAYLOAD])
        if source['@timestamp'] != body['timestamp'] or source['event']['id'] != identifier(
                body, source['organization']['id'], source['host']['id']):
            raise EdgeError('edge_identity_mismatch')
        if received:
            timestamp(source['event']['ingested'], central=True)
        return body
    except EdgeError:
        raise
    except (ValueError, TypeError, KeyError, AttributeError):
        raise EdgeError('edge_envelope_invalid') from None
