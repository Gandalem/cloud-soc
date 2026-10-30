"""S3 -> SQS -> create-only bulk ingestion, bounded and replay safe.

No provisioning occurs here. A receipt is acknowledged only after every object
record is accepted by the destination. Unknown/invalid input remains on SQS.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
import gzip
import hashlib
from ipaddress import ip_address
import json
import re
import shlex
import threading
from urllib.parse import unquote_plus, urlsplit

from cloud_soc.aws.cloudtrail import _object, _reject_constant, iso, project_event, safe, timestamp

REGION = 'ap-southeast-2'
FORMATS = {'cloudtrail', 'vpc_flow_v2', 'alb', 'cloudwatch', 'tpot_cowrie', 'tpot_suricata'}
MAX_COMPRESSED = 32 * 1024 * 1024
MAX_EXPANDED = 64 * 1024 * 1024
MAX_RECORDS = 100000
MAX_LINE = 1024 * 1024
TOKEN = re.compile(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}')
FLOW_HEADER = 'version account-id interface-id srcaddr dstaddr srcport dstport protocol packets bytes start end action log-status'


class IngestError(RuntimeError):
    """Only fixed error codes, never payloads or SDK exception messages."""


def require(condition, code='invalid_record'):
    if not condition:
        raise IngestError(code)


def load_json(value):
    return json.loads(value, object_pairs_hook=_object, parse_constant=_reject_constant)


@dataclass(frozen=True)
class Source:
    bucket: str
    prefix: str
    format: str
    account_id: str
    bucket_owner: str
    source_id: str
    team: str | None = None
    resource_id: str | None = None


@dataclass(frozen=True)
class StreamSettings:
    collector_account: str
    organization: str
    queue_url: str
    sources: tuple[Source, ...]
    role_teams: dict
    user_teams: dict = field(default_factory=dict)

    @classmethod
    def parse(cls, value):
        required = {'collector_account', 'organization', 'region', 'queue_url', 'sources', 'role_teams'}
        require(isinstance(value, dict) and required <= set(value)
                and set(value) <= required | {'user_teams'}, 'invalid_config')
        require(value['region'] == REGION, 'region_must_be_sydney')
        account, org = value['collector_account'], value['organization']
        require(isinstance(account, str) and re.fullmatch(r'\d{12}', account), 'invalid_account')
        require(isinstance(org, str) and TOKEN.fullmatch(org), 'invalid_organization')
        queue = value['queue_url']
        require(isinstance(queue, str) and re.fullmatch(
            rf'https://sqs\.ap-southeast-2\.amazonaws\.com/{account}/[A-Za-z0-9_-]{{1,80}}', queue), 'invalid_queue')
        require(isinstance(value['sources'], list) and 1 <= len(value['sources']) <= 100, 'invalid_sources')
        sources = []
        for row in value['sources']:
            require(isinstance(row, dict) and set(row) <= {
                'bucket', 'prefix', 'format', 'account_id', 'bucket_owner', 'source_id', 'team', 'resource_id'}, 'invalid_source')
            require({'bucket', 'prefix', 'format', 'account_id', 'bucket_owner', 'source_id'} <= set(row), 'invalid_source')
            source = Source(**row)
            require(isinstance(source.bucket, str) and re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', source.bucket)
                    and '..' not in source.bucket, 'invalid_bucket')
            require(isinstance(source.prefix, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_./=-]{0,510}/', source.prefix)
                    and '..' not in source.prefix and '//' not in source.prefix, 'invalid_prefix')
            require(isinstance(source.format, str) and source.format in FORMATS
                    and isinstance(source.source_id, str) and TOKEN.fullmatch(source.source_id), 'invalid_source')
            require(all(isinstance(x, str) and re.fullmatch(r'\d{12}', x) for x in (
                source.account_id, source.bucket_owner)), 'invalid_account')
            require(source.team is None or isinstance(source.team, str) and TOKEN.fullmatch(source.team), 'invalid_team')
            if source.format == 'alb':
                require(isinstance(source.resource_id, str) and re.fullmatch(
                    r'app/[A-Za-z0-9-]{1,32}/[a-f0-9]{16}', source.resource_id), 'invalid_alb_resource')
            require(not any(s.bucket == source.bucket and (
                s.prefix.startswith(source.prefix) or source.prefix.startswith(s.prefix)) for s in sources), 'overlapping_sources')
            sources.append(source)
        roles = value['role_teams']
        require(isinstance(roles, dict) and len(roles) <= 100, 'invalid_roles')
        for role, team in roles.items():
            require(isinstance(role, str) and re.fullmatch(r'arn:aws:iam::\d{12}:role/[A-Za-z0-9_+=,.@/-]{1,512}', role)
                    and isinstance(team, str) and TOKEN.fullmatch(team), 'invalid_roles')
        users = value.get('user_teams', {})
        require(isinstance(users, dict) and len(users) <= 100, 'invalid_users')
        for user, team in users.items():
            require(isinstance(user, str) and re.fullmatch(r'arn:aws:iam::\d{12}:user/[A-Za-z0-9_+=,.@/-]{1,512}', user)
                    and isinstance(team, str) and TOKEN.fullmatch(team), 'invalid_users')
        return cls(account, org, queue, tuple(sources), roles, users)

    def match(self, bucket, key):
        found = [s for s in self.sources if s.bucket == bucket and key.startswith(s.prefix)]
        require(len(found) == 1, 'object_out_of_scope')
        return found[0]


def numbers(value, *, maximum=2**63-1):
    require(isinstance(value, str) and re.fullmatch(r'\d{1,20}', value))
    number = int(value)
    require(number <= maximum)
    return number


def endpoint(value):
    if value == '-':
        return {}
    host, port = value.rsplit(':', 1)
    return {'ip': str(ip_address(host.strip('[]'))), 'port': numbers(port, maximum=65535)}


def json_documents(text):
    """Firehose may concatenate CloudWatch JSON envelopes without delimiters."""
    decoder = json.JSONDecoder(object_pairs_hook=_object, parse_constant=_reject_constant)
    offset = 0
    while offset < len(text):
        if text[offset].isspace():
            offset += 1
            continue
        value, offset = decoder.raw_decode(text, offset)
        yield value


def records(text, source):
    count = 0
    if source.format in ('cloudtrail', 'cloudwatch'):
        for envelope in json_documents(text):
            require(isinstance(envelope, dict))
            if source.format == 'cloudtrail':
                rows = envelope.get('Records')
            else:
                require(envelope.get('owner') == source.account_id, 'account_mismatch')
                if envelope.get('messageType') == 'CONTROL_MESSAGE':
                    continue
                require(envelope.get('messageType') == 'DATA_MESSAGE')
                rows = envelope.get('logEvents')
            require(isinstance(rows, list))
            for row in rows:
                count += 1
                require(count <= MAX_RECORDS, 'record_limit')
                yield count, row, envelope
    else:
        for line in text.splitlines():
            if not line.strip() or source.format == 'vpc_flow_v2' and line.strip() == FLOW_HEADER:
                continue
            count += 1
            require(count <= MAX_RECORDS, 'record_limit')
            require(len(line.encode()) <= MAX_LINE, 'line_limit')
            yield count, line, None


def project(row, envelope, source, settings):
    kind = source.format
    fields = {}
    # Team names on non-audit sources describe operator-bound resource ownership,
    # never an inferred IAM actor. CloudTrail requires an exact issuer-role match.
    team, basis = source.team, 'configured_source_binding'
    if kind == 'cloudtrail':
        require(isinstance(row, dict))
        region = row.get('awsRegion')
        require(region == REGION or region == 'us-east-1' and row.get('eventSource') in (
            'iam.amazonaws.com', 'signin.amazonaws.com', 'sts.amazonaws.com'), 'event_region_mismatch')
        _, _, document = project_event({'CloudTrailEvent': json.dumps(row), 'EventId': row.get('eventID'),
                                        'EventTime': row.get('eventTime')}, account=source.account_id,
                                       region=region, organization=settings.organization)
        issuer = document['aws']['cloudtrail']['session_issuer_arn']
        team, basis = settings.role_teams.get(issuer), 'cloudtrail_session_issuer'
        if document['aws']['cloudtrail']['identity_type'] == 'IAMUser':
            team = settings.user_teams.get(document['aws']['cloudtrail']['identity_arn'])
            basis = 'cloudtrail_iam_user'
        document['labels']['collection_path'] = 's3_sqs'
    else:
        event = {'kind': 'event', 'dataset': 'aws.' + kind, 'outcome': 'unknown'}
        document = {'event': event, 'organization': {'id': settings.organization},
                    'cloud': {'provider': 'aws', 'account': {'id': source.account_id}, 'region': REGION},
                    'agent': {'type': 's3-sqs', 'id': source.source_id},
                    'labels': {'log_source': kind, 'privacy_policy': 'aws_stream_metadata_v1'}}
        if kind == 'vpc_flow_v2':
            parts = row.split()
            require(len(parts) == 14 and parts[0] == '2' and parts[1] == source.account_id, 'invalid_flow')
            require(re.fullmatch(r'eni-[a-f0-9]{8,17}', parts[2]))
            require(parts[13] in ('OK', 'NODATA', 'SKIPDATA'))
            document['observer'] = {'name': parts[2]}
            fields['log_status'] = parts[13]
            end = numbers(parts[11])
            start = numbers(parts[10])
            require(start <= end)
            document['@timestamp'] = iso(datetime.fromtimestamp(end, timezone.utc))
            if parts[13] == 'OK':
                require(parts[12] in ('ACCEPT', 'REJECT'))
                document['source'] = {'ip': str(ip_address(parts[3])), 'port': numbers(parts[5], maximum=65535)}
                document['destination'] = {'ip': str(ip_address(parts[4])), 'port': numbers(parts[6], maximum=65535)}
                document['network'] = {'iana_number': numbers(parts[7], maximum=255),
                                       'packets': numbers(parts[8]), 'bytes': numbers(parts[9])}
                event.update(action=parts[12].lower(), start=iso(datetime.fromtimestamp(start, timezone.utc)),
                             end=document['@timestamp'])
            else:
                event['action'] = parts[13].lower()
        elif kind == 'alb':
            parts = shlex.split(row)
            require(len(parts) >= 22 and parts[0] in ('http', 'https', 'h2', 'grpcs', 'ws', 'wss'), 'invalid_alb')
            require(parts[2] == source.resource_id, 'resource_mismatch')
            document['@timestamp'] = iso(parts[1])
            document['source'], document['destination'] = endpoint(parts[3]), endpoint(parts[4])
            status = None if parts[8] == '-' else numbers(parts[8], maximum=599)
            require(status is None or status >= 100)
            request = parts[12].split()
            require(len(request) == 3 and (request[0] == '-' or re.fullmatch(r'[A-Z]{1,20}', request[0])))
            event['action'] = 'request'
            document['http'] = {}
            if request[0] != '-':
                document['http']['request'] = {'method': request[0]}
            if status is not None:
                document['http']['response'] = {'status_code': status}
            document['network'] = {'bytes': numbers(parts[10]) + numbers(parts[11])}
            # Request URLs, query strings, cookies, trace IDs and user agents stay in S3.
        elif kind == 'cloudwatch':
            require(isinstance(row, dict) and isinstance(row.get('id'), str) and len(row['id']) <= 256)
            require(type(row.get('timestamp')) is int and row['timestamp'] >= 0)
            if source.resource_id:
                require(envelope.get('logGroup') == source.resource_id, 'resource_mismatch')
            document['@timestamp'] = iso(datetime.fromtimestamp(row['timestamp'] / 1000, timezone.utc))
            event.update(id=row['id'], action='service_log')
            fields = {'log_group': safe(envelope.get('logGroup')), 'log_stream': safe(envelope.get('logStream'))}
            # Arbitrary service messages may contain tokens; index metadata only.
        else:
            value = load_json(row)
            require(isinstance(value, dict))
            document['@timestamp'] = iso(value.get('timestamp'))
            if kind == 'tpot_cowrie':
                action = value.get('eventid')
                require(isinstance(action, str) and re.fullmatch(r'cowrie\.[a-z0-9_.]{1,100}', action), 'invalid_tpot')
                document['source'] = {'ip': str(ip_address(value['src_ip']))}
                event.update(dataset='tpot.cowrie', action=action)
            else:
                require(value.get('event_type') == 'alert', 'invalid_tpot')
                alert = value.get('alert')
                require(isinstance(alert, dict) and type(alert.get('signature_id')) is int and alert['signature_id'] >= 0)
                document['source'] = {'ip': str(ip_address(value['src_ip']))}
                document['destination'] = {'ip': str(ip_address(value['dest_ip']))}
                event.update(dataset='tpot.suricata', action='alert', code=str(alert['signature_id']))
            document['observer'] = {'name': source.source_id, 'type': 'honeypot'}
        if fields:
            document['aws'] = {'stream': fields}
    document['labels'].update(source_id=source.source_id, collection_region=REGION,
                              team=team or 'unattributed', team_basis=basis if team else 'unattributed')
    return document


def object_events(message, settings):
    require(isinstance(message, dict) and isinstance(message.get('Records'), list)
            and 1 <= len(message['Records']) <= 100, 'invalid_notification')
    for row in message['Records']:
        require(row.get('eventSource') == 'aws:s3' and row.get('awsRegion') == REGION
                and str(row.get('eventName', '')).startswith('ObjectCreated:'), 'notification_out_of_scope')
        bucket = row['s3']['bucket']['name']
        obj = row['s3']['object']
        key = unquote_plus(obj['key'], encoding='utf-8', errors='strict')
        require(len(key.encode()) <= 1024 and not any(ord(c) < 32 for c in key), 'invalid_object_key')
        source = settings.match(bucket, key)
        etag = obj.get('eTag')
        require(isinstance(etag, str) and re.fullmatch(r'[a-fA-F0-9]{32}(?:-\d{1,8})?', etag), 'invalid_etag')
        require(type(obj.get('size')) is int and 0 <= obj['size'] <= MAX_COMPRESSED, 'object_size_limit')
        version = obj.get('versionId')
        require(version is None or isinstance(version, str) and 1 <= len(version) <= 1024, 'invalid_version')
        yield source, key, etag, version


def read_object(s3, source, key, etag, version):
    args = {'Bucket': source.bucket, 'Key': key, 'IfMatch': '"' + etag + '"',
            'ExpectedBucketOwner': source.bucket_owner}
    if version:
        args['VersionId'] = version
    response = s3.get_object(**args)
    body = response['Body']
    try:
        require(0 <= response['ContentLength'] <= MAX_COMPRESSED, 'object_size_limit')
        require(response.get('ETag', '').strip('"') == etag, 'object_identity_mismatch')
        if version:
            require(response.get('VersionId') == version, 'object_identity_mismatch')
        compressed = body.read(MAX_COMPRESSED + 1)
        require(len(compressed) <= MAX_COMPRESSED, 'object_size_limit')
        require(len(compressed) == response['ContentLength'], 'object_truncated')
    finally:
        body.close()
    if compressed.startswith(b'\x1f\x8b'):
        import io
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            content = stream.read(MAX_EXPANDED + 1)
    else:
        content = compressed
    require(len(content) <= MAX_EXPANDED, 'expanded_size_limit')
    return content.decode('utf-8', errors='strict')


class BulkSink:
    def __init__(self, client):
        self.client = client.options(request_timeout=30, max_retries=0)

    def write(self, documents):
        operations = []
        for index, identifier, document in documents:
            operations.extend(({'create': {'_index': index, '_id': identifier}}, document))
        response = self.client.bulk(operations=operations, pipeline='cloud-soc-received-at-v1')
        require(isinstance(response.get('items'), list) and len(response['items']) == len(documents), 'invalid_bulk_response')
        statuses = [item.get('create', {}).get('status') for item in response['items']]
        require(all(type(status) is int and status in (201, 409) for status in statuses), 'bulk_write_failed')
        return {'created': statuses.count(201), 'duplicates': statuses.count(409)}


class Lease:
    """Renew only this receipt; concurrent workers rely on SQS visibility leases."""
    def __init__(self, sqs, queue, receipt):
        self.sqs, self.queue, self.receipt = sqs, queue, receipt
        self.stop = threading.Event()
        self.failed = threading.Event()
        self.thread = threading.Thread(target=self.renew, daemon=True)

    def renew(self):
        while not self.stop.wait(30):
            try:
                self.sqs.change_message_visibility(QueueUrl=self.queue, ReceiptHandle=self.receipt, VisibilityTimeout=180)
            except Exception:
                self.failed.set()
                return

    def __enter__(self):
        self.thread.start()
        return self

    def check(self):
        require(not self.failed.is_set(), 'queue_lease_lost')

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(timeout=30)


def consume(message, settings, s3, sqs, sink):
    receipt = message['ReceiptHandle']
    with Lease(sqs, settings.queue_url, receipt) as lease:
        notification = load_json(message['Body'])
        if isinstance(notification, dict) and notification.get('Event') == 's3:TestEvent':
            require(notification.get('Service') == 'Amazon S3' and notification.get('Bucket') in {
                s.bucket for s in settings.sources}, 'notification_out_of_scope')
            lease.check()
            sqs.delete_message(QueueUrl=settings.queue_url, ReceiptHandle=receipt)
            return {'objects': 0, 'created': 0, 'duplicates': 0}
        # Fully validate notification scope before touching S3 or writing anything.
        objects = list(object_events(notification, settings))
        totals = {'objects': 0, 'created': 0, 'duplicates': 0}
        for source, key, etag, version in objects:
            lease.check()
            if source.format == 'alb' and key.endswith('/ELBAccessLogTestFile'):
                continue
            text = read_object(s3, source, key, etag, version)
            # S3 console folder markers share approved notification prefixes.
            # Verify owner/version/ETag and actual empty body before skipping.
            if key.endswith('/') and text == '':
                continue
            batch, size = [], 0
            def flush():
                nonlocal size
                if batch:
                    lease.check()
                    counts = sink.write(batch)
                    totals['created'] += counts['created']
                    totals['duplicates'] += counts['duplicates']
                    batch.clear()
                    size = 0
            for ordinal, row, envelope in records(text, source):
                document = project(row, envelope, source, settings)
                occurred = timestamp(document['@timestamp'])
                identifier = hashlib.sha256(json.dumps([
                    settings.organization, source.account_id, source.bucket, key, version, etag, ordinal
                ], separators=(',', ':')).encode()).hexdigest()
                if source.format == 'cloudtrail':
                    identifier = hashlib.sha256(json.dumps([
                        settings.organization, source.account_id, document['cloud']['region'],
                        'cloudtrail', document['event']['id'].lower()
                    ], separators=(',', ':')).encode()).hexdigest()
                elif source.format == 'cloudwatch':
                    identifier = hashlib.sha256(json.dumps([
                        settings.organization, source.account_id, 'cloudwatch',
                        envelope.get('logGroup'), envelope.get('logStream'), document['event']['id']
                    ], separators=(',', ':')).encode()).hexdigest()
                index = 'soc-ingest-' + ('tpot-' if source.format.startswith('tpot_') else 'aws-') + occurred.strftime('%Y.%m.%d')
                document['ingest'] = {'object_id': hashlib.sha256(
                    json.dumps([source.bucket, key, version, etag]).encode()).hexdigest(), 'ordinal': ordinal}
                encoded = len(json.dumps(document).encode())
                require(encoded <= MAX_LINE, 'document_size_limit')
                if len(batch) >= 500 or size + encoded > 2 * 1024 * 1024:
                    flush()
                batch.append((index, identifier, document))
                size += encoded
            flush()
            totals['objects'] += 1
        lease.check()
        sqs.delete_message(QueueUrl=settings.queue_url, ReceiptHandle=receipt)
        return totals


def poll(settings, s3, sqs, sink):
    # One leased message per worker avoids unrenewed receipts waiting in a batch.
    page = sqs.receive_message(QueueUrl=settings.queue_url, WaitTimeSeconds=20,
                               MaxNumberOfMessages=1, VisibilityTimeout=180)
    results = []
    for message in page.get('Messages', []):
        try:
            results.append({'status': 'ok', **consume(message, settings, s3, sqs, sink)})
        except Exception as error:
            # Leave the receipt untouched; the configured redrive policy handles DLQ.
            results.append({'status': 'error', 'code': str(error) if isinstance(error, IngestError)
                            else 'ingestion_failed'})
    return results


def validate_destination(url):
    parsed = urlsplit(url)
    require(parsed.scheme == 'https' and parsed.hostname and not parsed.username and not parsed.password
            and not parsed.query and not parsed.fragment and parsed.path in ('', '/')
            and not any(c.isspace() for c in url), 'invalid_destination')
    require(parsed.port is None or 1 <= parsed.port <= 65535, 'invalid_destination')
    return url
