"""Offline SDK/sink boundaries. No AWS credentials, live services or load traffic."""
from copy import deepcopy
import gzip
import io
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from cloud_soc.aws import stream_cli
from cloud_soc.aws.streaming import (
    BulkSink, IngestError, REGION, StreamSettings, consume, object_events, poll,
    project, read_object, records, validate_destination,
)

ROOT = Path(__file__).resolve().parents[1]
ACCOUNT = '123456789012'
ETAG = 'a' * 32
CANARY = 'PRIVATE_CANARY_NEVER_INDEX'
FLOW = '2 123456789012 eni-0123456789abcdef0 192.0.2.1 198.51.100.1 12345 443 6 3 900 1792545600 1792545660 ACCEPT OK'
ALB = ('https 2026-10-21T00:00:00Z app/replace-alb-name/0123456789abcdef '
       '192.0.2.1:12345 198.51.100.1:443 0.001 0.002 0.003 200 200 100 500 '
       '"GET https://example.test/private?token=' + CANARY + ' HTTP/1.1" "' + CANARY + '" '
       'ECDHE TLSv1.3 arn:aws:elasticloadbalancing:ap-southeast-2:123456789012:targetgroup/test/id '
       '"Root=private" "example.test" "-" 1 2026-10-21T00:00:00Z "forward"')


@pytest.fixture
def config():
    return json.loads((ROOT / 'deploy/aws/sydney/collector.example.json').read_text())


@pytest.fixture
def settings(config):
    return StreamSettings.parse(config)


def notification(settings, index=1, *, key=None, etag=ETAG, version='version-one'):
    source = settings.sources[index]
    return {'Records': [{'eventSource': 'aws:s3', 'eventName': 'ObjectCreated:Put', 'awsRegion': REGION,
                         's3': {'bucket': {'name': source.bucket}, 'object': {
                             'key': key or source.prefix + 'sample.log.gz', 'size': 100,
                             'eTag': etag, 'versionId': version}}}]}


class S3:
    def __init__(self, data):
        self.data = data
        self.requests = []

    def get_object(self, **kwargs):
        self.requests.append(kwargs)
        return {'Body': io.BytesIO(self.data), 'ContentLength': len(self.data),
                'ETag': '"' + ETAG + '"', 'VersionId': kwargs.get('VersionId')}


class Sink:
    def __init__(self):
        self.docs = {}
        self.batches = []
        self.fail = False

    def write(self, batch):
        self.batches.append(len(batch))
        if self.fail:
            raise IngestError('bulk_write_failed')
        created = 0
        for index, identifier, document in batch:
            if (index, identifier) not in self.docs:
                self.docs[index, identifier] = deepcopy(document)
                created += 1
        return {'created': created, 'duplicates': len(batch) - created}


def receipt(value):
    return {'ReceiptHandle': 'synthetic-receipt', 'Body': json.dumps(value)}


@pytest.mark.parametrize('mutation', [
    lambda c: c.update(region='ap-northeast-2'),
    lambda c: c.update(queue_url=c['queue_url'].replace('123456789012', '999999999999')),
    lambda c: c['sources'].append(c['sources'][0]),
    lambda c: c['sources'][0].update(prefix='../outside/'),
    lambda c: c['sources'][2].update(resource_id='app/other'),
    lambda c: c.update(role_teams={'arn:aws:sts::123456789012:assumed-role/demo/session': 'team-a'}),
])
def test_invalid_configuration_is_rejected(config, mutation):
    mutation(config)
    with pytest.raises(IngestError):
        StreamSettings.parse(config)


@pytest.mark.parametrize('url', ['http://example.test', 'https://user:pass@example.test',
                                'https://example.test/path', 'https://example.test?key=secret',
                                'https://example.test:0'])
def test_destination_requires_verified_https_origin(url):
    with pytest.raises(IngestError):
        validate_destination(url)


def test_cloudtrail_issuer_maps_team_without_indexing_sensitive_fields(settings):
    row = json.loads((ROOT / 'tests/fixtures/cloudtrail_management.json').read_text())['events'][1]
    settings.role_teams['arn:aws:iam::123456789012:role/fixture'] = 'team-b'
    document = project(row, None, settings.sources[0], settings)
    assert document['labels']['team'] == 'team-b'
    assert document['labels']['team_basis'] == 'cloudtrail_session_issuer'
    assert document['cloud']['region'] == 'us-east-1'
    assert document['labels']['collection_region'] == REGION
    assert 'PRIVATE_CANARY' not in json.dumps(document)
    del settings.role_teams['arn:aws:iam::123456789012:role/fixture']
    assert project(row, None, settings.sources[0], settings)['labels']['team'] == 'unattributed'


def test_cloudtrail_other_regional_ec2_and_foreign_accounts_fail(settings):
    row = json.loads((ROOT / 'tests/fixtures/cloudtrail_management.json').read_text())['events'][2]
    with pytest.raises(IngestError, match='event_region_mismatch'):
        project(row, None, settings.sources[0], settings)
    row['awsRegion'] = REGION
    row['recipientAccountId'] = '999999999999'
    with pytest.raises(ValueError):
        project(row, None, settings.sources[0], settings)


def test_vpc_counts_scope_and_no_invented_role(settings):
    document = project(FLOW, None, settings.sources[1], settings)
    assert document['network'] == {'iana_number': 6, 'packets': 3, 'bytes': 900}
    assert document['source'] == {'ip': '192.0.2.1', 'port': 12345}
    assert document['event']['action'] == 'accept'
    assert document['labels']['team_basis'] == 'configured_source_binding'
    assert 'user' not in document
    with pytest.raises(IngestError):
        project(FLOW.replace(ACCOUNT, '999999999999'), None, settings.sources[1], settings)


@pytest.mark.parametrize('status', ['NODATA', 'SKIPDATA'])
def test_vpc_missing_data_remains_explicit(status, settings):
    line = f'2 {ACCOUNT} eni-0123456789abcdef0 - - - - - - - 1792545600 1792545660 - {status}'
    document = project(line, None, settings.sources[1], settings)
    assert document['aws']['stream']['log_status'] == status
    assert document['event']['outcome'] == 'unknown'
    assert 'network' not in document


def test_alb_metadata_and_exact_bound_resource(settings):
    document = project(ALB, None, settings.sources[2], settings)
    assert document['http'] == {'request': {'method': 'GET'}, 'response': {'status_code': 200}}
    assert document['network']['bytes'] == 600
    assert CANARY not in json.dumps(document)
    assert 'url' not in document
    with pytest.raises(IngestError, match='resource_mismatch'):
        project(ALB.replace('replace-alb-name', 'other'), None, settings.sources[2], settings)


def test_cloudwatch_concatenated_envelopes_and_no_message(settings):
    envelope = {'owner': ACCOUNT, 'messageType': 'DATA_MESSAGE', 'logGroup': '/aws/lambda/demo',
                'logStream': 'stream', 'logEvents': [{'id': 'event-one', 'timestamp': 1792540800000, 'message': CANARY}]}
    data = json.dumps(envelope) + json.dumps(envelope)
    rows = list(records(data, settings.sources[3]))
    assert [x[0] for x in rows] == [1, 2]
    document = project(rows[0][1], rows[0][2], settings.sources[3], settings)
    assert document['@timestamp'] == '2026-10-21T00:00:00Z'
    assert CANARY not in json.dumps(document)
    envelope['owner'] = '999999999999'
    with pytest.raises(IngestError, match='account_mismatch'):
        list(records(json.dumps(envelope), settings.sources[3]))


@pytest.mark.parametrize('index,payload,action', [
    (4, {'timestamp': '2026-10-21T00:00:00Z', 'eventid': 'cowrie.login.failed', 'src_ip': '192.0.2.2',
         'username': CANARY, 'password': CANARY, 'input': CANARY}, 'cowrie.login.failed'),
    (5, {'timestamp': '2026-10-21T00:00:00+0000', 'event_type': 'alert', 'src_ip': '192.0.2.2',
         'dest_ip': '198.51.100.2', 'alert': {'signature_id': 12345}, 'payload': CANARY}, 'alert'),
])
def test_tpot_sources_keep_metadata_only(index, payload, action, settings):
    document = project(json.dumps(payload), None, settings.sources[index], settings)
    assert document['event']['action'] == action
    assert document['observer'] == {'name': 'team-a-tpot', 'type': 'honeypot'}
    assert CANARY not in json.dumps(document)


def test_batch_limits_replay_and_ack_after_all_records(settings):
    data = gzip.compress(('\n'.join([FLOW] * 1201) + '\n').encode())
    s3, sqs, sink = S3(data), Mock(), Sink()
    message = receipt(notification(settings))
    result = consume(message, settings, s3, sqs, sink)
    assert result == {'objects': 1, 'created': 1201, 'duplicates': 0}
    assert sink.batches == [500, 500, 201]
    assert len(sink.docs) == 1201
    sqs.delete_message.assert_called_once_with(QueueUrl=settings.queue_url, ReceiptHandle='synthetic-receipt')
    assert s3.requests[0]['ExpectedBucketOwner'] == ACCOUNT
    assert s3.requests[0]['IfMatch'] == '"' + ETAG + '"'
    assert s3.requests[0]['VersionId'] == 'version-one'
    again = consume(message, settings, s3, sqs, sink)
    assert again == {'objects': 1, 'created': 0, 'duplicates': 1201}
    assert len(sink.docs) == 1201


def test_sink_failure_never_acknowledges_and_replay_recovers(settings):
    sqs, sink, s3 = Mock(), Sink(), S3((FLOW + '\n').encode())
    sink.fail = True
    with pytest.raises(IngestError, match='bulk_write_failed'):
        consume(receipt(notification(settings)), settings, s3, sqs, sink)
    sqs.delete_message.assert_not_called()
    sink.fail = False
    assert consume(receipt(notification(settings)), settings, s3, sqs, sink)['created'] == 1


def test_malformed_tail_after_partial_bulk_is_not_acknowledged(settings):
    sqs, sink = Mock(), Sink()
    data = ('\n'.join([FLOW] * 501 + ['invalid']) + '\n').encode()
    with pytest.raises(IngestError):
        consume(receipt(notification(settings)), settings, S3(data), sqs, sink)
    sqs.delete_message.assert_not_called()
    assert len(sink.docs) == 500


def test_wrong_notification_account_prefix_and_region_touch_no_sink(settings):
    for field, value in [('awsRegion', 'us-east-2'), ('eventSource', 'untrusted')]:
        event = notification(settings)
        event['Records'][0][field] = value
        with pytest.raises(IngestError):
            list(object_events(event, settings))
    event = notification(settings, key='outside/no-log.gz')
    sqs, s3, sink = Mock(), Mock(), Mock()
    with pytest.raises(IngestError, match='object_out_of_scope'):
        consume(receipt(event), settings, s3, sqs, sink)
    s3.get_object.assert_not_called()
    sink.write.assert_not_called()
    sqs.delete_message.assert_not_called()


def test_notification_decodes_url_key_and_keeps_version(settings):
    event = notification(settings, key=settings.sources[1].prefix + 'log%2Bfile+one.gz')
    _, key, etag, version = next(object_events(event, settings))
    assert key.endswith('log+file one.gz')
    assert etag == ETAG and version == 'version-one'


def test_oversize_gzip_and_mutable_object_identity_fail_closed(settings, monkeypatch):
    from cloud_soc.aws import streaming
    monkeypatch.setattr(streaming, 'MAX_EXPANDED', 128)
    s3 = S3(gzip.compress(b'x' * 129))
    with pytest.raises(IngestError, match='expanded_size_limit'):
        read_object(s3, settings.sources[1], 'key', ETAG, None)
    bad = Mock()
    body = io.BytesIO(b'payload')
    bad.get_object.return_value = {'Body': body, 'ContentLength': 7, 'ETag': '"' + 'b'*32 + '"'}
    with pytest.raises(IngestError, match='object_identity_mismatch'):
        read_object(bad, settings.sources[1], 'key', ETAG, None)
    assert body.closed


def test_bulk_partial_errors_reject_entire_receipt():
    client = Mock()
    client.options.return_value = client
    sink = BulkSink(client)
    batch = [('soc-ingest-aws-2026.10.21', str(i), {'event': {}}) for i in range(2)]
    client.bulk.return_value = {'items': [{'create': {'status': 201}}, {'create': {'status': 429}}]}
    with pytest.raises(IngestError, match='bulk_write_failed'):
        sink.write(batch)
    client.bulk.return_value = {'items': [{'create': {'status': 201}}, {'create': {'status': 409}}]}
    assert sink.write(batch) == {'created': 1, 'duplicates': 1}
    assert client.bulk.call_args.kwargs['pipeline'] == 'cloud-soc-received-at-v1'


def test_poll_hides_secret_sdk_error_and_leaves_queue_receipt(settings):
    s3, sqs, sink = Mock(), Mock(), Mock()
    sqs.receive_message.return_value = {'Messages': [receipt(notification(settings))]}
    s3.get_object.side_effect = RuntimeError(CANARY)
    assert poll(settings, s3, sqs, sink) == [{'status': 'error', 'code': 'ingestion_failed'}]
    sqs.delete_message.assert_not_called()


def test_default_cli_is_offline(config, tmp_path, monkeypatch, capsys):
    path = tmp_path / 'config.json'
    path.write_text(json.dumps(config))
    monkeypatch.setattr(stream_cli, 'preflight', Mock(side_effect=AssertionError('must stay offline')))
    assert stream_cli.main(['--config', str(path)]) == 0
    output = json.loads(capsys.readouterr().out)
    assert output['aws_contacted'] is False and output['es_contacted'] is False


def test_preflight_account_and_dlq_guards_before_s3(settings):
    session = Mock()
    clients = {x: Mock() for x in ('sts', 'sqs', 's3')}
    session.client.side_effect = lambda name, **_: clients[name]
    clients['sts'].get_caller_identity.return_value = {'Account': '999999999999'}
    with pytest.raises(IngestError, match='collector_account_mismatch'):
        stream_cli.preflight(session, settings, None)
    clients['sts'].get_caller_identity.return_value = {'Account': ACCOUNT}
    clients['sqs'].get_queue_attributes.return_value = {'Attributes': {
        'QueueArn': f'arn:aws:sqs:{REGION}:{ACCOUNT}:' + settings.queue_url.rsplit('/', 1)[1]}}
    with pytest.raises(IngestError, match='queue_requires_dead_letter_policy'):
        stream_cli.preflight(session, settings, None)
    clients['s3'].get_bucket_location.assert_not_called()


@pytest.mark.parametrize('format_index', [0, 3])
def test_logical_event_ids_deduplicate_across_different_s3_files(settings, format_index):
    if format_index == 0:
        event = json.loads((ROOT / 'tests/fixtures/cloudtrail_management.json').read_text())['events'][1]
        data = json.dumps({'Records': [event]}).encode()
    else:
        data = json.dumps({'owner': ACCOUNT, 'messageType': 'DATA_MESSAGE',
                           'logGroup': '/aws/lambda/demo', 'logStream': 'stream',
                           'logEvents': [{'id': 'same-event', 'timestamp': 1792540800000}]}).encode()
    sqs, sink, s3 = Mock(), Sink(), S3(data)
    for name in ('first.gz', 'second.gz'):
        consume(receipt(notification(settings, index=format_index,
            key=settings.sources[format_index].prefix + name)), settings, s3, sqs, sink)
    assert len(sink.docs) == 1
    assert sqs.delete_message.call_count == 2


def test_test_notification_only_acknowledges_an_approved_bucket(settings):
    sqs, s3, sink = Mock(), Mock(), Mock()
    event = {'Service': 'Amazon S3', 'Event': 's3:TestEvent', 'Bucket': settings.sources[0].bucket}
    assert consume(receipt(event), settings, s3, sqs, sink) == {'objects': 0, 'created': 0, 'duplicates': 0}
    sqs.delete_message.assert_called_once()
    event['Bucket'] = 'unapproved-bucket'
    with pytest.raises(IngestError):
        consume(receipt(event), settings, s3, sqs, sink)
    assert sqs.delete_message.call_count == 1
    s3.get_object.assert_not_called()


def test_s3_reads_specific_version_and_notification_body_never_authorizes_a_new_prefix(settings):
    bad = notification(settings)
    bad['Records'].append(notification(settings, key='unapproved/new-prefix.gz')['Records'][0])
    s3, sqs, sink = Mock(), Mock(), Mock()
    with pytest.raises(IngestError):
        consume(receipt(bad), settings, s3, sqs, sink)
    s3.get_object.assert_not_called()
    sqs.delete_message.assert_not_called()


def test_lease_failure_keeps_receipt(settings, monkeypatch):
    from cloud_soc.aws import streaming
    monkeypatch.setattr(streaming.Lease, 'check', Mock(side_effect=IngestError('queue_lease_lost')))
    sqs = Mock()
    with pytest.raises(IngestError, match='queue_lease_lost'):
        consume(receipt(notification(settings)), settings, S3(FLOW.encode()), sqs, Sink())
    sqs.delete_message.assert_not_called()


def test_preflight_verifies_queue_dlq_and_bucket_region(settings):
    session = Mock()
    clients = {name: Mock() for name in ('sts', 'sqs', 's3')}
    session.client.side_effect = lambda name, **_: clients[name]
    clients['sts'].get_caller_identity.return_value = {'Account': ACCOUNT}
    clients['sqs'].get_queue_attributes.return_value = {'Attributes': {
        'QueueArn': f'arn:aws:sqs:{REGION}:{ACCOUNT}:' + settings.queue_url.rsplit('/', 1)[1],
        'RedrivePolicy': json.dumps({'deadLetterTargetArn': f'arn:aws:sqs:{REGION}:{ACCOUNT}:dlq', 'maxReceiveCount': '5'})}}
    clients['s3'].get_bucket_location.return_value = {'LocationConstraint': REGION}
    assert stream_cli.preflight(session, settings, None) == (clients['s3'], clients['sqs'])
    clients['s3'].get_bucket_location.assert_called_once_with(
        Bucket=settings.sources[0].bucket, ExpectedBucketOwner=ACCOUNT)
    clients['s3'].get_bucket_location.return_value = {'LocationConstraint': 'us-east-1'}
    with pytest.raises(IngestError, match='bucket_region_mismatch'):
        stream_cli.preflight(session, settings, None)


def test_bounded_sample_does_not_export_cloudwatch_message_or_aws_credentials():
    from cloud_soc.aws.sample import collect
    from datetime import datetime, timezone
    session = Mock()
    clients = {name: Mock() for name in ('sts', 'cloudtrail', 'logs')}
    session.client.side_effect = lambda name, **_: clients[name]
    clients['sts'].get_caller_identity.return_value = {'Account': ACCOUNT}
    fixture = json.loads((ROOT / 'tests/fixtures/cloudtrail_management.json').read_text())['events'][2]
    fixture['awsRegion'] = REGION
    clients['cloudtrail'].lookup_events.return_value = {
        'Events': [{'CloudTrailEvent': json.dumps(fixture)}], 'NextToken': 'another-page'}
    clients['logs'].filter_log_events.return_value = {'events': [{
        'eventId': 'one', 'timestamp': 1792540800000, 'ingestionTime': 1792540810000, 'message': CANARY}]}
    sleep = Mock()
    result = collect(session, ACCOUNT, ['/ecs/test'], now=datetime(2026, 10, 21, tzinfo=timezone.utc), sleep=sleep)
    assert clients['cloudtrail'].lookup_events.call_count == 3
    assert result['cloudtrail_more_available'] is True
    assert result['service_log_groups'][0]['events'] == [{
        'event_id': 'one', 'timestamp_ms': 1792540800000, 'ingestion_time_ms': 1792540810000}]
    assert CANARY not in json.dumps(result) and 'PRIVATE_CANARY' not in json.dumps(result)
    assert result['raw_messages_saved'] is False and result['new_aws_resources_created'] is False


def test_inventory_default_stays_offline(capsys):
    from cloud_soc.aws.inventory import main
    assert main([]) == 0
    assert json.loads(capsys.readouterr().out)['aws_contacted'] is False


def test_truncated_or_wrong_version_objects_never_acknowledge(settings):
    for override in ({'ContentLength': 1000}, {'VersionId': 'different-version'}):
        s3, sqs = Mock(), Mock()
        s3.get_object.return_value = {'Body': io.BytesIO(FLOW.encode()), 'ContentLength': len(FLOW),
                                     'ETag': '"' + ETAG + '"', 'VersionId': 'version-one', **override}
        with pytest.raises(IngestError):
            consume(receipt(notification(settings)), settings, s3, sqs, Sink())
        sqs.delete_message.assert_not_called()


def test_alb_missing_status_and_method_do_not_invent_success(settings):
    line = ALB.replace('200 200 100 500', '- - 100 500').replace(
        'GET https://example.test/private?token=' + CANARY + ' HTTP/1.1', '- - -')
    document = project(line, None, settings.sources[2], settings)
    assert document['http'] == {}
    assert document['event']['outcome'] == 'unknown'


def test_distinct_iam_users_map_by_full_arn_without_claiming_a_role(config):
    config['user_teams'] = {'arn:aws:iam::123456789012:user/fixture': 'member-a'}
    settings = StreamSettings.parse(config)
    row = json.loads((ROOT / 'tests/fixtures/cloudtrail_management.json').read_text())['events'][0]
    document = project(row, None, settings.sources[0], settings)
    assert document['labels']['team'] == 'member-a'
    assert document['labels']['team_basis'] == 'cloudtrail_iam_user'
    row['userIdentity']['arn'] = 'arn:aws:iam::123456789012:user/other'
    assert project(row, None, settings.sources[0], settings)['labels']['team'] == 'unattributed'


def test_iam_user_mapping_does_not_accept_assumed_role_arns(config):
    config['user_teams'] = {'arn:aws:sts::123456789012:assumed-role/fixture/member': 'member-a'}
    with pytest.raises(IngestError, match='invalid_users'):
        StreamSettings.parse(config)


def test_verified_empty_s3_folder_marker_does_not_poison_queue(settings):
    event = notification(settings, key=settings.sources[1].prefix + 'AWSLogs/')
    event['Records'][0]['s3']['object']['size'] = 0
    s3, sqs, sink = S3(b''), Mock(), Sink()
    result = consume(receipt(event), settings, s3, sqs, sink)
    assert result == {'objects': 0, 'created': 0, 'duplicates': 0}
    assert len(s3.requests) == 1
    sqs.delete_message.assert_called_once()


def test_nonempty_folder_key_is_not_silently_discarded(settings):
    event = notification(settings, key=settings.sources[1].prefix + 'AWSLogs/')
    sqs, sink = Mock(), Sink()
    result = consume(receipt(event), settings, S3(FLOW.encode()), sqs, sink)
    assert result['created'] == 1
