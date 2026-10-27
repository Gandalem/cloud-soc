"""Sydney S3/SQS collector. Configuration validation is offline by default."""
import argparse
import json
from pathlib import Path
import time

from cloud_soc.aws.__main__ import protected_key
from cloud_soc.aws.streaming import (
    BulkSink, IngestError, REGION, StreamSettings, load_json, poll, require, validate_destination,
)


def preflight(session, settings, sdk_config):
    sts = session.client('sts', region_name=REGION, config=sdk_config)
    identity = sts.get_caller_identity()
    require(identity.get('Account') == settings.collector_account, 'collector_account_mismatch')
    sqs = session.client('sqs', region_name=REGION, config=sdk_config)
    attributes = sqs.get_queue_attributes(QueueUrl=settings.queue_url,
        AttributeNames=['QueueArn', 'RedrivePolicy'])['Attributes']
    name = settings.queue_url.rsplit('/', 1)[1]
    require(attributes.get('QueueArn') == f'arn:aws:sqs:{REGION}:{settings.collector_account}:{name}', 'queue_scope_mismatch')
    redrive = load_json(attributes.get('RedrivePolicy', '{}'))
    require(isinstance(redrive.get('deadLetterTargetArn'), str)
            and redrive['deadLetterTargetArn'].startswith(f'arn:aws:sqs:{REGION}:{settings.collector_account}:')
            and 2 <= int(redrive.get('maxReceiveCount', 0)) <= 20, 'queue_requires_dead_letter_policy')
    s3 = session.client('s3', region_name=REGION, config=sdk_config)
    for bucket, owner in sorted({(s.bucket, s.bucket_owner) for s in settings.sources}):
        require(s3.get_bucket_location(Bucket=bucket, ExpectedBucketOwner=owner).get(
            'LocationConstraint') == REGION, 'bucket_region_mismatch')
    return s3, sqs


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True)
    parser.add_argument('--profile')
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--once', action='store_true')
    parser.add_argument('--es-url')
    parser.add_argument('--ca-file')
    parser.add_argument('--api-key-file')
    args = parser.parse_args(argv)
    try:
        path = Path(args.config)
        require(not path.is_symlink() and path.is_file() and path.stat().st_size <= 65536, 'invalid_config_file')
        settings = StreamSettings.parse(load_json(path.read_text(encoding='utf-8')))
        require(not args.once or args.run, 'once_requires_run')
        if not args.run:
            print(json.dumps({'status': 'config_valid', 'region': REGION, 'sources': len(settings.sources),
                              'aws_contacted': False, 'es_contacted': False}))
            return 0
        url = validate_destination(args.es_url or '')
        require(args.ca_file and Path(args.ca_file).is_file() and not Path(args.ca_file).is_symlink(), 'missing_ca_file')
        key = protected_key(args.api_key_file or '')
        import boto3
        from botocore.config import Config
        from elasticsearch import Elasticsearch
        config = Config(connect_timeout=5, read_timeout=35,
                        retries={'mode': 'standard', 'total_max_attempts': 3}, ignore_configured_endpoint_urls=True)
        session = boto3.Session(profile_name=args.profile, region_name=REGION)
        s3, sqs = preflight(session, settings, config)
        with Elasticsearch(url, ca_certs=args.ca_file, api_key=key, max_retries=0) as es:
            sink = BulkSink(es)
            while True:
                results = poll(settings, s3, sqs, sink)
                print(json.dumps({'region': REGION, 'messages': results}), flush=True)
                if args.once:
                    return 1 if any(x['status'] == 'error' for x in results) else 0
                if any(x['status'] == 'error' for x in results):
                    time.sleep(5)
    except KeyboardInterrupt:
        return 130
    except Exception as error:
        print(json.dumps({'status': 'error', 'code': str(error) if isinstance(error, IngestError)
                          else 'collector_unavailable', 'credentials_printed': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
