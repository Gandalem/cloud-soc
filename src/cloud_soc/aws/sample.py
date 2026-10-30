"""Bounded metadata-only sample from existing Sydney resources; no provisioning."""
import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import time

from cloud_soc.aws.cloudtrail import safe
from cloud_soc.aws.streaming import IngestError, REGION, require


def collect(session, account, groups, *, now=None, sleep=time.sleep):
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=30, ignore_configured_endpoint_urls=True,
                    retries={'mode': 'standard', 'total_max_attempts': 3})
    def client(service):
        return session.client(service, region_name=REGION, config=config)
    require(client('sts').get_caller_identity().get('Account') == account, 'account_mismatch')
    now = now or datetime.now(timezone.utc)
    trail = client('cloudtrail')
    events, token = [], None
    for _ in range(3):
        args = {'StartTime': now - timedelta(hours=24), 'EndTime': now, 'MaxResults': 50}
        if token:
            args['NextToken'] = token
        page = trail.lookup_events(**args)
        for outer in page.get('Events', []):
            event = json.loads(outer['CloudTrailEvent'])
            if event.get('recipientAccountId') != account or event.get('awsRegion') != REGION:
                continue
            identity = event.get('userIdentity') or {}
            issuer = (identity.get('sessionContext') or {}).get('sessionIssuer') or {}
            events.append({'event_id': safe(event.get('eventID')), 'timestamp': safe(event.get('eventTime')),
                           'service': safe(event.get('eventSource')), 'action': safe(event.get('eventName')),
                           'actor_type': safe(identity.get('type')), 'role_issuer_arn': safe(issuer.get('arn')),
                           'error_code': safe(event.get('errorCode'))})
        token = page.get('NextToken')
        if not token:
            break
        sleep(0.6)
    logs = client('logs')
    selected = []
    for group in groups:
        try:
            page = logs.filter_log_events(logGroupName=group, limit=20,
                startTime=int((now - timedelta(days=7)).timestamp() * 1000), endTime=int(now.timestamp() * 1000))
            selected.append({'log_group': group, 'more_available': bool(page.get('nextToken')),
                             'events': [{'event_id': safe(e.get('eventId')), 'timestamp_ms': e.get('timestamp'),
                                         'ingestion_time_ms': e.get('ingestionTime')} for e in page.get('events', [])]})
        except Exception:
            selected.append({'log_group': group, 'error': 'service_log_read_failed'})
    return {'account_id': account, 'region': REGION, 'collected_at': now.isoformat(),
            'mode': 'bounded_existing_resource_metadata_sample', 'cloudtrail_more_available': bool(token),
            'cloudtrail_events': events, 'service_log_groups': selected, 'raw_messages_saved': False,
            'new_aws_resources_created': False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--profile')
    parser.add_argument('--log-group', action='append', default=[])
    parser.add_argument('--run', action='store_true')
    parser.add_argument('--output', default='state/aws-sydney-sample.json')
    args = parser.parse_args(argv)
    try:
        require(re.fullmatch(r'\d{12}', args.account), 'invalid_account')
        require(len(args.log_group) <= 10 and all(re.fullmatch(r'[A-Za-z0-9_./#-]{1,512}', x)
                                                for x in args.log_group), 'invalid_log_groups')
        if not args.run:
            print(json.dumps({'region': REGION, 'aws_contacted': False, 'requires': '--run'}))
            return 0
        import boto3
        data = collect(boto3.Session(profile_name=args.profile, region_name=REGION), args.account, args.log_group)
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(data, output, indent=2, ensure_ascii=False)
        print(json.dumps({'status': 'sample_saved', 'output': str(path),
                          'cloudtrail_events': len(data['cloudtrail_events']),
                          'cloudtrail_more_available': data['cloudtrail_more_available'],
                          'service_events': sum(len(g.get('events', [])) for g in data['service_log_groups'])}))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'error', 'code': str(error) if isinstance(error, IngestError)
                          else 'sample_collection_failed', 'credentials_printed': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
