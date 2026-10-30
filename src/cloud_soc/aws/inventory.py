"""Explicit, read-only Sydney inventory. Never exports credentials or log payloads."""
import argparse
import json
import os
from pathlib import Path

REGION = 'ap-southeast-2'


def inventory(session):
    from botocore.config import Config
    config = Config(connect_timeout=5, read_timeout=20,
                    retries={'mode': 'standard', 'total_max_attempts': 3},
                    ignore_configured_endpoint_urls=True)
    def client(service):
        return session.client(service, region_name=REGION, config=config)
    who = client('sts').get_caller_identity()
    result = {'region': REGION, 'account_id': who['Account'], 'caller_arn': who['Arn'],
              'read_only': True, 'errors': [], 'truncated': []}
    def read(label, service, operation, key, project, **kwargs):
        rows = []
        try:
            api = client(service)
            if api.can_paginate(operation):
                pages = api.get_paginator(operation).paginate(**kwargs)
            else:
                pages = [getattr(api, operation)(**kwargs)]
            for number, page in enumerate(pages):
                if number >= 100 or len(rows) + len(page.get(key, [])) > 1000:
                    result['truncated'].append(label)
                    break
                rows.extend(project(row) for row in page.get(key, []))
            result[label] = rows
        except Exception as error:
            response = getattr(error, 'response', {})
            code = response.get('Error', {}).get('Code', 'unavailable')
            result['errors'].append({'source': label, 'code': code if code in (
                'AccessDenied', 'AccessDeniedException', 'UnauthorizedOperation',
                'ExpiredToken', 'ThrottlingException') else 'unavailable'})
            result[label] = rows
    read('roles', 'iam', 'list_roles', 'Roles', lambda x: {'name': x['RoleName'], 'arn': x['Arn']})
    read('vpcs', 'ec2', 'describe_vpcs', 'Vpcs', lambda x: {
        'vpc_id': x['VpcId'], 'default': x.get('IsDefault', False),
        'tags': {t['Key']: t['Value'] for t in x.get('Tags', []) if t['Key'] in ('Name', 'Team', 'Owner')}})
    read('load_balancers', 'elbv2', 'describe_load_balancers', 'LoadBalancers', lambda x: {
        'arn': x['LoadBalancerArn'], 'name': x['LoadBalancerName'], 'vpc_id': x['VpcId'], 'type': x['Type']})
    read('trails', 'cloudtrail', 'describe_trails', 'trailList', lambda x: {
        'arn': x['TrailARN'], 'home_region': x.get('HomeRegion'), 'bucket': x.get('S3BucketName'),
        'prefix': x.get('S3KeyPrefix', '')}, includeShadowTrails=False)
    read('flow_logs', 'ec2', 'describe_flow_logs', 'FlowLogs', lambda x: {
        'id': x['FlowLogId'], 'resource_id': x.get('ResourceId'), 'status': x.get('FlowLogStatus'),
        'destination_type': x.get('LogDestinationType'), 'destination': x.get('LogDestination'),
        'format': x.get('LogFormat')})
    read('log_groups', 'logs', 'describe_log_groups', 'logGroups', lambda x: {
        'name': x['logGroupName'], 'arn': x['arn'], 'stored_bytes': x.get('storedBytes')})
    read('buckets', 's3', 'list_buckets', 'Buckets', lambda x: {'name': x['Name']})
    for bucket in result['buckets']:
        try:
            location = client('s3').get_bucket_location(
                Bucket=bucket['name'], ExpectedBucketOwner=who['Account'])['LocationConstraint'] or 'us-east-1'
            bucket['region'] = location
        except Exception:
            bucket['region'] = 'unverified'
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', help='Contact AWS using existing credentials; read only')
    parser.add_argument('--profile')
    parser.add_argument('--output', default='state/aws-sydney-inventory.json')
    args = parser.parse_args(argv)
    if not args.run:
        print(json.dumps({'region': REGION, 'aws_contacted': False, 'requires': '--run'}))
        return 0
    try:
        import boto3
        data = inventory(boto3.Session(profile_name=args.profile, region_name=REGION))
        path = Path(args.output)
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as output:
            json.dump(data, output, indent=2, ensure_ascii=False)
        print(json.dumps({'status': 'inventory_saved', 'output': str(path), 'region': REGION,
                          'incomplete': bool(data['errors'] or data['truncated'])}))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'error', 'code': 'output_exists' if isinstance(error, FileExistsError)
                          else 'aws_inventory_unavailable', 'credentials_printed': False}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
