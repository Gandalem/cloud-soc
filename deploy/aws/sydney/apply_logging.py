"""Apply a reviewed service-delivery plan to task-owned buffers. Default: dry run.

Creates no identity roles, changes no existing trails or EC2 instances, and
opens no ports. Keep this file beside delivery_plan.py when using CloudShell.
"""
import argparse
import json
import os
from pathlib import Path

from delivery_plan import plan as generate

TASK = 'aws-sydney-ingest-20261021'


def apply(value, session, receipt):
    from botocore.config import Config
    region, account, bucket = value['region'], value['account'], value['bucket']
    config = Config(connect_timeout=5, read_timeout=30, ignore_configured_endpoint_urls=True,
                    retries={'mode': 'standard', 'total_max_attempts': 3})
    clients = {name: session.client(name, region_name=region, config=config)
               for name in ('sts', 's3', 'sqs', 'cloudtrail', 'ec2', 'elbv2')}
    if clients['sts'].get_caller_identity()['Account'] != account:
        raise ValueError('account_mismatch')
    s3, sqs, ct, ec2, alb = (clients[x] for x in ('s3', 'sqs', 'cloudtrail', 'ec2', 'elbv2'))
    tags = {x['Key']: x['Value'] for x in s3.get_bucket_tagging(Bucket=bucket, ExpectedBucketOwner=account)['TagSet']}
    if tags.get('TaskId') != TASK or s3.get_bucket_location(
            Bucket=bucket, ExpectedBucketOwner=account).get('LocationConstraint') != region:
        raise ValueError('unowned_or_wrong_region_bucket')
    queue = sqs.get_queue_url(QueueName='cloud-soc-sydney-ingest', QueueOwnerAWSAccountId=account)['QueueUrl']
    if sqs.list_queue_tags(QueueUrl=queue).get('Tags', {}).get('TaskId') != TASK:
        raise ValueError('unowned_queue')
    lb = alb.describe_load_balancers(LoadBalancerArns=[value['alb_arn']])['LoadBalancers'][0]
    if lb['VpcId'] != value['vpc']:
        raise ValueError('alb_vpc_mismatch')
    attributes = alb.describe_load_balancer_attributes(LoadBalancerArn=value['alb_arn'])['Attributes']
    previous = {x['Key']: x['Value'] for x in attributes}
    receipt['previous_alb_attributes'] = attributes
    if previous.get('access_logs.s3.enabled') == 'true' and (
            previous.get('access_logs.s3.bucket') != bucket or previous.get('access_logs.s3.prefix') != 'alb/shared'):
        raise ValueError('existing_alb_logging_destination_conflict')
    current_notifications = s3.get_bucket_notification_configuration(Bucket=bucket, ExpectedBucketOwner=account)
    meaningful = {k: v for k, v in current_notifications.items() if k != 'ResponseMetadata' and v}
    if meaningful and meaningful != value['notifications']:
        raise ValueError('existing_notification_conflict')
    try:
        previous_policy = json.loads(s3.get_bucket_policy(Bucket=bucket, ExpectedBucketOwner=account)['Policy'])
    except s3.exceptions.ClientError as error:
        if error.response.get('Error', {}).get('Code') != 'NoSuchBucketPolicy':
            raise
        previous_policy = None
    receipt['previous_bucket_policy'] = previous_policy
    if previous_policy and previous_policy != value['bucket_policy']:
        raise ValueError('existing_bucket_policy_conflict')
    sqs.set_queue_attributes(QueueUrl=queue, Attributes={'Policy': json.dumps(value['queue_policy'])})
    receipt['completed'].append('sqs_service_delivery_policy')
    s3.put_bucket_policy(Bucket=bucket, ExpectedBucketOwner=account, Policy=json.dumps(value['bucket_policy']))
    receipt['completed'].append('s3_service_delivery_policy')
    s3.put_bucket_notification_configuration(Bucket=bucket, ExpectedBucketOwner=account,
                                            NotificationConfiguration=value['notifications'])
    receipt['completed'].append('s3_notifications')
    flow_destination = value['flow']['LogDestination'].rstrip('/')
    flow_logs = ec2.describe_flow_logs(Filters=[{'Name': 'resource-id', 'Values': [value['vpc']]}])['FlowLogs']
    matching = [x for x in flow_logs if x.get('LogDestination', '').rstrip('/') == flow_destination
                and x.get('TrafficType') == 'ALL']
    if matching:
        receipt['flow_log_ids'] = [x['FlowLogId'] for x in matching]
    else:
        response = ec2.create_flow_logs(**value['flow'], TagSpecifications=[{
            'ResourceType': 'vpc-flow-log', 'Tags': [{'Key': 'TaskId', 'Value': TASK},
                                                   {'Key': 'Project', 'Value': 'CloudSOC'}]}])
        if response.get('Unsuccessful'):
            raise ValueError('flow_log_create_failed')
        receipt['flow_log_ids'] = response['FlowLogIds']
    receipt['completed'].append('vpc_flow_logging')
    # The Flow Logs API can insert broad delivery statements. Replace only this
    # task's policy and the two known generated statements with the scoped plan.
    after = json.loads(s3.get_bucket_policy(Bucket=bucket, ExpectedBucketOwner=account)['Policy'])
    allowed_sids = {s['Sid'] for s in value['bucket_policy']['Statement']} | {
        'AWSLogDeliveryWrite', 'AWSLogDeliveryAclCheck'}
    if any(s.get('Sid') not in allowed_sids for s in after['Statement']):
        raise ValueError('concurrent_bucket_policy_change')
    if after != value['bucket_policy']:
        s3.put_bucket_policy(Bucket=bucket, ExpectedBucketOwner=account, Policy=json.dumps(value['bucket_policy']))
    alb.modify_load_balancer_attributes(LoadBalancerArn=value['alb_arn'], Attributes=value['alb_attributes'])
    receipt['completed'].append('alb_access_logging')
    trail_arn = f'arn:aws:cloudtrail:{region}:{account}:trail/' + value['trail']['Name']
    existing = ct.describe_trails(trailNameList=[trail_arn], includeShadowTrails=False)['trailList']
    if existing:
        prior = existing[0]
        tag_rows = ct.list_tags(ResourceIdList=[trail_arn])['ResourceTagList']
        trail_tags = {x['Key']: x.get('Value') for row in tag_rows for x in row.get('TagsList', [])}
        if trail_tags.get('TaskId') != TASK or prior.get('S3BucketName') != bucket:
            raise ValueError('existing_trail_conflict')
    else:
        ct.create_trail(**value['trail'], TagsList=[{'Key': 'TaskId', 'Value': TASK},
                                                  {'Key': 'Project', 'Value': 'CloudSOC'}])
    ct.put_event_selectors(TrailName=trail_arn, EventSelectors=value['trail_selectors'])
    ct.start_logging(Name=trail_arn)
    receipt['completed'].append('sydney_cloudtrail_logging')
    receipt['trail_arn'] = trail_arn
    receipt['trail_logging'] = ct.get_trail_status(Name=trail_arn)['IsLogging']
    receipt['status'] = 'configuration_applied_delivery_not_yet_verified'
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True)
    parser.add_argument('--apply', action='store_true')
    parser.add_argument('--receipt', default='cloud-soc-sydney-run/logging-apply.json')
    args = parser.parse_args()
    receipt = {'completed': [], 'status': 'not_applied'}
    try:
        value = json.loads(Path(args.plan).read_text())
        if value != generate(value['account'], value['bucket'], value['alb_arn'], value['vpc']):
            raise ValueError('plan_does_not_match_generator')
        if not args.apply:
            print(json.dumps({'status': 'plan_valid', 'aws_contacted': False,
                              'bucket': value['bucket'], 'region': value['region']}))
            return 0
        import boto3
        target = Path(args.receipt)
        target.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        try:
            apply(value, boto3.Session(region_name=value['region']), receipt)
        finally:
            with os.fdopen(fd, 'w') as output:
                json.dump(receipt, output, indent=2)
        print(json.dumps(receipt))
        return 0
    except Exception as error:
        print(json.dumps({'status': 'incomplete', 'completed': receipt['completed'],
                          'error': str(error) if isinstance(error, ValueError) else type(error).__name__}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
