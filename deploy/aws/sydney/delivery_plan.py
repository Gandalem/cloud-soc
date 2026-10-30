"""Generate scoped AWS service-delivery policies; does not contact AWS."""
import argparse
import json
from pathlib import Path
import re

REGION = 'ap-southeast-2'


def plan(account, bucket, alb_arn, vpc):
    if not re.fullmatch(r'\d{12}', account) or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket):
        raise ValueError('Invalid account or bucket')
    if not alb_arn.startswith(f'arn:aws:elasticloadbalancing:{REGION}:{account}:loadbalancer/app/'):
        raise ValueError('ALB must belong to the specified Sydney account')
    if not re.fullmatch(r'vpc-[a-f0-9]{8,17}', vpc):
        raise ValueError('Invalid VPC')
    bucket_arn = 'arn:aws:s3:::' + bucket
    trail_arn = f'arn:aws:cloudtrail:{REGION}:{account}:trail/cloud-soc-sydney'
    queue_arn = f'arn:aws:sqs:{REGION}:{account}:cloud-soc-sydney-ingest'
    statements = [{'Sid': 'DenyInsecureTransport', 'Effect': 'Deny', 'Principal': '*',
                   'Action': 's3:*', 'Resource': [bucket_arn, bucket_arn + '/*'],
                   'Condition': {'Bool': {'aws:SecureTransport': 'false', 'aws:PrincipalIsAWSService': 'false'}}}]
    def allow(sid, principal, action, resource, condition):
        statements.append({'Sid': sid, 'Effect': 'Allow', 'Principal': {'Service': principal},
                           'Action': action, 'Resource': resource, 'Condition': condition})
    ct = {'StringEquals': {'aws:SourceArn': trail_arn}}
    allow('CloudTrailAcl', 'cloudtrail.amazonaws.com', 's3:GetBucketAcl', bucket_arn, ct)
    allow('CloudTrailWrite', 'cloudtrail.amazonaws.com', 's3:PutObject',
          bucket_arn + f'/cloudtrail/AWSLogs/{account}/*', {'StringEquals': {
              'aws:SourceArn': trail_arn, 's3:x-amz-acl': 'bucket-owner-full-control'}})
    flow = {'StringEquals': {'aws:SourceAccount': account},
            'ArnLike': {'aws:SourceArn': f'arn:aws:logs:{REGION}:{account}:*'}}
    allow('FlowAcl', 'delivery.logs.amazonaws.com', 's3:GetBucketAcl', bucket_arn, flow)
    allow('FlowWrite', 'delivery.logs.amazonaws.com', 's3:PutObject',
          bucket_arn + f'/vpc/shared/AWSLogs/{account}/*', {
              'StringEquals': {'aws:SourceAccount': account, 's3:x-amz-acl': 'bucket-owner-full-control'},
              'ArnLike': flow['ArnLike']})
    allow('AlbWrite', 'logdelivery.elasticloadbalancing.amazonaws.com', 's3:PutObject',
          bucket_arn + f'/alb/shared/AWSLogs/{account}/*', {'ArnLike': {'aws:SourceArn': alb_arn}})
    queue_policy = {'Version': '2012-10-17', 'Statement': [{
        'Sid': 'OnlyThisArchiveBucket', 'Effect': 'Allow', 'Principal': {'Service': 's3.amazonaws.com'},
        'Action': 'sqs:SendMessage', 'Resource': queue_arn, 'Condition': {
            'StringEquals': {'aws:SourceAccount': account}, 'ArnEquals': {'aws:SourceArn': bucket_arn}}}]}
    prefixes = [f'cloudtrail/AWSLogs/{account}/CloudTrail/{REGION}/', 'vpc/shared/', 'alb/shared/']
    notifications = {'QueueConfigurations': [{
        'Id': 'cloud-soc-' + str(i), 'QueueArn': queue_arn, 'Events': ['s3:ObjectCreated:*'],
        'Filter': {'Key': {'FilterRules': [{'Name': 'prefix', 'Value': prefix}]}}}
        for i, prefix in enumerate(prefixes)]}
    return {'account': account, 'region': REGION, 'bucket': bucket, 'vpc': vpc, 'alb_arn': alb_arn,
            'bucket_policy': {'Version': '2012-10-17', 'Statement': statements},
            'queue_policy': queue_policy, 'notifications': notifications,
            'trail': {'Name': 'cloud-soc-sydney', 'S3BucketName': bucket, 'S3KeyPrefix': 'cloudtrail',
                      'IncludeGlobalServiceEvents': False, 'IsMultiRegionTrail': False,
                      'EnableLogFileValidation': True, 'IsOrganizationTrail': False},
            'trail_selectors': [{'ReadWriteType': 'All', 'IncludeManagementEvents': True,
                                 'DataResources': [], 'ExcludeManagementEventSources': []}],
            'flow': {'ResourceIds': [vpc], 'ResourceType': 'VPC', 'TrafficType': 'ALL',
                     'LogDestinationType': 's3', 'LogDestination': bucket_arn + '/vpc/shared/',
                     'MaxAggregationInterval': 600,
                     'DestinationOptions': {'FileFormat': 'plain-text', 'HiveCompatiblePartitions': False,
                                            'PerHourPartition': False}},
            'alb_attributes': [{'Key': 'access_logs.s3.enabled', 'Value': 'true'},
                               {'Key': 'access_logs.s3.bucket', 'Value': bucket},
                               {'Key': 'access_logs.s3.prefix', 'Value': 'alb/shared'}],
            'iam_identity_grants': [], 'public_access': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--bucket', required=True)
    parser.add_argument('--alb-arn', required=True)
    parser.add_argument('--vpc', required=True)
    parser.add_argument('--output', required=True)
    args = parser.parse_args()
    value = plan(args.account, args.bucket, args.alb_arn, args.vpc)
    with Path(args.output).open('x', encoding='utf-8') as output:
        json.dump(value, output, indent=2)


if __name__ == '__main__':
    main()
