"""Generated grants are service-only, account/region/source bounded; no AWS I/O."""
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sydney_delivery_plan', ROOT / 'deploy/aws/sydney/delivery_plan.py')
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
ACCOUNT = '123456789012'
ALB = f'arn:aws:elasticloadbalancing:ap-southeast-2:{ACCOUNT}:loadbalancer/app/test/0123456789abcdef'


def test_policies_grant_only_scoped_log_services_and_no_identity_permissions():
    value = module.plan(ACCOUNT, 'test-sydney-private-archive', ALB, 'vpc-0123456789abcdef0')
    assert value['public_access'] is False and value['iam_identity_grants'] == []
    allows = [s for s in value['bucket_policy']['Statement'] if s['Effect'] == 'Allow']
    assert {s['Principal']['Service'] for s in allows} == {
        'cloudtrail.amazonaws.com', 'delivery.logs.amazonaws.com', 'logdelivery.elasticloadbalancing.amazonaws.com'}
    assert {s['Action'] for s in allows} == {'s3:GetBucketAcl', 's3:PutObject'}
    assert all(s['Condition'] for s in allows)
    assert all(ACCOUNT in s['Resource'] for s in allows if s['Action'] == 's3:PutObject')
    statement = value['queue_policy']['Statement'][0]
    assert statement['Principal'] == {'Service': 's3.amazonaws.com'}
    assert statement['Action'] == 'sqs:SendMessage'
    assert statement['Condition']['StringEquals']['aws:SourceAccount'] == ACCOUNT
    assert statement['Condition']['ArnEquals']['aws:SourceArn'] == 'arn:aws:s3:::test-sydney-private-archive'


def test_sydney_trail_and_notifications_do_not_select_data_or_digest_events():
    value = module.plan(ACCOUNT, 'test-sydney-private-archive', ALB, 'vpc-0123456789abcdef0')
    assert value['trail']['IsMultiRegionTrail'] is False
    assert value['trail']['IncludeGlobalServiceEvents'] is False
    assert value['trail']['EnableLogFileValidation'] is True
    assert value['trail_selectors'][0]['DataResources'] == []
    prefixes = [c['Filter']['Key']['FilterRules'][0]['Value'] for c in value['notifications']['QueueConfigurations']]
    assert prefixes == [f'cloudtrail/AWSLogs/{ACCOUNT}/CloudTrail/ap-southeast-2/', 'vpc/shared/', 'alb/shared/']
    assert not any(f'cloudtrail/AWSLogs/{ACCOUNT}/CloudTrail-Digest/'.startswith(p) for p in prefixes)
    assert value['flow']['ResourceType'] == 'VPC'
    assert value['flow']['MaxAggregationInterval'] == 600


@pytest.mark.parametrize('account,alb', [('999999999999', ALB), (ACCOUNT, ALB.replace('ap-southeast-2', 'us-east-1'))])
def test_wrong_account_or_region_alb_is_rejected(account, alb):
    with pytest.raises(ValueError):
        module.plan(account, 'test-sydney-private-archive', alb, 'vpc-0123456789abcdef0')
