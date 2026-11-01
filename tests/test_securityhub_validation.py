from datetime import datetime, timezone
import json

import botocore.session
from botocore.validate import validate_parameters
import pytest

from cloud_soc.aws.securityhub_validation import ACCOUNT, REGION, FINDING_ID, PRODUCT_ARN, finding, preflight, apply
from cloud_soc.aws.verify_samples import VerificationError

NOW = datetime.now(timezone.utc)


class FakeAWS:
    def __init__(self):
        self.calls, self.payloads = [], []
        self.targets = [{'Arn': f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:/cloud-soc/aws/securityhub-findings'}]
        self.existing, self.match, self.deliver = [], True, True

    def __call__(self, *args):
        self.calls.append(args)
        action = args[1]
        if action == 'get-caller-identity': return {'Account': ACCOUNT, 'Arn': f'arn:aws:iam::{ACCOUNT}:user/test'}
        if action == 'describe-rule': return {'State': 'ENABLED', 'EventPattern': '{}'}
        if action == 'list-targets-by-rule': return {'Targets': self.targets}
        if action == 'test-event-pattern': return {'Result': self.match}
        if action == 'get-findings': return {'Findings': self.existing}
        if action == 'batch-import-findings':
            self.payloads.extend(json.loads(args[args.index('--findings') + 1]))
            return {'FailedCount': 0, 'SuccessCount': 1}
        if action == 'filter-log-events':
            if not self.deliver: return {'events': []}
            event = {'source': 'aws.securityhub', 'detail-type': 'Security Hub Findings - Imported',
                     'account': ACCOUNT, 'region': REGION, 'time': NOW.isoformat(), 'detail': {'findings': [self.payloads[0]]}}
            return {'events': [{'eventId': 'test-event', 'logStreamName': 'test-stream',
                                'timestamp': int(NOW.timestamp()*1000), 'ingestionTime': int(NOW.timestamp()*1000),
                                'message': json.dumps(event)}]}
        raise AssertionError('Unexpected operation')


def test_plan_uses_valid_asff_and_only_an_information_test_of_our_rds():
    payload = finding(NOW)
    model = botocore.session.get_session().get_service_model('securityhub').operation_model('BatchImportFindings')
    validate_parameters({'Findings': [payload]}, model.input_shape)
    assert payload['Id'] == FINDING_ID and payload['ProductArn'] == PRODUCT_ARN
    assert payload['Severity']['Label'] == 'INFORMATIONAL' and '[TEST ONLY]' in payload['Title']
    assert payload['ProductFields']['cloud_soc_validation'] == 'true'


def test_delivery_test_creates_and_archives_only_the_same_sample_without_rule_or_db_change():
    aws = FakeAWS()
    report = apply(call=aws, sleep=lambda _: None, now=NOW, attempts=1)
    assert report['created'] and report['archived'] and report['sources'][0]['status'] == 'verified'
    assert [p['RecordState'] for p in aws.payloads] == ['ACTIVE', 'ARCHIVED']
    assert {p['Id'] for p in aws.payloads} == {FINDING_ID}
    assert not any(c[1] in ('put-rule', 'put-targets', 'reboot-db-instance', 'generate-sample-findings') for c in aws.calls)


@pytest.mark.parametrize('change', ['target', 'existing', 'pattern'])
def test_changed_preconditions_stop_before_finding_creation(change):
    aws = FakeAWS()
    if change == 'target': aws.targets.append({'Arn': 'another-target'})
    if change == 'existing': aws.existing = [{'Id': FINDING_ID}]
    if change == 'pattern': aws.match = False
    with pytest.raises(VerificationError): preflight(finding(NOW), call=aws)
    assert not aws.payloads


def test_no_delivery_is_not_success_and_the_created_finding_is_still_archived():
    aws = FakeAWS()
    aws.deliver = False
    report = apply(call=aws, sleep=lambda _: None, now=NOW, attempts=1)
    assert report['archived'] and report['sources'][0]['status'] != 'verified'
