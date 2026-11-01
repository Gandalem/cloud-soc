"""Explicit one-finding delivery check; default is an offline plan, never mutation."""
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
import time

from cloud_soc.aws.verify_samples import aws, sample, VerificationError

ACCOUNT = '897722691159'
REGION = 'ap-northeast-3'
FINDING_ID = 'cloud-soc-validation/20261101-gyumin-rds-delivery-01'
PRODUCT_ARN = f'arn:aws:securityhub:{REGION}:{ACCOUNT}:product/{ACCOUNT}/default'
RESOURCE_ARN = f'arn:aws:rds:{REGION}:{ACCOUNT}:db:cloud-soc-rds-mysql'
LOG_GROUP = '/cloud-soc/aws/securityhub-findings'
RULE = 'cloud-soc-securityhub-findings'


def finding(now):
    stamp = now.isoformat().replace('+00:00', 'Z')
    return {'SchemaVersion': '2018-10-08', 'Id': FINDING_ID, 'ProductArn': PRODUCT_ARN,
            'GeneratorId': 'cloud-soc-delivery-validation', 'AwsAccountId': ACCOUNT, 'Region': REGION,
            'Types': ['Software and Configuration Checks/Industry and Regulatory Standards'],
            'CreatedAt': stamp, 'UpdatedAt': stamp, 'Severity': {'Label': 'INFORMATIONAL'},
            'Title': '[TEST ONLY] Cloud SOC delivery verification',
            'Description': 'Intentional delivery validation sample. This is not a security incident or a database change.',
            'Resources': [{'Type': 'AwsRdsDbInstance', 'Id': RESOURCE_ARN, 'Partition': 'aws', 'Region': REGION}],
            'RecordState': 'ACTIVE', 'Workflow': {'Status': 'NEW'},
            'ProductFields': {'cloud_soc_validation': 'true', 'cloud_soc_validation_id': FINDING_ID}}


def preflight(payload, *, call=aws):
    identity = call('sts', 'get-caller-identity', '--region', REGION)
    if identity.get('Account') != ACCOUNT or not str(identity.get('Arn', '')).startswith('arn:aws:'):
        raise VerificationError('aws_account_mismatch')
    rule = call('events', 'describe-rule', '--region', REGION, '--name', RULE, '--event-bus-name', 'default')
    if rule.get('State') != 'ENABLED':
        raise VerificationError('rule_not_enabled')
    targets = call('events', 'list-targets-by-rule', '--region', REGION, '--rule', RULE, '--event-bus-name', 'default').get('Targets')
    expected = f'arn:aws:logs:{REGION}:{ACCOUNT}:log-group:{LOG_GROUP}'
    if not isinstance(targets, list) or len(targets) != 1 or targets[0].get('Arn') != expected:
        raise VerificationError('target_scope_changed')
    if any(key in targets[0] for key in ('Input', 'InputPath', 'InputTransformer')):
        raise VerificationError('target_payload_transformation_requires_review')
    event = {'version': '0', 'id': '00000000-0000-4000-8000-000000000001', 'source': 'aws.securityhub',
             'detail-type': 'Security Hub Findings - Imported', 'account': ACCOUNT, 'region': REGION,
             'time': payload['UpdatedAt'], 'resources': [], 'detail': {'findings': [payload]}}
    tested = call('events', 'test-event-pattern', '--region', REGION,
                  '--event-pattern', rule['EventPattern'], '--event', json.dumps(event))
    if tested.get('Result') is not True:
        raise VerificationError('current_rule_does_not_match_sample')
    filters = {'Id': [{'Value': FINDING_ID, 'Comparison': 'EQUALS'}],
               'ProductArn': [{'Value': PRODUCT_ARN, 'Comparison': 'EQUALS'}]}
    existing = call('securityhub', 'get-findings', '--region', REGION, '--filters', json.dumps(filters), '--max-results', '1', '--no-paginate')
    if existing.get('Findings'):
        raise VerificationError('validation_finding_already_exists_do_not_recreate')
    return {'account_verified': True, 'single_log_target_verified': True, 'current_pattern_matches': True,
            'finding_id': FINDING_ID, 'resource_arn': RESOURCE_ARN, 'severity': 'INFORMATIONAL',
            'rule_changes': False, 'database_changes': False}


def apply(*, call=aws, sleep=time.sleep, now=None, attempts=16):
    now = now or datetime.now(timezone.utc)
    payload = finding(now)
    checked = preflight(payload, call=call)
    report = {'schema': 'aws-real-samples-v1', 'account': ACCOUNT, 'organization': 'aws-dev-gyumin',
              'mode': 'manual_readonly_cloudshell_sample', 'verified_at': now.isoformat(),
              'finding_origin': 'intentional_informational_delivery_test', 'preflight': checked,
              'finding_id': FINDING_ID, 'created': False, 'archived': False, 'sources': []}
    created = call('securityhub', 'batch-import-findings', '--region', REGION, '--findings', json.dumps([payload]))
    if created.get('FailedCount') != 0 or created.get('SuccessCount') != 1:
        raise VerificationError('validation_finding_creation_failed')
    report['created'] = True
    start = int((now - timedelta(minutes=2)).timestamp()*1000)
    source = {'kind': 'securityhub', 'region': REGION, 'group': LOG_GROUP, 'resource': 'securityhub-cspm',
              'extra': ['--filter-pattern', '{ $.detail.findings[0].Id = ' + json.dumps(FINDING_ID) + ' }']}
    try:
        for attempt in range(attempts):
            current = datetime.now(timezone.utc)
            result = sample(source, account=ACCOUNT, organization=report['organization'],
                            start=start, end=int(current.timestamp()*1000), call=call, sleep=sleep, max_pages=5)
            if result['status'] == 'verified':
                report['sources'] = [result]
                break
            if attempt + 1 < attempts:
                sleep(5)
        if not report['sources']:
            report['sources'] = [{'kind': 'securityhub', 'status': 'delivery_not_observed_in_bounded_wait'}]
    except Exception as error:
        code = str(error) if isinstance(error, VerificationError) else 'delivery_verification_failed'
        report['sources'] = [{'kind': 'securityhub', 'status': 'error', 'code': code}]
    finally:
        # Only the one payload this invocation successfully created is archived.
        archived = deepcopy(payload)
        archived.update(RecordState='ARCHIVED', UpdatedAt=datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'))
        try:
            result = call('securityhub', 'batch-import-findings', '--region', REGION, '--findings', json.dumps([archived]))
            report['archived'] = result.get('FailedCount') == 0 and result.get('SuccessCount') == 1
        except Exception:
            report['archive_error'] = 'archive_failed_check_exact_validation_finding'
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    modes = parser.add_mutually_exclusive_group()
    modes.add_argument('--preflight', action='store_true')
    modes.add_argument('--apply', action='store_true')
    args = parser.parse_args(argv)
    try:
        if args.apply:
            report = apply()
            print('AWS_REAL_SAMPLES_BEGIN')
            print(json.dumps(report, ensure_ascii=False, separators=(',', ':')))
            print('AWS_REAL_SAMPLES_END')
            return 0 if report['archived'] and report['sources'][0]['status'] == 'verified' else 1
        payload = finding(datetime.now(timezone.utc))
        print(json.dumps(preflight(payload) if args.preflight else {'status': 'offline_plan', 'finding': payload,
                         'aws_contacted': False, 'apply_required': True}, ensure_ascii=False))
        return 0
    except VerificationError as error:
        print(json.dumps({'status': 'error', 'code': str(error), 'finding_id': FINDING_ID}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
