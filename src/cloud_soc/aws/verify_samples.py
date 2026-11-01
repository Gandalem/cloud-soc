"""Read existing CloudWatch samples through the AWS CLI; emit protected projections only.

No SDK installation, AWS mutations, production checkpoint or ES endpoint is used.
"""
import argparse
from datetime import datetime, timedelta, timezone
import json
import re
import subprocess
import time

from cloud_soc.aws.service_logs import project

SOURCES = (
    {'kind': 'route53_resolver', 'region': 'ap-northeast-3',
     'group': '/cloud-soc/aws/route53-resolver', 'resource': 'vpc-0e4bb99234215e866',
     'extra': ['--filter-pattern', '{ $.vpc_id = "vpc-0e4bb99234215e866" }']},
    {'kind': 'cloudfront', 'region': 'us-east-1',
     'group': '/cloud-soc/aws/cloudfront-access', 'resource': 'EGVZJI81RXNWQ',
     'extra': ['--log-stream-names', 'CloudFront_EGVZJI81RXNWQ']},
    {'kind': 'rds_error', 'region': 'ap-northeast-3',
     'group': '/aws/rds/instance/cloud-soc-rds-mysql/error', 'resource': 'cloud-soc-rds-mysql',
     'extra': ['--log-stream-names', 'cloud-soc-rds-mysql']},
)
GENERAL_SOURCE = {'kind': 'rds_general', 'region': 'ap-northeast-3',
                  'group': '/aws/rds/instance/cloud-soc-rds-mysql/general', 'resource': 'cloud-soc-rds-mysql',
                  'extra': ['--log-stream-names', 'cloud-soc-rds-mysql', '--filter-pattern', 'Query']}
FIREWALL_SOURCES = tuple(
    {'kind': 'network_firewall_' + kind, 'region': 'ap-northeast-3',
     'group': '/cloud-soc/aws/network-firewall-' + kind, 'resource': 'cloud-soc-network-firewall',
     'extra': ['--filter-pattern', '{ $.firewall_name = "cloud-soc-network-firewall" && '
               '$.event.event_type = "' + event_type + '" && $.event.src_ip = "10.250.10.156" && '
               '$.event.dest_port = 443' + (' && $.event.alert.signature_id = 1000001' if kind == 'alert' else '') + ' }']}
    for kind, event_type in (('alert', 'alert'), ('flow', 'netflow')))


class VerificationError(ValueError):
    """Fixed diagnostics only; never echo AWS stderr or original event bodies."""


def aws(*args):
    try:
        result = subprocess.run(['aws', *args, '--output', 'json', '--no-cli-pager',
                                 '--cli-connect-timeout', '5', '--cli-read-timeout', '20'],
                                capture_output=True, text=True, timeout=35, check=False)
    except (OSError, subprocess.TimeoutExpired):
        raise VerificationError('aws_cli_unavailable_or_timeout') from None
    if result.returncode:
        code = 'aws_read_failed'
        for native, fixed in (('AccessDenied', 'aws_access_denied'), ('NoCredentials', 'aws_credentials_missing'),
                              ('ResourceNotFound', 'aws_resource_missing'), ('ExpiredToken', 'aws_credentials_expired')):
            if native in result.stderr:
                code = fixed
                break
        raise VerificationError(code)
    try:
        return json.loads(result.stdout)
    except (ValueError, TypeError):
        raise VerificationError('invalid_aws_response') from None


def sample(source, *, account, organization, start, end, call=aws, sleep=time.sleep, max_pages=20):
    if source['kind'] == 'cloudfront':
        distribution = call('cloudfront', 'get-distribution', '--id', source['resource'])
        if distribution.get('Distribution', {}).get('ARN') != f"arn:aws:cloudfront::{account}:distribution/{source['resource']}":
            raise VerificationError('cloudfront_binding_mismatch')
    token, seen = None, set()
    for _ in range(max_pages):
        request = ['logs', 'filter-log-events', '--region', source['region'],
                   '--log-group-name', source['group'], '--start-time', str(start), '--end-time', str(end),
                   '--limit', '1', '--no-paginate', *source['extra']]
        if token:
            request += ['--next-token', token]
        page = call(*request)
        events = page.get('events')
        if not isinstance(events, list) or len(events) > 1:
            raise VerificationError('invalid_aws_page')
        if events:
            envelope = events[0]
            stamp = envelope.get('timestamp')
            if type(stamp) is not int or not start <= stamp <= end:
                raise VerificationError('event_outside_requested_window')
            try:
                index, identifier, document = project(envelope, account=account, organization=organization,
                    region=source['region'], group=source['group'], kind=source['kind'], resource_id=source['resource'])[0]
            except (ValueError, TypeError, IndexError):
                raise VerificationError('native_sample_parse_failed') from None
            return {'kind': source['kind'], 'status': 'verified', 'reference': {'index': index, 'id': identifier},
                    'document': document}
        token = page.get('nextToken')
        if token is None:
            return {'kind': source['kind'], 'status': 'no_sample_in_window'}
        if not isinstance(token, str) or not 0 < len(token) <= 8192 or token in seen:
            raise VerificationError('invalid_pagination')
        seen.add(token)
        sleep(0.25)
    raise VerificationError('sample_page_limit_reached')


def verify(*, account, call=aws, now=None, sleep=time.sleep, sources=SOURCES, window=None):
    now = now or datetime.now(timezone.utc)
    start, end = int((now - timedelta(hours=48)).timestamp() * 1000), int(now.timestamp() * 1000)
    if window is not None:
        if (not isinstance(window, (tuple, list)) or len(window) != 2
                or any(type(value) is not int for value in window)
                or not 0 <= window[0] < window[1] <= end or window[1] - window[0] > 172800000):
            raise VerificationError('invalid_sample_window')
        start, end = window
    identity = call('sts', 'get-caller-identity')
    if identity.get('Account') != account or not str(identity.get('Arn', '')).startswith('arn:aws:'):
        raise VerificationError('aws_account_mismatch')
    # This is a bounded read of already delivered samples, not a watermark poll.
    # Newly created RDS logs must not be hidden behind the collector's normal lag.
    report = {'schema': 'aws-real-samples-v1', 'account': account, 'organization': 'aws-dev-gyumin',
              'mode': 'manual_readonly_cloudshell_sample', 'verified_at': now.isoformat(),
              'window': {'start_ms': start, 'end_ms': end}, 'sources': []}
    for source in sources:
        try:
            result = sample(source, account=account, organization=report['organization'], start=start,
                            end=end, call=call, sleep=sleep)
        except VerificationError as error:
            result = {'kind': source['kind'], 'status': 'error', 'code': str(error)}
        except Exception:
            result = {'kind': source['kind'], 'status': 'error', 'code': 'sample_verification_failed'}
        report['sources'].append(result)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--account', required=True)
    parser.add_argument('--only', choices=[s['kind'] for s in (*SOURCES, GENERAL_SOURCE, *FIREWALL_SOURCES)]
                        + ['network_firewall'])
    args = parser.parse_args(argv)
    try:
        if not re.fullmatch(r'[0-9]{12}', args.account):
            raise VerificationError('invalid_account')
        sources = (FIREWALL_SOURCES if args.only == 'network_firewall' else
                   tuple(s for s in (*SOURCES, GENERAL_SOURCE, *FIREWALL_SOURCES) if s['kind'] == args.only)
                   if args.only else SOURCES)
        result = verify(account=args.account, sources=sources)
        print('AWS_REAL_SAMPLES_BEGIN')
        print(json.dumps(result, ensure_ascii=False, separators=(',', ':')))
        print('AWS_REAL_SAMPLES_END')
        return 1 if any(s['status'] == 'error' for s in result['sources']) else 0
    except VerificationError as error:
        print(json.dumps({'status': 'error', 'code': str(error)}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
