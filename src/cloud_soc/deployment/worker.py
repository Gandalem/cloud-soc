"""Execute only a prepared, policy-pinned worker from the common deployment."""
import argparse
import json
import os
from pathlib import Path
import sys

from cloud_soc.deployment.contract import AWS_RULE_IDS, CATALOG_WORKER, WORKERS, command, defaults, digest, options, policy, stamp, validate_rules


def argv(value, name, release_policy):
    if name not in (*WORKERS, 'detector-aws', CATALOG_WORKER) or value.get('policy_sha256') != digest(release_policy) or not value.get('prepared'):
        raise ValueError('Runtime migration not prepared for this release')
    validate_rules(release_policy)
    if name == CATALOG_WORKER:
        selected = sorted(release_policy['catalog_rules'])
        if value.get('catalog_rules') != selected:
            raise ValueError('Catalog worker rule inventory differs from release')
        floor = stamp(value['catalog_detection_start']).isoformat()
        config = defaults('detector-additional', floor, selected)
        config['--status-id'] = name
        return command('cloud_soc.detection', config)
    if name == 'detector-aws':
        if tuple(value.get('aws_rules', ())) != AWS_RULE_IDS:
            raise ValueError('AWS rule inventory differs from the release')
        floor = stamp(value['aws_detection_start']).isoformat()
        config = defaults('detector-additional', floor, AWS_RULE_IDS)
        config['--status-id'] = name
        return command('cloud_soc.detection', config)
    row = value['workers'][name]
    expected = 'cloud_soc.processing' if name.startswith('normalizer') else 'cloud_soc.detection'
    if row['module'] != expected:
        raise ValueError('Unexpected worker module')
    result = command(expected, row['options'])
    parsed = options(result, expected)
    if parsed['--state'] != '/data/' + row['state_file'] or parsed['--api-key-file'] != '/run/keys/worker.key':
        raise ValueError('Runtime state/key path does not match the common mount')
    selected = parsed.get('--additional-rules', parsed.get('--rules', 'AUTH-001')).split(',')
    if set(selected) - set(release_policy['verified_rules']) or '--isolated-all' in parsed:
        raise ValueError('Unverified production rules refused')
    if name == 'detector-priority' and (parsed.get('--status-id') != name or parsed.get('--early-auth')):
        raise ValueError('Priority worker cannot own primary telemetry/notices')
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--service', choices=(*WORKERS, 'detector-aws', CATALOG_WORKER), required=True)
    parser.add_argument('--contract', type=Path, default=Path('/run/runtime/contract.json'))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[3]
    result = argv(json.loads(args.contract.read_text()), args.service, policy(root))
    os.execv(sys.executable, [sys.executable, *result[1:]])


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('runtime_contract_invalid; worker not started; credentials omitted') from None
