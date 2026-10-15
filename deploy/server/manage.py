"""Common central install/upgrade entry point. Only explicit apply changes a server."""
import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import sys
import time

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'src'))
from cloud_soc.deployment.contract import SERVICES
from cloud_soc.deployment.host import Docker, ResourceBudgetError, apply, before_build, containers, recover, service_running, snapshot, summary, worker_inventory
from cloud_soc.deployment.migrations import atomic_json
from cloud_soc.deployment.verify import portal


def ready(engine, name, project):
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            obj = engine.json(['inspect', project + '-' + name + '-1'])[0]
        except RuntimeError:
            time.sleep(2)
            continue
        if service_running(obj):
            return
        time.sleep(2)
    raise ValueError('Required service readiness deadline exceeded')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('action', choices=('plan', 'apply', 'install', 'recover', 'verify'))
    parser.add_argument('--workspace', type=Path, default=ROOT)
    parser.add_argument('--state', type=Path, default=ROOT / 'state/server')
    parser.add_argument('--image', default='cloud-soc-central-runtime:local')
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--build', action='store_true')
    parser.add_argument('--before-build', action='store_true', help='Resource-only non-applicable plan before image construction')
    parser.add_argument('--build-budget-mib', type=int, default=4096, help='Conservative upper bound for new image plus build scratch')
    parser.add_argument('--ingress-reserve-mib', type=int, default=1024, help='Bound for incoming ES/state logs during the upgrade')
    parser.add_argument('--backup-root', type=Path, help='Existing private directory on a verified separate filesystem')
    parser.add_argument('--startup-only', action='store_true', help='Structure only; never claims ingestion/detection acceptance')
    parser.add_argument('--portal-origin')
    parser.add_argument('--password-stdin', action='store_true', help='Read a JSON password object from stdin, never argv/environment')
    parser.add_argument('--probe', type=Path, help='Receipt from an explicit local SSH exercise')
    parser.add_argument('--wait-seconds', type=int, default=0)
    args = parser.parse_args()
    if os.name != 'posix' or os.geteuid() != 0:
        raise ValueError('Run on the approved Linux Docker host with sudo')
    if (args.state.is_symlink() or args.wait_seconds < 0 or args.wait_seconds > 3600
            or args.ingress_reserve_mib < 1024 or args.build_budget_mib < 1024
            or (args.before_build and args.action != 'plan')):
        raise ValueError('Invalid state path or verification deadline')
    engine = Docker();state = args.state.resolve()
    if args.action == 'recover':
        print(json.dumps(recover(engine, state)))
        return 0
    if args.action == 'plan':
        options = {'backup_root': args.backup_root, 'ingress_bytes': args.ingress_reserve_mib * 1024**2}
        p = (before_build(engine, args.workspace, state, build_bytes=args.build_budget_mib * 1024**2, **options)
             if args.before_build else snapshot(engine, args.workspace, state, args.image, **options))
        output = args.plan or state / 'runtime-plan.json'
        atomic_json(output, p)
        print(json.dumps(p if args.before_build else summary(p)))
        return int(not p['resources']['ok'])
    if args.action in ('apply', 'install'):
        if args.build:
            if args.action != 'install':
                raise ValueError('Build the upgrade candidate before reviewing its plan')
            budget = before_build(engine, args.workspace, state, build_bytes=args.build_budget_mib * 1024**2,
                backup_root=args.backup_root, ingress_bytes=args.ingress_reserve_mib * 1024**2)
            if not budget['resources']['ok']:
                print(json.dumps(budget));return 1
            engine.run(['build', '--pull=false', '-f', str(args.workspace / 'deploy/server/Dockerfile'), '-t', args.image,
                        str(args.workspace)], timeout=600)
        p = (snapshot(engine, args.workspace, state, args.image, backup_root=args.backup_root,
                      ingress_bytes=args.ingress_reserve_mib * 1024**2) if args.action == 'install'
             else json.loads(args.plan.read_text()) if args.plan else None)
        if not p or p.get('kind') == 'before_build_budget' or (args.action == 'install' and not p['fresh']):
            raise ValueError('Use a reviewed plan to upgrade an existing server')
        print(json.dumps(apply(engine, p, poll=ready)))
        return 0
    runtime = state / 'runtime';current = json.loads((runtime / 'current.json').read_text())
    objects = containers(engine, 'cloud-soc-central')
    from cloud_soc.deployment.contract import ALL_WORKERS
    if set(worker_inventory(engine, 'cloud-soc-central')) != set(ALL_WORKERS):
        raise ValueError('Missing or duplicate common worker')
    if any(n not in objects or not service_running(objects[n]) for n in SERVICES):
        raise ValueError('A required runtime service is missing')
    from cloud_soc.deployment.contract import APP_SERVICES
    if any(objects[n]['Image'] != current['image_id'] for n in APP_SERVICES):
        raise ValueError('Mixed application versions cannot pass verification')
    if args.startup_only:
        print(json.dumps({'runtime_ready': True, 'live_acceptance': 'not_verified', 'version': current['version']}))
        return 0
    password = None
    if args.portal_origin:
        password = json.load(sys.stdin)['password'] if args.password_stdin else getpass.getpass('Portal admin password: ')
    probe = json.loads(args.probe.read_text()) if args.probe else None
    deadline = time.monotonic() + args.wait_seconds
    while True:
        result = engine.json(['exec', '-i', 'cloud-soc-central-portal-1', 'python', '-m', 'cloud_soc.deployment.verify'],
                             input=json.dumps({'since': current['utc'], 'probe': probe}))
        if result['policy_sha256'] != current['policy_sha256']:
            raise ValueError('Live runtime policy differs from the applied version')
        if result['verified'] or time.monotonic() >= deadline:
            break
        time.sleep(min(10, max(0, deadline - time.monotonic())))
    if args.portal_origin:
        result['portal'] = portal(args.portal_origin, state / 'tls/ca.crt', password)
    else:
        result['verified'] = False;result['issues'].append('actual_portal_authentication_not_verified')
    result['checked_at'] = datetime.now(timezone.utc).isoformat()
    atomic_json(runtime / 'acceptance.json', result)
    print(json.dumps(result))
    return int(not result['verified'])


if __name__ == '__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        if isinstance(error, ResourceBudgetError):
            print(json.dumps({'resource_preflight_refused': True, 'resources': error.report}))
        raise SystemExit('Runtime operation stopped (' + type(error).__name__ + '); protected state retained; credentials omitted.') from None
