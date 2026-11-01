#!/usr/bin/env python3
"""Explicit collector lifecycle, isolated from central workers and their checkpoints."""
import argparse
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

PROVIDERS = {'aws': ('aws.compose.json', 'cloud-soc-multicloud'),
             'naver': ('naver.compose.json', 'cloud-soc-naver')}


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def safe_file(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError('regular_file_required:' + str(path))
    return path


def save(path, value):
    temp = path.with_name('.' + path.name + '.next')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(value, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def deployment(folder, provider):
    filename, project = PROVIDERS[provider]
    path = safe_file(folder / filename)
    definition = json.loads(path.read_text())
    if definition.get('name') != project or set(definition.get('services', {})) != {provider}:
        raise ValueError('collector_compose_project_or_service_mismatch')
    row = definition['services'][provider]
    if not row.get('image', '').startswith('sha256:'):
        raise ValueError('collector_image_must_be_pinned_to_local_image_id')
    if row.get('privileged') or row.get('ports') or row.get('network_mode') == 'host':
        raise ValueError('unexpected_collector_exposure')
    if row.get('user') != '10001:10001' or row.get('read_only') is not True:
        raise ValueError('collector_privilege_boundary_changed')
    # Persist identities and paths, never credential values or the Docker Env array.
    config = next(v['source'] for v in row['volumes'] if v.get('target') == '/app/config.json')
    state = next(v['source'] for v in row['volumes'] if v.get('target') == '/state')
    if not Path(config).resolve().is_relative_to(folder) or not Path(state).resolve().is_relative_to(folder):
        raise ValueError('collector_configuration_or_checkpoint_outside_feature_state')
    return {'compose': str(path), 'compose_sha256': digest(path), 'image_id': row['image'],
        'project': project, 'service': provider, 'config': config, 'config_sha256': digest(safe_file(Path(config))),
        'checkpoint_directory': state, 'credential_files': list(row.get('env_file', [])),
        'networks': definition.get('networks', {}),
        'script_sha256': digest(Path(__file__).resolve())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['prepare', 'adopt', 'start', 'stop', 'recreate', 'status', 'backup-plan'])
    parser.add_argument('--provider', choices=PROVIDERS, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--workspace', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--env', type=Path)
    parser.add_argument('--source')
    parser.add_argument('--image', default='cloud-soc-multicloud:20261101')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('run_with_sudo')
    state, workspace = args.state.resolve(), args.workspace.resolve()
    if not state.is_dir():
        raise ValueError('existing_central_state_required')
    if args.action == 'prepare':
        if args.env is None:
            raise ValueError('explicit_private_env_path_required')
        if args.provider == 'aws':
            command = [sys.executable, str(workspace/'deploy/multicloud/connect.py'),
                '--workspace', str(workspace), '--state', str(state), '--aws-env', str(args.env.resolve()),
                '--source', args.source or 'aws-audit-oregon', '--image', args.image]
        else:
            command = [sys.executable, str(workspace/'deploy/multicloud/connect_naver.py'), 'prepare',
                '--workspace', str(workspace), '--state', str(state), '--env', str(args.env.resolve()),
                '--source', args.source or 'naver-audit', '--image', args.image]
        subprocess.run(command, check=True)
    folder = state / 'multicloud'
    if folder.is_symlink() or not folder.is_dir() or folder.stat().st_uid != 0 or folder.stat().st_mode & 0o077:
        raise ValueError('root_owned_private_feature_directory_required')
    with (folder/'lifecycle.lock').open('a') as lock:
        os.chmod(folder/'lifecycle.lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        registry = folder / 'collectors.json'
        if registry.is_symlink():
            raise ValueError('unsafe_collector_registry')
        receipt = json.loads(registry.read_text()) if registry.exists() else {'version': 1, 'collectors': {}}
        if receipt.get('version') != 1:
            raise ValueError('unsupported_collector_registry_version')
        current = deployment(folder, args.provider)
        if args.action in ('prepare', 'adopt'):
            # adopt records existing files without changing images, config, keys, or checkpoints.
            receipt['collectors'][args.provider] = current
            save(registry, receipt)
            print(json.dumps({'registered': True, 'provider': args.provider,
                'action': args.action, 'collector_started': False, 'central_services_changed': False}))
            return
        if receipt['collectors'].get(args.provider) != current:
            raise ValueError('collector_changed_use_explicit_prepare_or_adopt')
        command = ['docker', 'compose', '-f', current['compose']]
        if args.action in ('start', 'stop', 'recreate'):
            options = ['stop', args.provider] if args.action == 'stop' else ['up', '-d']
            if args.action == 'recreate':
                options.append('--force-recreate')
            if args.action != 'stop':
                options.append(args.provider)
            subprocess.run([*command, *options], check=True)
        elif args.action == 'status':
            result = subprocess.run([*command, 'ps', '--all', '--format', 'json'], check=True,
                                    capture_output=True, text=True)
            print(result.stdout)
        else:
            paths = [registry, Path(current['compose']), Path(current['config']),
                folder/'ca.crt', folder/'writer-api-key', folder/'writer.json',
                *map(Path, current['credential_files'])]
            plan = {'version': 1, 'created_at': datetime.now(timezone.utc).isoformat(),
                'provider': args.provider, 'files_to_encrypt': list(map(str, paths)),
                'checkpoint_directory': current['checkpoint_directory'],
                'checkpoint_backup_method': 'SQLite online backup API or stopped collector; preserve WAL coherency',
                'elasticsearch_indices': ['soc-multicloud-*'], 'snapshot_required': True,
                'backup_executed': False, 'central_workers_included': False}
            target = folder / (args.provider + '-backup-plan.json')
            save(target, plan)
            print(json.dumps({'backup_plan': str(target), 'backup_executed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print(json.dumps({'success': False, 'error_type': type(exc).__name__,
            'reason': str(exc) if isinstance(exc, ValueError) else 'collector_operation_failed'}))
        sys.exit(1)
