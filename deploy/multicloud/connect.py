#!/usr/bin/env python3
"""Prepare additive ES grants and a standalone AWS Compose file; never start services."""
import argparse
import fcntl
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys


def docker_json(*args):
    result = subprocess.run(['docker', *args], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def save(path, data, mode=0o600):
    temp = path.with_name('.' + path.name + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def source_mount(container, target):
    matches = [m for m in container['Mounts'] if m['Destination'] == target and m['Type'] == 'bind']
    if len(matches) != 1:
        raise ValueError('expected_bind_mount_missing:' + target)
    path = Path(matches[0]['Source'])
    if not path.is_file():
        raise ValueError('expected_mount_file_missing:' + target)
    return path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--workspace', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--aws-env', type=Path, required=True)
    parser.add_argument('--source', default='aws-audit-oregon')
    parser.add_argument('--image', default='cloud-soc-multicloud:20261101')
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise ValueError('run_with_sudo')
    workspace, state, aws_env = args.workspace.resolve(), args.state.resolve(), args.aws_env.resolve()
    if not state.is_dir():
        raise ValueError('existing_central_state_directory_required')
    config = workspace / 'config/multicloud.json'
    values = json.loads(config.read_text())
    matches = [s for s in values['sources'] if s.get('id') == args.source and s.get('provider') == 'aws']
    if len(matches) != 1:
        raise ValueError('aws_source_id_not_found_in_config')
    scope = matches[0]
    import re
    if (not re.fullmatch(r'[0-9]{12}', str(scope.get('account', '')))
            or not re.fullmatch(r'[a-z]{2}(?:-[a-z]+)+-[0-9]+', str(scope.get('region', '')))):
        raise ValueError('valid_aws_account_and_region_required')
    if scope.get('profile'):
        raise ValueError('remove_profile_from_aws_source_for_environment_credentials')
    if not aws_env.is_file() or aws_env.stat().st_mode & 0o077:
        raise ValueError('private_aws_env_file_required_chmod_600')
    credentials = {}
    for line in aws_env.read_text().splitlines():
        if not line or line.startswith('#'):
            continue
        key, sep, value = line.partition('=')
        if not sep or key not in {'AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN', 'AWS_CREDENTIAL_EXPIRATION'} or not value:
            raise ValueError('invalid_aws_env_format_use_env-no-export')
        credentials[key] = value
    if not all(credentials.get(k) for k in ('AWS_ACCESS_KEY_ID', 'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN')):
        raise ValueError('aws_temporary_credential_triplet_required')
    portal = docker_json('inspect', 'cloud-soc-central-portal-1')[0]
    elastic = docker_json('inspect', 'cloud-soc-central-elasticsearch-1')[0]
    environment = dict(e.split('=', 1) for e in portal['Config']['Env'])
    if environment.get('SOC_PORTAL_READ_API_KEY_FILE'):
        raise ValueError('portal_uses_restricted_api_key_stop_before_changes_needs_reader_key_specific_setup')
    if not environment.get('SOC_MONITOR_PASSWORD_FILE'):
        raise ValueError('native_monitor_authentication_not_configured')
    if environment.get('SOC_INTERNAL_ES_URL') != 'https://elasticsearch:9200':
        raise ValueError('unexpected_internal_elasticsearch_origin')
    ca = source_mount(portal, environment['SOC_CA_FILE'])
    password = source_mount(elastic, '/run/secrets/elastic_password')
    if ca.resolve() != (state / 'tls/ca.crt').resolve() or password.resolve() != (state / 'secrets/elastic_password').resolve():
        raise ValueError('provided_state_does_not_match_running_container_mounts')
    networks = set(portal['NetworkSettings']['Networks']) & set(elastic['NetworkSettings']['Networks'])
    if len(networks) != 1:
        raise ValueError('ambiguous_or_missing_shared_central_network')
    network = networks.pop()
    image = docker_json('image', 'inspect', args.image)[0]['Id']
    out = state / 'multicloud'
    if out.is_symlink():
        raise ValueError('output_directory_must_not_be_symlink')
    out.mkdir(mode=0o700, exist_ok=True)
    if out.stat().st_uid != 0 or out.stat().st_mode & 0o077:
        raise ValueError('multicloud_output_must_be_root_owned_mode_700')
    with (out / 'setup.lock').open('a') as lock:
        os.chmod(out / 'setup.lock', 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        script = Path(__file__).resolve().with_name('configure_es.py')
        command = ['docker', 'run', '--rm', '--network', network, '--user', '0:0', '--read-only',
            '--cap-drop', 'ALL', '--cap-add', 'CHOWN', '--cap-add', 'DAC_OVERRIDE', '--security-opt', 'no-new-privileges:true', '--tmpfs', '/tmp',
            '--mount', f'type=bind,src={ca},dst=/run/setup/ca.crt,readonly',
            '--mount', f'type=bind,src={password},dst=/run/setup/elastic-password,readonly',
            '--mount', f'type=bind,src={script},dst=/setup.py,readonly',
            '--mount', f'type=bind,src={out},dst=/output',
            '--entrypoint', 'python', image, '/setup.py']
        subprocess.run(command, check=True)
        ca_copy = out / 'ca.crt'
        if ca_copy.exists() and ca_copy.read_bytes() != ca.read_bytes():
            raise ValueError('saved_ca_differs_manual_certificate_update_required')
        if not ca_copy.exists():
            shutil.copyfile(ca, ca_copy)
        os.chmod(ca_copy, 0o644)
        collector_state = out / 'aws-state'
        if collector_state.is_symlink():
            raise ValueError('collector_state_must_not_be_symlink')
        collector_state.mkdir(mode=0o700, exist_ok=True)
        os.chown(collector_state, 10001, 10001)
        os.chmod(collector_state, 0o700)
        # Public source config only; cloud credentials are never copied into Compose.
        config_copy = out / 'aws-config.json'
        save(config_copy, json.dumps({'sources': [scope]}, indent=2), 0o644)
        composition = {'name': 'cloud-soc-multicloud', 'services': {'aws': {
            'image': image, 'restart': 'unless-stopped', 'init': True, 'user': '10001:10001',
            'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'tmpfs': ['/tmp'],
            'env_file': [str(aws_env)],
            'environment': {'ELASTICSEARCH_URL': 'https://elasticsearch:9200',
                'ELASTICSEARCH_CA_FILE': '/run/secrets/es-ca.crt',
                'ELASTICSEARCH_API_KEY_FILE': '/run/secrets/es-writer',
                'AWS_DEFAULT_REGION': scope['region'], 'AWS_EC2_METADATA_DISABLED': 'true'},
            'command': ['collect', '--config', '/app/config.json', '--source', args.source, '--state-dir', '/state'],
            'volumes': [
                {'type': 'bind', 'source': str(config_copy), 'target': '/app/config.json', 'read_only': True},
                {'type': 'bind', 'source': str(ca_copy), 'target': '/run/secrets/es-ca.crt', 'read_only': True},
                {'type': 'bind', 'source': str(out / 'writer-api-key'), 'target': '/run/secrets/es-writer', 'read_only': True},
                {'type': 'bind', 'source': str(collector_state), 'target': '/state'}],
            'networks': ['central'],
            'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}},
            'networks': {'central': {'external': True, 'name': network}}}
        compose_path = out / 'aws.compose.json'
        save(compose_path, json.dumps(composition, indent=2))
        print(json.dumps({'prepared': True, 'compose': str(compose_path), 'source': args.source,
            'region': scope['region'], 'collector_started': False, 'central_services_restarted': False}))


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as exc:
        print(json.dumps({'prepared': False, 'error_type': 'DockerCommandFailed', 'exit_code': exc.returncode}))
        sys.exit(1)
    except Exception as exc:
        print(json.dumps({'prepared': False, 'error_type': type(exc).__name__,
                          'reason': str(exc) if isinstance(exc, ValueError) else 'local_setup_failed'}))
        sys.exit(1)
