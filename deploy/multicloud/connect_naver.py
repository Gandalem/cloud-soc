#!/usr/bin/env python3
"""Save Naver credentials privately or prepare an isolated Naver Compose project."""
import argparse
from datetime import datetime, timedelta, timezone
import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import sys


def write_private(path, text, mode=0o600):
    temp = path.with_name('.' + path.name + '.tmp')
    fd = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
    try:
        with os.fdopen(fd, 'w') as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def inspect(*args):
    result = subprocess.run(['docker', *args], check=True, capture_output=True, text=True)
    return json.loads(result.stdout)


def credentials(args):
    if os.geteuid() == 0:
        raise ValueError('run_credentials_without_sudo')
    if not sys.stdin.isatty():
        raise ValueError('interactive_terminal_required')
    path = args.env.resolve()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if path.parent.stat().st_uid != os.getuid() or path.parent.stat().st_mode & 0o077:
        raise ValueError('credential_directory_must_be_user_owned_and_mode_700')
    if path.exists() or path.is_symlink():
        raise ValueError('existing_env_preserved_choose_a_new_env_path')
    access = getpass.getpass('Naver Access Key ID (hidden): ').strip()
    secret = getpass.getpass('Naver Secret Key (hidden): ').strip()
    if not access or not secret or any(c.isspace() for c in access + secret):
        raise ValueError('nonempty_single_line_keys_required')
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(fd, 'w') as stream:
        stream.write('SOC_NAVER_ACCESS_KEY=' + access + '\nSOC_NAVER_SECRET_KEY=' + secret + '\n')
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({'credentials_saved': True, 'path': str(path), 'keys_printed': False}))


def prepare(args):
    if os.geteuid() != 0:
        raise ValueError('run_prepare_with_sudo')
    workspace, env = args.workspace.resolve(), args.env.resolve()
    portal = inspect('inspect', 'cloud-soc-central-portal-1')[0]
    actual_ca = [m for m in portal['Mounts'] if m['Destination'] == '/run/certs/ca.crt']
    if len(actual_ca) != 1:
        raise ValueError('one_central_ca_mount_required')
    state = args.state.resolve() if args.state else Path(actual_ca[0]['Source']).resolve().parents[1]
    if not state.is_dir():
        raise ValueError('existing_central_state_required')
    if not env.is_file() or env.stat().st_mode & 0o077:
        raise ValueError('private_naver_env_required_mode_600')
    values = {}
    for line in env.read_text().splitlines():
        key, sep, value = line.partition('=')
        if not sep or not value or key not in {'SOC_NAVER_ACCESS_KEY', 'SOC_NAVER_SECRET_KEY'} or key in values:
            raise ValueError('invalid_naver_env')
        values[key] = value
    if set(values) != {'SOC_NAVER_ACCESS_KEY', 'SOC_NAVER_SECRET_KEY'}:
        raise ValueError('both_naver_keys_required')
    config = json.loads((workspace / 'config/multicloud.json').read_text())
    sources = [s for s in config['sources'] if s.get('provider') == 'naver' and s.get('id') == args.source]
    if len(sources) != 1:
        raise ValueError('exactly_one_naver_source_required')
    source = sources[0]
    if not re.fullmatch(r'[0-9]{1,20}', str(source.get('account', ''))):
        raise ValueError('naver_account_must_be_parent_member_number')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', source.get('organization', '')):
        raise ValueError('valid_organization_required')
    if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,99}', args.source):
        raise ValueError('valid_source_id_required')
    if source.get('access_key_env') != 'SOC_NAVER_ACCESS_KEY' or source.get('secret_key_env') != 'SOC_NAVER_SECRET_KEY':
        raise ValueError('use_expected_naver_credential_environment_names')
    floor = datetime.fromisoformat(source['start'].replace('Z', '+00:00'))
    if floor.utcoffset() is None or floor < datetime.now(timezone.utc) - timedelta(days=30):
        raise ValueError('explicit_timezone_and_start_within_30_days_required')
    out = state / 'multicloud'
    if not out.is_dir() or out.is_symlink() or out.stat().st_uid != 0 or out.stat().st_mode & 0o077:
        raise ValueError('existing_root_owned_multicloud_state_required_mode_700')
    for name in ('writer-api-key', 'writer.json', 'ca.crt'):
        if not (out / name).is_file() or (out / name).is_symlink():
            raise ValueError('existing_multicloud_writer_and_ca_required')
    if json.loads((out / 'writer.json').read_text())['expiration'] <= int(datetime.now(timezone.utc).timestamp()*1000):
        raise ValueError('existing_es_writer_expired_explicit_renewal_required')
    es = inspect('inspect', 'cloud-soc-central-elasticsearch-1')[0]
    networks = set(portal['NetworkSettings']['Networks']) & set(es['NetworkSettings']['Networks'])
    if len(networks) != 1:
        raise ValueError('one_shared_central_network_required')
    ca_mounts = [m for m in portal['Mounts'] if m['Destination'] == '/run/certs/ca.crt']
    if len(ca_mounts) != 1 or Path(ca_mounts[0]['Source']).read_bytes() != (out / 'ca.crt').read_bytes():
        raise ValueError('existing_ca_does_not_match_current_portal')
    image = inspect('image', 'inspect', args.image)[0]['Id']
    directory = out / 'naver-state'
    if directory.is_symlink():
        raise ValueError('naver_state_must_not_be_symlink')
    directory.mkdir(mode=0o700, exist_ok=True)
    os.chown(directory, 10001, 10001)
    os.chmod(directory, 0o700)
    config_copy = out / 'naver-config.json'
    if config_copy.exists() and json.loads(config_copy.read_text()) != {'sources': [source]}:
        raise ValueError('naver_scope_changed_existing_config_preserved_use_explicit_migration')
    if not config_copy.exists():
        write_private(config_copy, json.dumps({'sources': [source]}, indent=2), 0o644)
    composition = {'name': 'cloud-soc-naver', 'services': {'naver': {
        'image': image, 'restart': 'unless-stopped', 'init': True, 'user': '10001:10001',
        'read_only': True, 'cap_drop': ['ALL'], 'security_opt': ['no-new-privileges:true'], 'tmpfs': ['/tmp'],
        'env_file': [str(env)],
        'environment': {'ELASTICSEARCH_URL': 'https://elasticsearch:9200',
            'ELASTICSEARCH_CA_FILE': '/run/secrets/es-ca.crt',
            'ELASTICSEARCH_API_KEY_FILE': '/run/secrets/es-writer'},
        'command': ['collect', '--config', '/app/config.json', '--source', args.source, '--state-dir', '/state'],
        'volumes': [
            {'type': 'bind', 'source': str(config_copy), 'target': '/app/config.json', 'read_only': True},
            {'type': 'bind', 'source': str(out/'ca.crt'), 'target': '/run/secrets/es-ca.crt', 'read_only': True},
            {'type': 'bind', 'source': str(out/'writer-api-key'), 'target': '/run/secrets/es-writer', 'read_only': True},
            {'type': 'bind', 'source': str(directory), 'target': '/state'}],
        'networks': ['central'],
        'logging': {'driver': 'json-file', 'options': {'max-size': '10m', 'max-file': '3'}}}},
        'networks': {'central': {'external': True, 'name': networks.pop()}}}
    target = out / 'naver.compose.json'
    write_private(target, json.dumps(composition, indent=2))
    print(json.dumps({'prepared': True, 'compose': str(target), 'provider': 'naver',
        'collector_started': False, 'aws_changed': False, 'es_permissions_changed': False,
        'live_ingestion_verified': False}))


def main():
    import pwd
    home = Path(pwd.getpwnam(os.environ.get('SUDO_USER') or getpass.getuser()).pw_dir)
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['credentials', 'prepare'])
    parser.add_argument('--env', type=Path, default=home / '.config/cloud-soc/naver.env')
    parser.add_argument('--workspace', type=Path, default=Path(__file__).resolve().parents[2])
    parser.add_argument('--state', type=Path)
    parser.add_argument('--source', default='naver-audit')
    parser.add_argument('--image', default='cloud-soc-multicloud:20261101')
    args = parser.parse_args()
    try:
        {'credentials': credentials, 'prepare': prepare}[args.action](args)
    except Exception as exc:
        print(json.dumps({'success': False, 'error_type': type(exc).__name__,
            'reason': str(exc) if isinstance(exc, ValueError) else 'local_setup_failed_no_secret_output'}))
        sys.exit(1)


if __name__ == '__main__':
    main()
