"""Approved lab validation lifecycle. Enter user credentials only on the VM console.

No stored user password or service key is read. Only one new key is created, used
by the existing read-only CLI, then invalidated. No service or document writes.
"""
import argparse
import base64
from datetime import datetime, timezone
import getpass
import hashlib
from ipaddress import ip_address, IPv4Address, IPv6Address
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import time
import urllib.error
import urllib.request
from uuid import uuid4

import validate_correlation_triage as validation

BASE = validation.BASE
UNITS = ('soc-mall-portal.service', 'soc-mall-waf.service',
         'soc-mall-edge-projector.service', 'soc-mall-filebeat-app.service',
         'soc-mall-filebeat-edge.service', 'soc-mall-normalizer.service')


class ConsoleError(ValueError):
    pass


def check(condition, code):
    if not condition:
        raise ConsoleError(code)


class Transport:
    def __init__(self, authorization, ca):
        self.authorization = authorization
        self.owned_id = None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), validation.NoRedirect(),
            urllib.request.HTTPSHandler(context=ssl.create_default_context(cafile=str(ca))))

    def call(self, method, path, body=None):
        permitted = (method == 'POST' and path == '/_security/user/_has_privileges' or
                     method == 'POST' and path == '/_security/api_key' or
                     method == 'GET' and path == '/_security/user/_privileges' or
                     self.owned_id is not None and method == 'GET' and path == '/_security/api_key?id=' + self.owned_id or
                     self.owned_id is not None and method == 'DELETE' and path == '/_security/api_key' and
                     body == {'ids': [self.owned_id]})
        check(permitted, 'console_operation_forbidden')
        request = urllib.request.Request('https://127.0.0.1:19200' + path, method=method,
            data=None if body is None else json.dumps(body).encode(),
            headers={'Authorization': self.authorization, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(request, timeout=20) as response:
                data = response.read(1024 * 1024 + 1)
                check(len(data) <= 1024 * 1024, 'console_response_limit')
                return response.status, json.loads(data)
        except urllib.error.HTTPError as error:
            # Never read or print an error body or exception text.
            return error.code, None
        except (OSError, ValueError):
            raise ConsoleError('console_tls_connection_or_response_failed') from None


def private_directory(path):
    """Pin every directory with openat; existing directories are never chmod'ed."""
    check(os.name == 'posix' and hasattr(os, 'O_NOFOLLOW'), 'linux_console_required')
    check(path.is_absolute() and path.is_relative_to(BASE / 'validation-7ab') and '..' not in path.parts,
          'private_directory_outside_lab')
    fd = os.open(path.anchor, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in path.parts[1:]:
            try:
                os.mkdir(part, mode=0o700, dir_fd=fd)
            except FileExistsError:
                pass
            next_fd = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd);fd = next_fd
        info = os.fstat(fd)
        check(info.st_uid == os.getuid() and stat.S_IMODE(info.st_mode) == 0o700, 'private_directory_permissions')
        return fd
    except BaseException:
        os.close(fd)
        raise


def private_save(path, value):
    fd = private_directory(path.parent)
    try:
        output_fd = os.open(path.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600, dir_fd=fd)
        with os.fdopen(output_fd, 'w', encoding='utf-8') as output:
            json.dump(value, output, indent=2);output.flush();os.fsync(output.fileno())
        os.fsync(fd)
    finally:
        os.close(fd)


def mall_listener(probe):
    """Accept one loopback listener, normalizing IPv4-mapped IPv6 addresses."""
    lines = probe.stdout.splitlines()
    columns = lines[0].split() if len(lines) == 1 else []
    pids = set(re.findall(r'pid=(\d+)', probe.stdout))
    check(probe.returncode == 0 and len(pids) == 1 and len(columns) >= 5 and columns[0] == 'LISTEN',
          'mall_identity_unavailable')
    host, separator, port = columns[3].rpartition(':')
    check(separator and port == '18080', 'mall_identity_unavailable')
    if host.startswith('[') and host.endswith(']'):
        host = host[1:-1]
    check('%' not in host, 'mall_identity_unavailable')
    try:
        address = ip_address(host)
    except ValueError:
        raise ConsoleError('mall_identity_unavailable') from None
    if isinstance(address, IPv6Address):
        address = address.ipv4_mapped
    check(address == IPv4Address('127.0.0.1'), 'mall_identity_unavailable')
    pid = int(pids.pop())
    check(pid > 0, 'mall_identity_unavailable')
    return pid


def snapshot():
    result = {}
    for unit in UNITS:
        probe = subprocess.run(['/usr/bin/systemctl', '--user', 'show', unit,
            '--property=MainPID,ActiveState,SubState,InvocationID,NRestarts'], capture_output=True, text=True, timeout=10)
        check(probe.returncode == 0, 'service_snapshot_failed')
        values = dict(line.split('=', 1) for line in probe.stdout.splitlines() if '=' in line)
        check(values.get('ActiveState') == 'active' and values.get('SubState') == 'running' and
              int(values.get('MainPID', '0')) > 0, 'peer_service_not_running')
        result[unit] = values
    probe = subprocess.run(['/usr/bin/ss', '-H', '-ltnp', 'sport = :18080'], capture_output=True, text=True, timeout=10)
    pid = mall_listener(probe)
    try:
        raw = Path('/proc', str(pid), 'stat').read_text()
        fields = raw.rsplit(')', 1)[1].split()
        check(raw.split(' ', 1)[0] == str(pid) and len(fields) > 19 and
              fields[19].isascii() and fields[19].isdigit() and int(fields[19]) > 0,
              'mall_identity_unavailable')
    except (OSError, IndexError):
        raise ConsoleError('mall_identity_unavailable') from None
    result['mall'] = {'pid': pid, 'start': fields[19]}
    return result


def verify_manifest(root):
    value = json.loads((root / 'manifest.json').read_text())
    check(isinstance(value, dict) and 40 <= len(value) <= 50, 'staging_manifest_invalid')
    for name, digest in value.items():
        relative = Path(name);target = root / relative
        check(not relative.is_absolute() and '..' not in relative.parts and
              not any(p.is_symlink() for p in (target, *target.parents)) and
              hashlib.sha256(target.read_bytes()).hexdigest() == digest, 'staging_manifest_mismatch')
    return hashlib.sha256((root / 'manifest.json').read_bytes()).hexdigest()


def payload(root, run):
    value = json.loads((root / 'deploy/security-mall/validation-read-key.request.example.json').read_text())
    role = value['role_descriptors']
    check(value['expiration'] == '2h' and set(role) == {'mall_7ab_validation_reader'}, 'issuance_plan_mismatch')
    descriptor = role['mall_7ab_validation_reader']
    check(set(descriptor) == {'cluster', 'indices', 'applications', 'run_as'} and
          all(descriptor[k] == [] for k in ('cluster', 'applications', 'run_as')) and len(descriptor['indices']) == 1,
          'issuance_plan_mismatch')
    entry = descriptor['indices'][0]
    check(set(entry) == {'names', 'privileges', 'allow_restricted_indices'} and len(entry['names']) == 6 and
          set(entry['names']) == set(validation.APPROVED_INDICES) and
          entry['privileges'] == ['read', 'view_index_metadata'] and entry['allow_restricted_indices'] is False,
          'issuance_plan_mismatch')
    value['name'] = 'mall-7ab-readonly-' + run
    return value


def assigned_key(issuer, key, expected):
    status, value = issuer.call('GET', '/_security/api_key?id=' + key['id'])
    check(status == 200 and isinstance(value, dict) and len(value.get('api_keys', [])) == 1, 'assigned_key_unverified')
    row = value['api_keys'][0]
    check(row['id'] == key['id'] and row.get('invalidated') is False and
          row.get('expiration') == key['expiration'], 'assigned_key_mismatch')
    roles = row.get('role_descriptors')
    check(isinstance(roles, dict) and set(roles) == set(expected['role_descriptors']), 'assigned_key_mismatch')
    for name, role in roles.items():
        wanted = expected['role_descriptors'][name]
        rows = role.get('indices')
        check(isinstance(rows, list) and len(rows) == 1, 'assigned_key_mismatch')
        row = rows[0];entry = wanted['indices'][0]
        check(all(role.get(k) == [] for k in ('cluster', 'applications', 'run_as')) and
              set(row.get('names', [])) == set(entry['names']) and len(row.get('names', [])) == 6 and
              set(row.get('privileges', [])) == {'read', 'view_index_metadata'} and
              row.get('allow_restricted_indices') is False and
              all(not role.get(k) for k in ('global', 'remote_cluster', 'remote_indices', 'restriction')),
              'assigned_key_mismatch')


def lifecycle(issuer, ca, key_file, expected, run_cli, report):
    """One issuance attempt, cleanup in finally, including CLI or persistence failure."""
    key = None;secret_identity = None
    try:
        status, own = issuer.call('POST', '/_security/user/_has_privileges', {
            'cluster': ['manage_own_api_key'], 'index': [{'names': list(validation.APPROVED_INDICES),
                'privileges': ['read', 'view_index_metadata']}]})
        check(status != 401, 'issuer_authentication_failed')
        check(status != 403, 'issuer_permission_denied')
        check(status == 200 and own.get('has_all_requested') is True, 'issuer_permission_missing')
        report['issuer_permissions_verified'] = True
        report['issuance_attempted'] = True
        status, response = issuer.call('POST', '/_security/api_key', expected)
        check(status == 200 and isinstance(response, dict), 'issuance_failed_or_unknown')
        identifier = response.get('id')
        check(isinstance(identifier, str) and re.fullmatch(r'[A-Za-z0-9_-]{1,256}', identifier), 'issued_id_unknown')
        issuer.owned_id = identifier
        # Capture cleanup identity before checking the rest of the response.
        key = {'id': identifier, 'encoded': response.get('encoded'), 'expiration': response.get('expiration')}
        report['key_issued'] = True
        check(type(key['expiration']) is int and int(time.time() * 1000) < key['expiration'] <= int(time.time() * 1000) + 7260000,
              'issued_expiration_mismatch')
        private_save(key_file, key)
        info = key_file.lstat();secret_identity = (info.st_dev, info.st_ino)
        validation.validation_credential(key_file)
        report['key_saved_private'] = True
        report['expires_at'] = datetime.fromtimestamp(key['expiration'] / 1000, timezone.utc).isoformat()
        assigned_key(issuer, key, expected)
        report['assigned_permissions_match'] = True
        report['cli_exit_code'] = run_cli()
    except (ConsoleError, validation.ValidationError) as error:
        report['reason'] = str(error)
    except KeyboardInterrupt:
        report['reason'] = 'console_interrupted'
    except BaseException:
        report['reason'] = 'console_execution_failed'
    finally:
        if key is not None:
            try:
                status, value = issuer.call('DELETE', '/_security/api_key', {'ids': [key['id']]})
                check(status == 200 and value.get('error_count') == 0 and key['id'] in (
                    value.get('invalidated_api_keys', []) + value.get('previously_invalidated_api_keys', [])), 'key_invalidation_failed')
                report['key_invalidated'] = True
                probe = Transport('ApiKey ' + key['encoded'], ca)
                status, _ = probe.call('GET', '/_security/user/_privileges')
                check(status == 401, 'key_rejection_unverified')
                report['revoked_key_rejected_401'] = True
                if key_file.exists():
                    # Never unlink a replaced or symlinked secret file.
                    info = key_file.lstat()
                    check(secret_identity == (info.st_dev, info.st_ino) and stat.S_ISREG(info.st_mode) and
                          info.st_uid == os.getuid() and
                          stat.S_IMODE(info.st_mode) == 0o600 and info.st_nlink == 1,
                          'secret_cleanup_file_changed')
                    key_file.unlink()
                report['secret_removed'] = True
            except BaseException:
                report['cleanup_failed'] = True
                report['reason'] = 'key_cleanup_incomplete_secret_retained_if_present'
    return 0 if (report.get('cli_exit_code') == 0 and report.get('secret_removed') and not report.get('cleanup_failed')) else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--start', required=True);parser.add_argument('--end', required=True)
    args = parser.parse_args(argv)
    report = {'key_issued': False, 'key_invalidated': False, 'secret_removed': False,
              'integration_complete': False, 'cleanup_failed': False}
    result_dir = None
    try:
        check(os.name == 'posix' and sys.stdin.isatty() and sys.stderr.isatty(), 'interactive_vm_console_required')
        os.umask(0o077)
        root = Path(__file__).resolve().parents[2]
        report['manifest_sha256'] = verify_manifest(root)
        check(Path(validation.__file__).resolve() == root / 'deploy/security-mall/validate_correlation_triage.py',
              'runtime_cli_mismatch')
        for entry in (validation.normalize, validation.CorrelationStore, validation.TriageStore):
            module_path = Path(sys.modules[entry.__module__].__file__).resolve()
            check(module_path.is_relative_to(root / 'src/cloud_soc'), 'runtime_engine_mismatch')
        validation.plan('continuous')
        validation.time_range(args.start, args.end, validation.Policy())
        run = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ-') + uuid4().hex[:8]
        result_dir = BASE / 'validation-7ab' / ('approved-' + run)
        fd = private_directory(result_dir);os.close(fd)
        key_file = BASE / 'validation-7ab/secrets' / ('reader-' + run + '.json')
        before = snapshot()
        private_save(result_dir / 'services-before.json', before)
        expected = payload(root, run)
        ca = BASE / 'portal-lab/config/ca.crt'
        # Interactive terminal input only; never read es-lab/runtime/elastic-password.
        username = getpass.getpass('ES 발급 사용자명(숨김): ')
        password = getpass.getpass('ES 사용자 비밀번호(숨김): ')
        check(username and ':' not in username and password, 'user_authentication_required')
        authorization = 'Basic ' + base64.b64encode((username + ':' + password).encode()).decode()
        del username, password
        issuer = Transport(authorization, ca);del authorization
        report['result_directory'] = str(result_dir)
        def run_cli():
            command = [sys.executable, str(root / 'deploy/security-mall/validate_correlation_triage.py'),
                '--profile', 'continuous', '--start', args.start, '--end', args.end,
                '--api-key-file', str(key_file), '--output-dir', str(result_dir / 'results')]
            output = subprocess.run(command, env=dict(os.environ, PYTHONPATH=str(root / 'src')),
                                    capture_output=True, text=True, timeout=600)
            # The existing CLI owns safe summary serialization. Never echo subprocess stderr/stdout.
            report['cli_summary_present'] = (result_dir / 'results/summary.json').is_file()
            return output.returncode
        code = lifecycle(issuer, ca, key_file, expected, run_cli, report)
        after = snapshot();private_save(result_dir / 'services-after.json', after)
        report['services_unchanged'] = before == after
        if not report['services_unchanged']: code = 1
        report['integration_complete'] = code == 0
    except (ConsoleError, validation.ValidationError) as error:
        report['reason'] = str(error);code = 1
    except BaseException:
        report['reason'] = 'console_preparation_or_final_check_failed';code = 1
    report['exit_code'] = code
    if result_dir is not None:
        try:
            private_save(result_dir / 'lifecycle.json', report)
        except BaseException:
            report.update(exit_code=1, reason='lifecycle_report_save_failed');code = 1
    print(json.dumps(report, ensure_ascii=False))
    return code


if __name__ == '__main__':
    raise SystemExit(main())
