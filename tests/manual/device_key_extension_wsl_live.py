"""Explicit disposable WSL/Filebeat expiry acceptance; no default distro access.

Imports a checksum-pinned public Ubuntu image into a fresh task-owned directory.
Management uses the real HTTPS Portal API. Browser clicks are NOT claimed here.
"""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import secrets
import shutil
import subprocess
import traceback
import uuid
import winreg

from device_os_live import PROJECT, HOST, PORTAL_PORT, CRL_PORT, wait
from device_wsl_reinstall_live import WslReinstallLab


IMAGE_HASH = 'bb415d824822c4b878125729af451a5d18fb13d1cf5cbed9a7393ad64ac6039e'


def names():
    result = subprocess.run(['wsl.exe', '--list', '--quiet'], capture_output=True, timeout=30, check=True)
    return sorted(s.strip() for s in result.stdout.decode('utf-16-le').replace('\x00', '').splitlines() if s.strip())


def base_path(distro):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r'Software\Microsoft\Windows\CurrentVersion\Lxss') as root:
        for number in range(winreg.QueryInfoKey(root)[0]):
            with winreg.OpenKey(root, winreg.EnumKey(root, number)) as entry:
                if winreg.QueryValueEx(entry, 'DistributionName')[0] == distro:
                    return Path(winreg.QueryValueEx(entry, 'BasePath')[0].removeprefix('\\\\?\\')).resolve()
    raise RuntimeError('Trial WSL registry identity not found')


class KeyExtensionWslLab(WslReinstallLab):
    def snapshot(self):
        return json.loads(self.linux_python("import json,hashlib,subprocess;from pathlib import Path;"
            "r=Path('/opt/cloud-soc-agent');"
            "files=['filebeat.yml','ca.crt','data/filebeat.keystore'];"
            "state=subprocess.check_output(['systemctl','show','cloud-soc-filebeat.service',"
            "'--property=MainPID,ExecMainStartTimestampMonotonic,ActiveState,SubState']).decode();"
            "receipt=list(Path('/var/lib/cloud-soc-enrollment').glob('complete-*.json'));assert len(receipt)==1;"
            "print(json.dumps({'agent_id':json.loads((r/'data/meta.json').read_text())['uuid'],"
            "'service':dict(line.split('=',1) for line in state.splitlines() if '=' in line),"
            "'file_hashes':{p:hashlib.sha256((r/p).read_bytes()).hexdigest() for p in files},"
            "'receipt_sha256':hashlib.sha256(receipt[0].read_bytes()).hexdigest()}))"))

    def linux(self):
        self.report.update(native_wsl='running_key_extension', native_windows='not_run',
            browser_clicks='not_run_browser_tool_start_failure',
            scope='one fresh Ubuntu24.04 WSL actual Filebeat; HTTPS management API; no attack/alert/reboot/old-expiry wait')
        self.linux_python("from pathlib import Path;assert 'VERSION_ID=\"24.04\"' in Path('/etc/os-release').read_text();"
            "assert Path('/proc/1/comm').read_text().strip()=='systemd';"
            "assert not any(Path(p).exists() for p in ['/opt/cloud-soc-agent','/var/lib/cloud-soc-enrollment','/var/lib/cloud-soc-bundles'])")
        self.linux_root, self.linux_logs = '/root/'+self.label, '/var/log/'+self.label
        self.linux_python("from pathlib import Path;import os;os.umask(0o077);"
            f"Path({self.linux_root!r}).mkdir();p=Path({self.linux_logs!r});p.mkdir();"
            "(p/'access.log').touch();(p/'audit.json').touch()")
        device, payload = self.device('ubuntu', self.linux_logs)
        self.stage(self.linux_root+'/bundle', payload)
        self.wsl('python3', self.linux_root+'/bundle/bootstrap-linux.py', 'install', timeout=1500, name='wsl-product-install')
        detail = self.call('/api/managed-devices/'+device['id'])['device']
        assert detail['state'] == 'received' and len(detail['keys']) == 1
        self.record('wsl_product_installer_actual_filebeat_fresh_receipt')
        before = self.general(device['id'], 'before-key-extension-'+self.label)
        before_hash = hashlib.sha256(json.dumps(before['_source'], sort_keys=True).encode()).hexdigest()
        local = self.snapshot()
        assert int(local['service']['MainPID']) > 0 and local['service']['ActiveState'] == 'active'
        key_id = detail['keys'][0]['id']
        issuer = self.app.extensions['issuer']
        remote = issuer.security.get_api_key(id=key_id, owner=True, with_limited_by=True)['api_keys'][0]
        base = '/api/managed-devices/'+device['id']+'/key-extension'
        operation = self.call(base+'/preview', {'key_id': key_id, 'days': 1})['extension']
        assert operation['before_expiration'] == remote['expiration']
        result = self.call(base+'/'+operation['id'], {'confirm': True})
        assert result['extension']['state'] == 'complete'
        after_remote = issuer.security.get_api_key(id=key_id, owner=True, with_limited_by=True)['api_keys'][0]
        assert after_remote['id'] == key_id and after_remote['expiration'] > remote['expiration']
        assert after_remote['role_descriptors'] == remote['role_descriptors']
        assert after_remote['limited_by'] == remote['limited_by']
        assert result['device']['keys'][0]['expiration'] == after_remote['expiration']
        assert self.call(base+'/'+operation['id'], {'confirm': True})['extension'] == result['extension']
        after = self.general(device['id'], 'after-key-extension-'+self.label)
        assert self.snapshot() == local, 'Service/config/keystore/receipt or collector identity changed'
        for hit in (before, after):
            source = hit['_source']
            assert source['agent']['id'] == local['agent_id']
            assert source['organization']['id'] == 'oslab'
            assert source['cloud_soc_enrollment']['key_id'] == key_id
            assert source['cloud_soc_enrollment']['package_id'] == device['package_id']
            assert source['cloud_soc_enrollment']['id'] == detail['registration']['id']
        original = self.client.get(index=before['_index'], id=before['_id'])['_source']
        assert hashlib.sha256(json.dumps(original, sort_keys=True).encode()).hexdigest() == before_hash
        for marker in ('before-key-extension-'+self.label, 'after-key-extension-'+self.label):
            assert sum(hit['_source'].get('http', {}).get('request', {}).get('id') == marker
                       for hit in self.raw(device['id'], 'generic_modsecurity')) == 1
        self.report['acceptance'] = {'before_expiration': remote['expiration'],
            'confirmed_expiration': after_remote['expiration'], 'same_key_id': True,
            'same_agent_id': True, 'same_service_pid_and_start': True, 'same_config_keystore_and_receipt': True,
            'before_raw': {'index': before['_index'], 'id': before['_id']},
            'after_raw': {'index': after['_index'], 'id': after['_id']}, 'previous_raw_unchanged': True,
            'old_expiry_crossing': 'not_waited_minimum_product_key_lifetime_one_day'}
        self.record('wsl_same_running_filebeat_exact_before_after_logs_same_key_and_identity_no_restart_or_reinstall')
        manager = '/var/lib/cloud-soc-bundles/'+device['id']+'/agent-manager.py'
        self.wsl('python3', manager, 'uninstall', data=b'2\nDELETE\n', name='wsl-product-uninstall')
        ended = self.call('/api/managed-devices/'+device['id']+'/end', {'confirm': True})['device']
        assert ended['state'] == 'ended'
        assert issuer.security.get_api_key(id=key_id, owner=True)['api_keys'][0]['invalidated'] is True
        self.linux_python("from pathlib import Path;import subprocess;"
            "assert not Path('/opt/cloud-soc-agent').exists();"
            "assert not Path('/etc/systemd/system/cloud-soc-filebeat.service').exists();"
            "assert subprocess.run(['pgrep','-x','filebeat'],capture_output=True).returncode==1")
        self.report['native_wsl'] = 'actual_filebeat_key_extension_passed'
        self.report['product_installer'] = 'actual_wsl_install_collection_extension_uninstall_passed'
        self.record('wsl_product_remove_and_extended_key_revocation_confirmed')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--image', type=Path, required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    root = args.state.resolve()
    if root.exists() or not root.is_relative_to((PROJECT/'state').resolve()):
        raise ValueError('Fresh task-owned state directory required')
    image = args.image.resolve(strict=True)
    if hashlib.sha256(image.read_bytes()).hexdigest() != IMAGE_HASH:
        raise ValueError('Pinned official Ubuntu WSL checksum differs')
    root.mkdir(parents=True, mode=0o700)
    prior = names()
    trial = 'CloudSOC-KeyExtend-2404-'+secrets.token_hex(5)
    distro_root = root/'wsl'
    token = uuid.uuid4().hex
    ownership = {'trial': trial, 'prior': prior, 'path': str(distro_root), 'owner_token': token}
    (root/'distro-ownership.json').write_text(json.dumps(ownership, indent=2))
    lab, imported, status = None, False, 1
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    try:
        assert trial not in prior
        subprocess.run(['wsl.exe', '--import', trial, str(distro_root), str(image), '--version', '2'],
                       capture_output=True, timeout=300, check=True)
        imported = True
        assert base_path(trial) == distro_root.resolve()
        print('fresh_task_owned_wsl_imported', flush=True)
        # Only the fresh trial is prepared; original Ubuntu is never selected.
        preparation = subprocess.run(['wsl.exe', '-d', trial, '-u', 'root', '--', 'sh', '-c',
            'set -eu; apt-get update -qq; DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends '
            'python3 curl openssl ca-certificates systemd systemd-sysv procps'], capture_output=True, timeout=600)
        (root/'prepare.log').write_bytes(preparation.stdout + preparation.stderr)
        if preparation.returncode:
            raise RuntimeError('Fresh WSL package preparation failed; inspect prepare.log')
        preparation = subprocess.run(['wsl.exe', '-d', trial, '-u', 'root', '--', 'python3', '-c',
            "from pathlib import Path;import configparser;p=Path('/etc/wsl.conf');"
            "c=configparser.ConfigParser();c.read(p);"
            "c.add_section('boot') if not c.has_section('boot') else None;"
            "c.set('boot','systemd','true');"
            "f=p.open('w');c.write(f);f.close()"], capture_output=True, timeout=90)
        (root/'systemd-prepare.log').write_bytes(preparation.stdout + preparation.stderr)
        if preparation.returncode:
            raise RuntimeError('Fresh WSL systemd preparation failed; inspect systemd-prepare.log')
        subprocess.run(['wsl.exe', '--terminate', trial], capture_output=True, timeout=60, check=True)
        lab = KeyExtensionWslLab(args.docker, root, trial)
        wait(lambda: lab.linux_python("from pathlib import Path;print(Path('/proc/1/comm').read_text().strip())") == 'systemd', 60)
        lab.start()
        lab.linux()
        status = 0
    except Exception as error:
        details = {'failure_type': type(error).__name__, 'failure_location': [
            {'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)]}
        (root/'failure.json').write_text(json.dumps(details, indent=2))
        print('WSL key extension stopped: '+type(error).__name__, flush=True)
    finally:
        cleanup = {'original_distro_names_preserved': False, 'trial_distro_removed': False,
                   'trial_resources_removed': False, 'private_directories_removed': False, 'reboot': False}
        try:
            if lab:
                lab.close()
            # A failed import may also leave a registered partial trial. Registry
            # path, absence at entry and task marker must all agree before removal.
            if trial in names():
                current = json.loads((root/'distro-ownership.json').read_text())
                assert current == ownership and current['owner_token'] == token and trial not in prior
                assert base_path(trial) == distro_root.resolve() and distro_root.resolve().is_relative_to(root)
                subprocess.run(['wsl.exe', '--terminate', trial], capture_output=True, timeout=60, check=True)
                subprocess.run(['wsl.exe', '--unregister', trial], capture_output=True, timeout=120, check=True)
            remaining = names()
            cleanup.update(trial_distro_removed=trial not in remaining,
                           original_distro_names_preserved=remaining == prior, imported=imported)
            if lab:
                assert not lab.dk('ps', '-a', '--filter', 'label=cloud-soc.lab='+lab.label, '--format', '{{.Names}}')
                assert not lab.dk('volume', 'ls', '--filter', 'label=cloud-soc.lab='+lab.label, '--format', '{{.Name}}')
                cleanup['trial_resources_removed'] = True
                for directory in (lab.tls, lab.log_dir/'portal'):
                    absolute = directory.resolve()
                    assert absolute.is_relative_to(root) and not directory.is_symlink()
                    if directory.exists():
                        shutil.rmtree(directory)
                cleanup['private_directories_removed'] = not lab.tls.exists() and not (lab.log_dir/'portal').exists()
            import socket
            ports = {}
            for port in (PORTAL_PORT, CRL_PORT):
                with socket.socket() as connection:
                    connection.settimeout(2)
                    ports[str(port)] = connection.connect_ex((HOST, port)) != 0
            cleanup['trial_ports_closed'] = ports
            assert cleanup['trial_distro_removed'] and cleanup['original_distro_names_preserved']
        except Exception as error:
            cleanup['failure_type'] = type(error).__name__
            status = 1
        (root/'cleanup-audit.json').write_text(json.dumps(cleanup, indent=2))
        print('cleanup_audit_saved', flush=True)
    return status


if __name__ == '__main__':
    raise SystemExit(main())
