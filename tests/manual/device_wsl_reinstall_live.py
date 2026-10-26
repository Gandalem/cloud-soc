"""Opt-in clean-reinstall acceptance in an explicitly prepared disposable Ubuntu WSL distro.

Uses actual bootstrap/manager, systemd, Filebeat and fresh TLS ES/Portal. The caller
owns importing/unregistering the named trial distro; never targets the default WSL.
"""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import traceback

from device_os_live import Lab, wait


class WslReinstallLab(Lab):
    def stage(self, folder, payload):
        self.linux_python("import io,sys,zipfile,os;from pathlib import Path;os.umask(0o077);"
                          f"r=Path({folder!r});r.mkdir();"
                          "z=zipfile.ZipFile(io.BytesIO(sys.stdin.buffer.read()));"
                          "assert all('/' not in n and chr(92) not in n for n in z.namelist());"
                          "[r.joinpath(n).write_bytes(z.read(n)) for n in z.namelist()]", data=payload, name='wsl-bundle-extract')

    def general(self, device, request):
        self.append_linux([self.waf(request, '198.51.100.47', '930100')])
        return wait(lambda: next((hit for hit in self.raw(device, 'generic_modsecurity')
                                  if hit['_source'].get('http', {}).get('request', {}).get('id') == request), None))

    def linux(self):
        self.report.update(native_wsl='running_clean_reinstall', native_windows='not_run',
                           scope='fresh Ubuntu24.04 WSL same-distro deletion/new-registration receipt; no queue restore/DEB/alert/reboot test')
        self.linux_python("from pathlib import Path;assert 'VERSION_ID=\"24.04\"' in Path('/etc/os-release').read_text();"
                          "assert Path('/proc/1/comm').read_text().strip()=='systemd';"
                          "assert not any(Path(p).exists() for p in ['/opt/cloud-soc-agent','/var/lib/cloud-soc-enrollment','/var/lib/cloud-soc-bundles'])")
        self.linux_root = '/root/'+self.label
        self.linux_logs = '/var/log/'+self.label
        self.linux_python("from pathlib import Path;import os;os.umask(0o077);"
                          f"Path({self.linux_root!r}).mkdir();p=Path({self.linux_logs!r});p.mkdir();"
                          "(p/'access.log').touch();(p/'audit.json').touch()")
        first, payload = self.device('ubuntu', self.linux_logs)
        first_bundle = self.linux_root+'/first'
        self.stage(first_bundle, payload)
        self.wsl('python3', first_bundle+'/bootstrap-linux.py', 'install', timeout=1500, name='wsl-first-install')
        assert self.call('/api/managed-devices/'+first['id'])['device']['state'] == 'received'
        first_agent = self.linux_python("import json;from pathlib import Path;print(json.loads(Path('/opt/cloud-soc-agent/data/meta.json').read_text())['uuid'])")
        first_manager = '/var/lib/cloud-soc-bundles/'+first['id']+'/agent-manager.py'
        self.linux_python("from pathlib import Path;import shutil;"
                          f"p=Path({first_bundle!r});assert p.parent==Path({self.linux_root!r});shutil.rmtree(p)")
        self.wsl('python3', first_manager, 'status', name='wsl-status-without-download')
        old = self.general(first['id'], 'before-clean-reinstall')
        old_hash = hashlib.sha256(json.dumps(old['_source'], sort_keys=True).encode()).hexdigest()
        self.record('wsl_first_product_install_fresh_receipt_and_exact_general_request_without_download_bundle')
        self.wsl('python3', first_manager, 'uninstall', data=b'1\n', name='wsl-preserve-remove')
        previous = json.loads(self.linux_python("import json,hashlib;from pathlib import Path;"
                              "s=Path('/var/lib/cloud-soc-enrollment');a=list(s.glob('retired-*'));assert len(a)==1;"
                              "r=json.loads((a[0]/'operation.json').read_text());assert r['data_preserved'] is True;"
                              "c=s/('complete-'+r['session']+'.json');"
                              "assert not Path('/opt/cloud-soc-agent').exists();"
                              "assert (a[0]/'cloud-soc-agent/data').is_dir();"
                              "print(json.dumps({'archive':str(a[0]),'receipt':c.name,'receipt_sha256':hashlib.sha256(c.read_bytes()).hexdigest()}))"))
        second, payload = self.device('ubuntu', self.linux_logs)
        second_bundle = self.linux_root+'/second'
        self.stage(second_bundle, payload)
        assert self.call('/api/managed-devices/'+second['id'])['device']['state'] != 'received'
        self.linux_python("import subprocess;"
                          f"p=subprocess.run(['python3',{second_bundle+'/bootstrap-linux.py'!r},'install'],capture_output=True);"
                          "assert p.returncode!=0 and '보존 자료' in p.stderr.decode('utf8');"
                          "print('preserved data correctly blocks the new installation')", name='wsl-preserved-reinstall-blocked')
        self.linux_python("import hashlib;from pathlib import Path;"
                          f"p=Path('/var/lib/cloud-soc-enrollment')/{previous['receipt']!r};"
                          f"assert hashlib.sha256(p.read_bytes()).hexdigest()=={previous['receipt_sha256']!r}")
        self.wsl('python3', first_manager, 'uninstall', data=b'DELETE\n', name='wsl-purge-retained')
        self.linux_python("import json;from pathlib import Path;"
                          f"a=Path({previous['archive']!r});r=json.loads((a/'operation.json').read_text());"
                          "assert r['state']=='removed' and r['data_preserved'] is False;"
                          "assert not (a/'cloud-soc-agent').exists() and not Path('/opt/cloud-soc-agent').exists()")
        self.call('/api/managed-devices/'+first['id']+'/end', {'confirm': True})
        assert self.call('/api/managed-devices/'+first['id'])['device']['state'] == 'ended'
        self.record('wsl_preserve_blocks_replacement_explicit_retained_purge_and_separate_old_key_revocation')
        self.wsl('python3', second_bundle+'/bootstrap-linux.py', 'install', timeout=1500, name='wsl-second-install')
        assert self.call('/api/managed-devices/'+second['id'])['device']['state'] == 'received'
        second_agent = self.linux_python("import json;from pathlib import Path;print(json.loads(Path('/opt/cloud-soc-agent/data/meta.json').read_text())['uuid'])")
        assert first_agent != second_agent
        current = self.general(second['id'], 'after-clean-reinstall')
        assert current['_source']['agent']['id'] == second_agent
        assert current['_source']['organization']['id'] == 'oslab'
        self.linux_python("import json,hashlib;from pathlib import Path;"
                          f"a=Path({previous['archive']!r})/{previous['receipt']!r};"
                          f"assert hashlib.sha256(a.read_bytes()).hexdigest()=={previous['receipt_sha256']!r};"
                          "p=list(Path('/var/lib/cloud-soc-enrollment').glob('complete-*.json'));assert len(p)==1;"
                          f"assert json.loads(p[0].read_text())['spec']['managed_device_id']=={second['id']!r}")
        old_after = self.client.get(index=old['_index'], id=old['_id'])
        assert hashlib.sha256(json.dumps(old_after['_source'], sort_keys=True).encode()).hexdigest() == old_hash
        self.record('wsl_new_registration_collector_uuid_fresh_receipt_exact_new_request_and_previous_history_raw_preserved')
        second_manager = '/var/lib/cloud-soc-bundles/'+second['id']+'/agent-manager.py'
        self.wsl('python3', second_manager, 'uninstall', data=b'2\nDELETE\n', name='wsl-second-purge')
        self.call('/api/managed-devices/'+second['id']+'/end', {'confirm': True})
        assert self.call('/api/managed-devices/'+second['id'])['device']['state'] == 'ended'
        self.linux_python("from pathlib import Path;import subprocess;"
                          "assert not Path('/opt/cloud-soc-agent').exists();"
                          "assert not any(Path('/etc/systemd/system',n).exists() for n in ['cloud-soc-filebeat.service','cloud-soc-discovery.service','cloud-soc-discovery.timer']);"
                          "assert subprocess.run(['pgrep','-x','filebeat'],capture_output=True).returncode==1")
        self.report['native_wsl'] = 'actual_clean_reinstall_passed'
        self.report['product_installer'] = 'actual_wsl_clean_reinstall_receipt_passed'
        self.record('wsl_second_data_delete_remote_revocation_no_collector_service_or_process')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--distro', required=True)
    args = parser.parse_args()
    root = args.state.resolve(strict=True)
    owned = json.loads((root/'distro-before.json').read_text())
    assert args.distro == owned['trial'] and args.distro.startswith('CloudSOC-Reinstall-') and args.distro not in owned['names']
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    lab = WslReinstallLab(args.docker, root, args.distro)
    try:
        lab.start()
        lab.linux()
    except Exception as error:
        lab.report.update(failure_type=type(error).__name__, failure_location=[
            {'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)])
        lab.save()
        print('WSL reinstall check stopped ('+type(error).__name__+'); inspect the redacted trial log.', flush=True)
        return 1
    finally:
        lab.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
