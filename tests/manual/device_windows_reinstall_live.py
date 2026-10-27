"""Opt-in fresh Windows VM EXE deletion/reinstall receipt check; no reboot or queue restore."""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import traceback

from device_os_live import wait
from device_windows_native_live import NativeInstallerLab


class ReinstallLab(NativeInstallerLab):
    def __init__(self, *args):
        super().__init__(*args)
        self.owned_devices = set()
        self.history = None
        self.history_hash = None
        self.report['native_wsl'] = 'not_run'

    def start(self):
        assert self.ps("[bool](Test-Path -LiteralPath 'C:\\ProgramData\\Cloud-SOC-Native-History')").strip() == 'False'
        super().start()

    def windows(self):
        root = self.guest_root
        self.report['native_windows'] = 'running_clean_reinstall'
        self.ps("$r='"+root+"';if(Test-Path -LiteralPath $r){throw 'Trial already exists'};"
                "New-Item -ItemType Directory -Path $r | Out-Null;"
                "icacls $r /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null;"
                "New-Item -ItemType Directory -Path ($r+'\\source') | Out-Null")
        self.upload(root+'\\source\\access.log', b'')
        self.upload(root+'\\source\\audit.json', b'')
        first, archive = self.device('windows', root+'\\source')
        self.device_id = first['id']
        self.owned_devices.add(first['id'])
        self.upload(root+'\\first.zip', archive)
        self.ps("Add-Type -AssemblyName System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory('"+root+"\\first.zip','"+root+"\\bundle')")
        self.owned = True
        self.native('install', '--bundle "'+root+'\\bundle"', bundle=True)
        first_state = json.loads(self.ps("Get-Content -LiteralPath 'C:\\ProgramData\\Cloud-SOC-Native\\state.json' -Raw"))
        assert first_state['phase'] == 'complete' and first_state['device_id'] == first['id']
        assert self.call('/api/managed-devices/'+first['id'])['device']['state'] == 'received'
        first_agent = json.loads(self.ps("Get-Content -LiteralPath 'C:\\Program Files\\Cloud-SOC-Agent\\data\\meta.json' -Raw"))['uuid']
        self.append_windows([self.waf('before-reinstall', '198.51.100.27', '930100')])
        old_hits = wait(lambda: self.raw(first['id'], 'generic_modsecurity'))
        old_raw = old_hits[0]
        old_hash = hashlib.sha256(json.dumps(old_raw['_source'], sort_keys=True).encode()).hexdigest()
        self.record('first_install_new_receipt_and_synthetic_general_log_observed')
        self.native('uninstall')
        self.ps("if(-not(Test-Path -LiteralPath 'C:\\Program Files\\Cloud-SOC-Agent\\data')){throw 'Retained data missing'}")
        second, archive = self.device('windows', root+'\\source')
        self.owned_devices.add(second['id'])
        self.upload(root+'\\second.zip', archive)
        self.ps("Add-Type -AssemblyName System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory('"+root+"\\second.zip','"+root+"\\second')")
        assert self.call('/api/managed-devices/'+second['id'])['device']['state'] != 'received'
        try:
            self.native('install', '--bundle "'+root+'\\second"', bundle=True)
        except RuntimeError:
            assert 'reinstall_preserved_data' in (self.log_dir/'native-install.log').read_text()
        else:
            raise AssertionError('Retained data must block replacement')
        self.native('uninstall', '--purge')
        purged_text = self.ps("Get-Content -LiteralPath 'C:\\ProgramData\\Cloud-SOC-Native\\state.json' -Raw")
        purged = json.loads(purged_text)
        assert purged['phase'] == 'purged'
        self.history = 'C:\\ProgramData\\Cloud-SOC-Native-History\\'.replace('\\\\', '\\')+first['id']+'-'+purged['enrollment_id']
        self.history_hash = self.ps("(Get-FileHash -Algorithm SHA256 -LiteralPath 'C:\\ProgramData\\Cloud-SOC-Native\\state.json').Hash").strip()
        self.call('/api/managed-devices/'+first['id']+'/end', {'confirm': True})
        assert self.call('/api/managed-devices/'+first['id'])['device']['state'] == 'ended'
        self.record('preserved_reinstall_blocked_explicit_purge_and_separate_remote_revocation')
        self.native('install', '--bundle "'+root+'\\second"', bundle=True)
        self.device_id = second['id']
        state = json.loads(self.ps("Get-Content -LiteralPath 'C:\\ProgramData\\Cloud-SOC-Native\\state.json' -Raw"))
        assert state['phase'] == 'complete' and state['device_id'] == second['id']
        assert state['enrollment_id'] != purged['enrollment_id']
        assert self.call('/api/managed-devices/'+second['id'])['device']['state'] == 'received'
        second_agent = json.loads(self.ps("Get-Content -LiteralPath 'C:\\Program Files\\Cloud-SOC-Agent\\data\\meta.json' -Raw"))['uuid']
        assert second_agent != first_agent
        assert self.ps("(Get-FileHash -Algorithm SHA256 -LiteralPath '"+self.history+"\\state.json').Hash").strip() == self.history_hash
        old_after = self.client.get(index=old_raw['_index'], id=old_raw['_id'])
        assert hashlib.sha256(json.dumps(old_after['_source'], sort_keys=True).encode()).hexdigest() == old_hash
        self.append_windows([self.waf('after-reinstall', '198.51.100.28', '930100')])
        wait(lambda: any(hit['_source'].get('agent', {}).get('id') == second_agent
                         for hit in self.raw(second['id'], 'generic_modsecurity')))
        self.record('new_device_session_collector_receipt_general_log_and_old_raw_history_preserved')
        self.native('uninstall', '--purge')
        self.call('/api/managed-devices/'+second['id']+'/end', {'confirm': True})
        assert self.call('/api/managed-devices/'+second['id'])['device']['state'] == 'ended'
        assert self.ps('Get-ExecutionPolicy').strip() == 'Restricted'
        self.report['product_installer'] = 'actual_clean_reinstall_receipt_passed'
        self.report['native_windows'] = 'actual_clean_reinstall_passed'
        self.report['scope'] = 'same VM, new registration after explicit data deletion; no queue restore/reboot/alert rerun'
        self.record('second_purge_remote_revocation_and_execution_policy_unchanged')

    def cleanup_guest(self):
        if self.owned:
            text = self.ps("if(Test-Path -LiteralPath 'C:\\ProgramData\\Cloud-SOC-Native\\state.json'){Get-Content -LiteralPath 'C:\\ProgramData\\Cloud-SOC-Native\\state.json' -Raw}")
            if text:
                current = json.loads(text)
                if current['device_id'] not in self.owned_devices:
                    raise RuntimeError('Unowned guest state; preserve it')
                self.device_id = current['device_id']
        super().cleanup_guest()
        if self.history:
            self.ps("$h='"+self.history+"';$base=[IO.Path]::GetDirectoryName($h);"
                    "if([IO.Path]::GetFullPath($h) -cne $h -or [IO.Path]::GetDirectoryName($h) -cne $base){throw 'History scope'};"
                    "if(Test-Path -LiteralPath $h){if((Get-FileHash -Algorithm SHA256 -LiteralPath ($h+'\\state.json')).Hash -cne '"+self.history_hash+"'){throw 'History changed'};"
                    "foreach($p in @((Get-Item -LiteralPath $h)) + @(Get-ChildItem -LiteralPath $h -Recurse -Force)){if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked history'}};"
                    "Remove-Item -LiteralPath $h -Recurse -Force};"
                    "if((Test-Path -LiteralPath $base) -and @(Get-ChildItem -LiteralPath $base -Force).Count -eq 0){Remove-Item -LiteralPath $base}", name='reinstall-history-cleanup')
        self.report['reinstall_history_cleanup'] = True
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    args = parser.parse_args()
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    lab = ReinstallLab(args.docker, args.state.resolve(strict=True), args.release.resolve(strict=True))
    try:
        lab.start()
        lab.windows()
    except Exception as error:
        lab.report.update(failure_type=type(error).__name__, failure_location=[
            {'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)])
        lab.save()
        print('Clean reinstall lab stopped ('+type(error).__name__+'); inspect redacted log.', flush=True)
        return 1
    finally:
        try:
            lab.cleanup_guest()
        finally:
            lab.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
