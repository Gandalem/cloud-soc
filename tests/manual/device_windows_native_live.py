"""Opt-in actual native EXE install on a separately prepared Windows VM.

PowerShell is ONLY the SSH lab controller, never a product installation fallback.
Uses fresh TLS Elasticsearch/Portal and synthetic files; no host agent/reboot.
Requires pinned known_hosts, new guest key and guest-ready.json in private --state.
"""
import argparse
import hashlib
import json
import logging
from pathlib import Path
import traceback

from device_os_live import wait
from device_windows_live import WindowsLab


class NativeInstallerLab(WindowsLab):
    def __init__(self, docker, root, release):
        super().__init__(docker, root, 'unused')
        self.release = release
        self.report.update(scope='actual native EXE VM installer; fresh synthetic lab', product_installer='not_started')
        self.owned = False

    def start(self):
        # No containers or guest mutation if access/policy/existing state differs.
        assert self.ps('Get-ExecutionPolicy').strip() == 'Restricted'
        assert self.ps("[bool]((Test-Path 'C:\\Program Files\\Cloud-SOC-Agent') -or (Test-Path 'C:\\ProgramData\\Cloud-SOC-Native'))").strip() == 'False'
        super().start()
        store = self.app.extensions['packages']
        store.windows_installer_dir = self.release
        store.windows_installer_sha256 = hashlib.sha256((self.release/'cloud-soc-agent-setup.exe').read_bytes()).hexdigest()
        store.windows_installer_allow_lab = True

    def native(self, action, extra='', *, bundle=False):
        exe = self.guest_root+'\\bundle\\cloud-soc-agent-setup.exe' if bundle else 'C:\\ProgramData\\Cloud-SOC-Native\\cloud-soc-agent.exe'
        return self.ps("$s=[Diagnostics.ProcessStartInfo]::new('"+exe+"','--"+action+" --lab --quiet "+extra+"');"
                       "$s.UseShellExecute=$false;$s.CreateNoWindow=$true;$s.RedirectStandardOutput=$true;$s.RedirectStandardError=$true;"
                       "$p=[Diagnostics.Process]::new();$p.StartInfo=$s;$null=$p.Start();$o=$p.StandardOutput.ReadToEndAsync();$e=$p.StandardError.ReadToEndAsync();"
                       "if(-not $p.WaitForExit(870000)){$p.Kill();throw 'Native timeout'};$p.WaitForExit();$o.Result;$e.Result;"
                       "if($p.ExitCode -ne 0){if(Test-Path 'C:\\ProgramData\\Cloud-SOC-Native\\diagnostic.json'){Get-Content 'C:\\ProgramData\\Cloud-SOC-Native\\diagnostic.json' -Raw};throw 'Native operation failed'}", timeout=900, name='native-'+action)

    def windows(self):
        root = self.guest_root
        self.ps("$r='"+root+"';if(Test-Path -LiteralPath $r){throw 'Trial path exists'};"
                "New-Item -ItemType Directory -Path $r | Out-Null;"
                "icacls $r /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null;"
                "New-Item -ItemType Directory -Path ($r+'\\source') | Out-Null")
        self.upload(root+'\\source\\access.log', b'')
        self.upload(root+'\\source\\audit.json', b'')
        device, archive = self.device('windows', root+'\\source')
        self.device_id = device['id']
        self.upload(root+'\\device.zip', archive)
        self.ps("Add-Type -AssemblyName System.IO.Compression.FileSystem;[IO.Compression.ZipFile]::ExtractToDirectory('"+root+"\\device.zip','"+root+"\\bundle')")
        self.owned = True
        self.report['product_installer'] = 'running_native_exe'
        self.save()
        self.native('install', '--bundle "'+root+'\\bundle"', bundle=True)
        public = json.loads(self.ps("Get-Content 'C:\\ProgramData\\Cloud-SOC-Native\\state.json' -Raw"))
        assert public['phase'] == 'complete' and public['device_id'] == device['id']
        assert self.call('/api/managed-devices/'+device['id'])['device']['state'] == 'received'
        self.record('native_exe_default_restricted_scm_com_dpapi_keystore_actual_central_receipt')
        # The product installer, not the controller, created the service/task/config.
        action = json.loads(self.ps("Get-ScheduledTask -TaskName Cloud-SOC-Discovery | Select-Object -ExpandProperty Actions | Select-Object Execute,Arguments | ConvertTo-Json"))
        assert action['Execute'] == 'C:\\ProgramData\\Cloud-SOC-Native\\cloud-soc-agent.exe' and action['Arguments'] == '--refresh'
        self.native('stop'); self.native('start')
        self.append_windows([self.waf('native-positive-'+str(n), '203.0.113.45', '942100') for n in range(2)]
                            + [self.waf('native-negative-'+str(n), '198.51.100.19', '930100') for n in range(3)])
        wait(lambda: len(self.raw(device['id'], 'generic_modsecurity')) == 5)
        self.pipeline(0, 5)
        self.append_windows([self.waf('native-positive-2', '203.0.113.45', '942100')])
        wait(lambda: len(self.raw(device['id'], 'generic_modsecurity')) == 6)
        alerts = self.pipeline(1, 6); self.verify_alert(alerts[0], device['id']); self.pipeline(1, 6)
        self.record('native_installer_real_logs_two_positive_zero_alert_three_positive_one_alert_exact_evidence_replay_stable')
        self.native('uninstall')
        assert self.ps("[bool](Test-Path 'C:\\Program Files\\Cloud-SOC-Agent\\data')").strip() == 'True'
        assert self.ps("[bool](Get-Service cloud-soc-filebeat -ErrorAction SilentlyContinue)").strip() == 'False'
        assert self.ps("[bool](Get-ScheduledTask -TaskName Cloud-SOC-Discovery -ErrorAction SilentlyContinue)").strip() == 'False'
        self.native('uninstall', '--purge')
        assert self.ps("[bool](Test-Path 'C:\\Program Files\\Cloud-SOC-Agent')").strip() == 'False'
        assert self.ps('Get-ExecutionPolicy').strip() == 'Restricted'
        self.call('/api/managed-devices/'+device['id']+'/end', {'confirm': True})
        assert self.call('/api/managed-devices/'+device['id'])['device']['state'] == 'ended'
        self.report['product_installer'] = 'actual_native_install_receipt_dataflow_uninstall_passed'
        self.record('native_stop_start_preserve_remove_explicit_purge_policy_unchanged_remote_revoke')

    def cleanup_guest(self):
        # Never delete a guest installation unless this fresh run owns its exact device.
        if self.owned:
            public = self.ps("if(Test-Path 'C:\\ProgramData\\Cloud-SOC-Native\\state.json'){Get-Content 'C:\\ProgramData\\Cloud-SOC-Native\\state.json' -Raw}")
            if public:
                state = json.loads(public)
                if state.get('device_id') != self.device_id:
                    raise RuntimeError('Guest owner differs; cleanup refused')
                if state.get('phase') not in ('purged',):
                    self.native('uninstall', '--purge')
                # Product intentionally retains manager/audit. Trial cleanup removes ONLY new owned state.
                self.ps("$r='C:\\ProgramData\\Cloud-SOC-Native';"
                        "if((Get-Service cloud-soc-filebeat -ErrorAction SilentlyContinue) -or (Get-ScheduledTask -TaskName Cloud-SOC-Discovery -ErrorAction SilentlyContinue)){throw 'Collector still exists'};"
                        "foreach($p in Get-ChildItem -LiteralPath $r -Recurse -Force){if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked trial state'}};"
                        "Remove-Item -LiteralPath $r -Recurse -Force")
        # No standalone Beat task is created by this subclass.
        super().cleanup_guest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--state', type=Path, required=True)
    parser.add_argument('--release', type=Path, required=True)
    args = parser.parse_args()
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    lab = NativeInstallerLab(args.docker, args.state.resolve(strict=True), args.release.resolve(strict=True))
    try:
        lab.start(); lab.windows()
    except Exception as error:
        lab.report.update(failure_type=type(error).__name__, failure_location=[
            {'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)])
        lab.save(); print('Native installer lab stopped ('+type(error).__name__+'); inspect redacted log.', flush=True)
        return 1
    finally:
        try:
            lab.cleanup_guest()
        finally:
            lab.close()
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
