"""Opt-in Windows VM native Filebeat flow with unchanged execution policy.

This is deliberately NOT a product installer acceptance: it records the default
script-policy block and runs only a SHA512-pinned collector under a disposable
task, with the product's unchanged privacy/input scripts and real enrollment API.
"""
import argparse
import base64
from datetime import datetime, timezone
import io
import json
import logging
from pathlib import Path
import re
import secrets
import sys
import traceback
import urllib.request
import uuid
import zipfile

from device_os_live import Lab, wait

PIN = 'cdb07ad1e39e7c65cefcd7c71e1dfcfa4f92b00daafc132c78490e3e04f664f67403cdb925c5873a8441058d6de08d29790bf6776748edc63582f50174c508c8'


class WindowsLab(Lab):
    def __init__(self, *args):
        super().__init__(*args)
        access = json.loads((self.root/'guest-ready.json').read_text())
        user = access['username'].split('\\')[-1]
        if not re.fullmatch(r'[A-Za-z0-9_.@-]{1,100}', user):
            raise ValueError('Unsupported lab account name')
        self.ssh = ['C:/Windows/System32/OpenSSH/ssh.exe', '-T', '-i', str(self.root/'guest_ed25519'),
            '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
            '-o', 'UserKnownHostsFile='+str(self.root/'known_hosts'), '-o', 'ConnectTimeout=8', user+'@192.168.235.132']
        self.guest_target = user+'@192.168.235.132:'
        self.guest_root = 'C:\\ProgramData\\Cloud-SOC-OS-Lab-20261025\\Native-'+self.label
        self.task = 'Cloud-SOC-OS-Lab-'+self.label
        self.report['native_wsl'] = 'separate_report'
        self.report['scope'] = 'actual Windows VM native collector flow; product installer blocked by default policy'

    def ps(self, script, **kwargs):
        code = "$ProgressPreference='SilentlyContinue';$ErrorActionPreference='Stop';" + \
            "[Console]::OutputEncoding=[Text.UTF8Encoding]::new($false);" + script
        encoded = base64.b64encode(code.encode('utf-16le')).decode()
        return self.command([*self.ssh, 'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '+encoded], **kwargs)

    def upload(self, path, payload):
        assert path.startswith(self.guest_root+'\\')
        # Use the file protocol rather than a child console's stdin/EOF behavior.
        temporary = self.log_dir/('transfer-'+uuid.uuid4().hex+'.tmp')
        try:
            temporary.write_bytes(payload)
            self.command(['C:/Windows/System32/OpenSSH/scp.exe', '-q', '-i', str(self.root/'guest_ed25519'),
                '-o', 'BatchMode=yes', '-o', 'StrictHostKeyChecking=yes',
                '-o', 'UserKnownHostsFile='+str(self.root/'known_hosts'), '-o', 'ConnectTimeout=8',
                str(temporary), self.guest_target+path.replace('\\', '/')], timeout=60)
        finally:
            temporary.unlink(missing_ok=True)

    def machine(self, action, body, token):
        request = urllib.request.Request(self.origin+'/api/installer/'+action,
            headers={'Authorization': 'Bearer '+token, 'X-Cloud-SOC': 'installer', 'Content-Type': 'application/json'},
            data=json.dumps(body).encode())
        with urllib.request.urlopen(request, context=self.context, timeout=15) as response:
            return json.load(response)

    def windows(self):
        root = self.guest_root
        self.report['native_windows'] = 'running_native_collector_only'
        policy = self.ps('Get-ExecutionPolicy').strip()
        self.report['effective_policy_before'] = policy
        assert policy == 'Restricted', 'Record and review unexpected policy before running a different profile'
        self.ps("$r='"+root+"';if(Test-Path $r){throw 'Existing trial path'};"
            "New-Item -ItemType Directory -Path $r | Out-Null;"
            "New-Item -ItemType Directory -Path ($r+'\\inputs'),($r+'\\data'),($r+'\\logs'),($r+'\\source') | Out-Null")
        device, archive = self.device('windows', root+'\\source')
        self.device_id = device['id']
        self.upload(root+'\\device.zip', archive)
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            registration = json.loads(z.read('registration.json'))
            spec = json.loads(z.read('package.json'))
            profile = json.loads(z.read('collection-profile.json'))
            self.upload(root+'\\bootstrap-windows.ps1', z.read('bootstrap-windows.ps1'))
            with zipfile.ZipFile(io.BytesIO(z.read('runtime.zip'))) as runtime:
                for name in ('site-privacy.js', 'privacy.js'):
                    self.upload(root+'\\'+name, runtime.read(name))
            self.upload(root+'\\ca.pem', z.read('ca.crt'))
        blocked = self.ps("try { & '"+root+"\\bootstrap-windows.ps1' help; 'unexpectedly_allowed' } "
            "catch [System.Management.Automation.PSSecurityException] { 'blocked_by_policy' }")
        assert 'blocked_by_policy' in blocked
        self.report['product_installer'] = 'blocked_by_default_execution_policy'
        self.record('windows_default_restricted_product_script_block_confirmed_no_policy_change')
        self.ps("$r='"+root+"';$archive=$r+'\\filebeat.zip';"
            "& $env:SystemRoot\\System32\\curl.exe --disable --fail --silent --show-error --proto '=https' "
            "--tlsv1.2 --connect-timeout 30 --max-time 300 --max-redirs 0 --output $archive "
            "https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-9.5.2-windows-x86_64.zip;"
            "if($LASTEXITCODE -ne 0){throw 'Official collector download failed'};"
            "if((Get-FileHash $archive -Algorithm SHA512).Hash.ToLowerInvariant() -cne '"+PIN+"'){throw 'Pinned SHA512 differs'};"
            "Add-Type -AssemblyName System.IO.Compression.FileSystem;"
            "$z=[IO.Compression.ZipFile]::OpenRead($archive);try{foreach($e in $z.Entries){"
            "if(-not $e.FullName.StartsWith('filebeat-9.5.2-windows-x86_64/') -or $e.FullName -match '\\.\\.'){throw 'Archive member refused'}"
            "}}finally{$z.Dispose()};[IO.Compression.ZipFile]::ExtractToDirectory($archive,$r)", timeout=420, name='windows-official-download')
        attempt = secrets.token_urlsafe(32)
        self.secret_values.append(attempt)
        reply = self.machine('enroll', {'attempt': attempt, 'package_id': spec['package_id'],
            'package_sha256': registration['package_sha256']}, registration['token'])
        key = reply['keys'][0]['key']
        self.secret_values.extend([key, key.split(':', 1)[1]])
        self.beat = root+'\\filebeat-9.5.2-windows-x86_64\\filebeat.exe'
        self.beat_args = '--path.home "'+root+'\\filebeat-9.5.2-windows-x86_64" --path.config "'+root+'" '+ \
            '--path.data "'+root+'\\data" --path.logs "'+root+'\\logs" -c "'+root+'\\filebeat.yml"'
        config = {'filebeat.config.inputs': {'enabled': True, 'path': root+'\\inputs\\*.yml',
                'reload.enabled': True, 'reload.period': '10s'},
            'processors': [{'add_host_metadata': {}}, {'add_fields': {'target': 'organization', 'fields': {'id': 'oslab'}}},
                {'script': {'lang': 'javascript', 'file': 'privacy.js', 'timeout': '50ms', 'tag_on_exception': '_privacy_error'}},
                {'drop_event': {'when': {'contains': {'tags': '_privacy_error'}}}}],
            'output.elasticsearch': {'hosts': [self.endpoint], 'api_key': '${CLOUD_SOC_API_KEY}',
                'ssl.certificate_authorities': [root+'\\ca.pem'], 'ssl.verification_mode': 'full',
                'index': 'soc-host-raw-windows-native-lab'},
            'setup.ilm.enabled': False, 'setup.template.enabled': False,
            'logging.level': 'info', 'logging.to_files': True, 'logging.to_stderr': False,
            'queue.disk': {'max_size': '32MB', 'segment_size': '1MB'}}
        self.upload(root+'\\filebeat.yml', json.dumps(config).encode())
        self.upload(root+'\\inputs\\web.yml', json.dumps(profile['web_inputs']).encode())
        self.upload(root+'\\source\\access.log', b'')
        self.upload(root+'\\source\\audit.json', b'')
        proof = {'@timestamp': datetime.now(timezone.utc).isoformat(),
            'event': {'action': 'installation_probe', 'kind': 'event'}, 'labels': {'installation_probe': reply['probe']},
            'message': 'Synthetic native Windows proof '+'x'*1100}
        self.upload(root+'\\proof.ndjson', (json.dumps(proof)+'\n').encode())
        self.upload(root+'\\inputs\\proof.yml', json.dumps([{'type': 'filestream', 'id': 'native-windows-proof',
            'paths': [root+'\\proof.ndjson'], 'parsers': [{'ndjson': {'target': '', 'add_error_key': True}}]}]).encode())
        self.ps("& '"+self.beat+"' "+self.beat_args+" keystore create; if($LASTEXITCODE -ne 0){throw 'Keystore create failed'}", name='windows-keystore-create')
        key_file = root+'\\one-time-publisher.key'
        self.upload(key_file, key.encode())
        self.ps("$f='"+key_file+"';try{$secret=[IO.File]::ReadAllText($f);"
            "$psi=[Diagnostics.ProcessStartInfo]::new('"+self.beat+"','"+self.beat_args+" keystore add CLOUD_SOC_API_KEY --stdin');"
            "$psi.UseShellExecute=$false;$psi.CreateNoWindow=$true;$psi.RedirectStandardInput=$true;"
            "$p=[Diagnostics.Process]::Start($psi);$p.StandardInput.WriteLine($secret);$p.StandardInput.Close();"
            "$p.WaitForExit();if($p.ExitCode -ne 0){throw 'Keystore add failed'}"
            "}finally{$secret=$null;Remove-Item -LiteralPath $f -Force}")
        self.ps("& '"+self.beat+"' "+self.beat_args+" test config; if($LASTEXITCODE -ne 0){throw 'Config refused'};"
            "& '"+self.beat+"' "+self.beat_args+" test output;if($LASTEXITCODE -ne 0){throw 'TLS/output refused'}", timeout=120, name='windows-config-output')
        self.ps("$action=New-ScheduledTaskAction -Execute '"+self.beat+"' -Argument '"+self.beat_args+"';"
            "$principal=New-ScheduledTaskPrincipal -UserId 'SYSTEM' -LogonType ServiceAccount -RunLevel Highest;"
            "Register-ScheduledTask -TaskName '"+self.task+"' -Action $action -Principal $principal | Out-Null;"
            "Start-ScheduledTask -TaskName '"+self.task+"'")
        hits = wait(lambda: self.raw(device['id']))
        agent = hits[0]['_source']['agent']['id']
        receipt = self.machine('receipt', {'attempt': attempt, 'agents': {'host': agent}}, registration['token'])
        assert receipt['verified'] is True
        assert not self.call('/api/managed-devices/'+device['id']+'/activity')['observed_at']
        self.record('windows_real_native_filebeat_pinned_archive_tls_keystore_machine_metadata_receipt')
        rows = [self.waf('win-positive-'+str(n), '203.0.113.45', '942100') for n in range(2)]
        rows += [self.waf('win-negative-'+str(n), '198.51.100.19', '930100') for n in range(3)]
        self.append_windows(rows)
        wait(lambda: len(self.raw(device['id'], 'generic_modsecurity')) == 5)
        self.pipeline(0, 5)
        self.record('windows_native_two_sqli_three_non_sqli_real_inputs_no_alert')
        self.append_windows([self.waf('win-positive-2', '203.0.113.45', '942100')])
        wait(lambda: len(self.raw(device['id'], 'generic_modsecurity')) == 6)
        alerts = self.pipeline(1, 6)
        self.verify_alert(alerts[0], device['id'])
        self.pipeline(1, 6)
        self.record('windows_native_three_sqli_one_alert_exact_evidence_hash_replay_stable')
        self.call('/api/managed-devices/'+device['id']+'/end', {'confirm': True})
        assert self.call('/api/managed-devices/'+device['id'])['device']['state'] == 'ended'
        assert self.ps('Get-ExecutionPolicy').strip() == policy
        self.report['native_windows'] = 'native_dataflow_passed_installer_blocked'
        self.record('windows_policy_unchanged_remote_key_revoked')

    def append_windows(self, rows):
        text = ''.join(json.dumps(row)+'\n' for row in rows)
        incoming = self.guest_root+'\\incoming.ndjson'
        self.upload(incoming, text.encode())
        self.ps("$p='"+incoming+"';try{[IO.File]::AppendAllText('"+self.guest_root+"\\source\\audit.json',"
            "[IO.File]::ReadAllText($p),[Text.UTF8Encoding]::new($false))}finally{Remove-Item -LiteralPath $p -Force}")

    def cleanup_guest(self):
        root = self.guest_root
        if not root.startswith('C:\\ProgramData\\Cloud-SOC-OS-Lab-20261025\\Native-soc-os-lab-'):
            raise ValueError('Unexpected guest cleanup scope')
        self.ps("$t=Get-ScheduledTask -TaskName '"+self.task+"' -ErrorAction SilentlyContinue;"
            "if($t){if(@($t.Actions).Count -ne 1 -or $t.Actions[0].Execute -cne '"+getattr(self, 'beat', '')+"'){throw 'Task owner differs'};"
            "Stop-ScheduledTask -TaskName '"+self.task+"';Unregister-ScheduledTask -TaskName '"+self.task+"' -Confirm:$false};"
            "$r='"+root+"';if(Test-Path $r){foreach($p in Get-ChildItem -LiteralPath $r -Recurse -Force){"
            "if($p.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'Linked trial path'}};"
            "Get-CimInstance Win32_Process -Filter \"Name='filebeat.exe'\" | Where-Object {$_.ExecutablePath -eq '"+getattr(self, 'beat', '')+"'} | "
            "ForEach-Object {Stop-Process -Id $_.ProcessId -Force};Start-Sleep -Seconds 2;Remove-Item -LiteralPath $r -Recurse -Force};"
            "if(Test-Path $r){throw 'Guest trial files remain'}", name='windows-guest-cleanup')
        self.report['guest_trial_cleanup'] = True
        self.save()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--run', action='store_true', required=True)
    parser.add_argument('--docker', required=True)
    parser.add_argument('--state', type=Path, required=True)
    args = parser.parse_args()
    logging.getLogger('elastic_transport').setLevel(logging.CRITICAL)
    lab = WindowsLab(args.docker, args.state.resolve(strict=True), 'unused_windows_phase')
    try:
        lab.start()
        lab.windows()
    except Exception as error:
        lab.report.update(failure_type=type(error).__name__, failure_location=[
            {'file': Path(f.filename).name, 'line': f.lineno} for f in traceback.extract_tb(error.__traceback__)])
        lab.save()
        print('Windows native lab stopped ('+type(error).__name__+'); inspect redacted log.', flush=True)
        return 1
    finally:
        try:
            lab.cleanup_guest()
        finally:
            lab.close()
    return 0


if __name__ == '__main__':
    sys.exit(main())
