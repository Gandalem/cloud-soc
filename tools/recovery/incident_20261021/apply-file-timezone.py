#!/usr/bin/env python3
"""Add a conditional live-host timezone processor to the installed JSON config."""
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile

ROOT = Path('/opt/cloud-soc-agent')
CONFIG = ROOT / 'filebeat.yml'
PROCESSOR = {'add_locale': {'format': 'offset'}, 'when': {'and': [
    {'or': [{'equals': {'labels.log_source':'linux_file'}},
            {'equals': {'labels.log_source':'linux_auth'}}]},
    {'not': {'has_fields':['event.timezone']}}]}}


def main():
    if os.geteuid() != 0 or CONFIG.is_symlink():
        raise SystemExit('Run with sudo; symlinked configuration refused.')
    original = CONFIG.read_bytes()
    value = json.loads(original)
    processors = value.setdefault('processors', [])
    if not isinstance(processors, list):
        raise SystemExit('Unexpected processors; configuration not changed.')
    if PROCESSOR in processors:
        print('Host timezone processor is already installed.')
        return
    processors.insert(0, PROCESSOR)
    info = CONFIG.stat()
    descriptor, filename = tempfile.mkstemp(prefix='.filebeat-timezone-', suffix='.json', dir=ROOT)
    temporary = Path(filename)
    try:
        with os.fdopen(descriptor, 'w') as target:
            json.dump(value, target, indent=2);target.write('\n');target.flush();os.fsync(target.fileno())
            os.fchown(target.fileno(), info.st_uid, info.st_gid)
            os.fchmod(target.fileno(), stat.S_IMODE(info.st_mode))
        command = [str(ROOT / 'filebeat/filebeat'), '--path.home',str(ROOT / 'filebeat'),
                   '--path.config',str(ROOT), '--path.data',str(ROOT / 'data'),
                   '--path.logs',str(ROOT / 'logs'), '-c',str(temporary),'test','config']
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise SystemExit('Filebeat rejected the candidate config; existing config retained. No secrets printed.')
        if CONFIG.read_bytes() != original:
            raise SystemExit('Config changed concurrently; no replacement performed.')
        backup_folder = ROOT / 'config-backups'
        backup_folder.mkdir(mode=0o700, exist_ok=True)
        if backup_folder.is_symlink():
            raise SystemExit('Unsafe backup directory; no replacement performed.')
        fd, backup_name = tempfile.mkstemp(prefix='before-timezone-', suffix='.json', dir=backup_folder)
        with os.fdopen(fd,'wb') as backup:
            backup.write(original);backup.flush();os.fsync(backup.fileno())
        os.replace(temporary,CONFIG)
        restart = subprocess.run(['systemctl','restart','cloud-soc-filebeat.service'],capture_output=True)
        active = subprocess.run(['systemctl','is-active','--quiet','cloud-soc-filebeat.service'])
        if restart.returncode or active.returncode:
            # Retain both configs. Restore the original config without touching queues/keys.
            restore = ROOT / '.filebeat-timezone-restore'
            shutil.copy2(backup_name,restore);os.chown(restore,info.st_uid,info.st_gid)
            os.chmod(restore,stat.S_IMODE(info.st_mode));os.replace(restore,CONFIG)
            subprocess.run(['systemctl','start','cloud-soc-filebeat.service'],capture_output=True)
            raise SystemExit('Filebeat start failed; original config restored. Inspect service status.')
        print('Filebeat active; new local file events receive the actual host UTC offset.')
        print('Existing source timestamps, queue data and API keys were retained.')
    finally:
        temporary.unlink(missing_ok=True)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('Timezone update stopped; credentials omitted. Inspect service status before retrying.') from None
