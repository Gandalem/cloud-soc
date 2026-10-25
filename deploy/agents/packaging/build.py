"""Build common installer artifacts with locally supplied, pinned tools. Never downloads/runs installers."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]
VERSIONS = {'windows': '4.8', 'ubuntu': '2.48.0'}
REFERENCES = ('System.dll', 'System.Core.dll', 'System.Security.dll', 'System.Web.Extensions.dll',
              'System.IO.Compression.dll', 'System.IO.Compression.FileSystem.dll', 'System.ServiceProcess.dll',
              'Microsoft.CSharp.dll', 'System.Windows.Forms.dll', 'System.Drawing.dll')


def windows(tool, output, *, lab=False, signtool=None, certificate=None):
    # The compiler is a build-host dependency, never distributed or invoked on devices.
    reviewed = Path(os.environ['WINDIR']) / 'Microsoft.NET/Framework64/v4.0.30319/csc.exe'
    if tool != reviewed.resolve(strict=True):
        raise ValueError('Use the Windows inbox Framework64 compiler')
    if not lab and not (signtool and certificate):
        raise ValueError('Production requires an Authenticode certificate and SignTool; use --lab only for isolated testing')
    from cloud_soc.portal.windows_native import INPUTS, source_hash
    target = output / 'cloud-soc-agent-setup.exe'
    command = [str(tool), '/nologo', '/target:winexe', '/platform:x64', '/optimize+',
               '/main:CloudSoc.Native.Program', '/out:' + str(target),
               '/win32manifest:' + str(SOURCE / 'native/app.manifest')]
    command += ['/reference:' + name for name in REFERENCES]
    command += ['/resource:' + str(SOURCE / name) + ',' + name for name in
                ('privacy.js', 'site-privacy.js', 'security-catalog.json')]
    command.append('/define:NATIVE_INSTALLER,NATIVE_LAB' if lab else '/define:NATIVE_INSTALLER')
    command += [str(SOURCE / name) for name in INPUTS if name.endswith('.cs')]
    subprocess.run(command, check=True)
    if not lab:
        if not re.fullmatch('[A-Fa-f0-9]{40}', certificate):
            raise ValueError('Certificate thumbprint required; do not pass private keys or passwords')
        signer = str(signtool.resolve(strict=True))
        subprocess.run([signer, 'sign', '/sha1', certificate, '/fd', 'SHA256', '/tr',
                        'http://timestamp.digicert.com', '/td', 'SHA256', str(target)], check=True)
        subprocess.run([signer, 'verify', '/pa', '/all', str(target)], check=True)
    metadata = {'schema': 1, 'target': 'windows-x64-net48', 'version': '1.0.0',
                'mode': 'lab' if lab else 'production', 'signed': not lab,
                'source_sha256': source_hash(SOURCE), 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}
    (output / 'release.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    return target, metadata


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=VERSIONS)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--lab', action='store_true', help='Separate unsigned Windows artifact; private-IP test endpoints only')
    parser.add_argument('--signtool', type=Path)
    parser.add_argument('--certificate', help='Public signing-certificate SHA-1 thumbprint from Windows certificate store')
    args = parser.parse_args()
    tool = args.tool.resolve(strict=True)
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.target == 'windows':
        target, metadata = windows(tool, output, lab=args.lab, signtool=args.signtool, certificate=args.certificate)
    else:
        if args.lab or args.signtool or args.certificate:
            raise ValueError('Windows-specific build options')
        version = subprocess.run([str(tool), '--version'], check=True, capture_output=True, text=True)
        if not re.search(r'(?<![0-9.])v?' + re.escape(VERSIONS[args.target]) + r'(?![0-9.])', version.stdout + version.stderr):
            raise ValueError('Build tool version differs from the reviewed pin')
        spec = {'name': 'cloud-soc-agent-manager', 'arch': 'all', 'platform': 'linux', 'version': '1.0.0',
            'maintainer': 'Cloud SOC maintainers', 'description': 'Cloud SOC device installation and local management',
            'license': 'See bundled project notices', 'depends': ['python3', 'openssl', 'curl', 'tar', 'util-linux', 'file'],
            'scripts': {'preremove': str(SOURCE / 'packaging/preremove')},
            'contents': [
                {'src': str(SOURCE / 'bootstrap-linux.py'), 'dst': '/usr/lib/cloud-soc-agent-manager/bootstrap-linux.py', 'file_info': {'mode': 420}},
                {'src': str(SOURCE / 'packaging/soc-agent'), 'dst': '/usr/bin/soc-agent', 'file_info': {'mode': 493}},
            ]}
        config = output / 'nfpm.json'
        config.write_text(json.dumps(spec), encoding='utf-8')
        target = output / 'cloud-soc-agent-manager.deb'
        subprocess.run([str(tool), 'package', '--config', str(config), '--packager', 'deb', '--target', str(target)], check=True)
    print(json.dumps({'artifact': str(target), 'tool_version': VERSIONS[args.target], 'signed': metadata['signed'] if args.target == 'windows' else False,
                      'installed': False, 'device_registered': False}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
