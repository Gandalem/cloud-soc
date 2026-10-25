"""Build common installer artifacts with locally supplied, pinned tools. Never downloads/runs installers."""
import argparse
import json
from pathlib import Path
import subprocess
import sys

SOURCE = Path(__file__).resolve().parents[1]
VERSIONS = {'windows': '3.13', 'ubuntu': '2.48.0'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('target', choices=VERSIONS)
    parser.add_argument('--tool', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    tool = args.tool.resolve(strict=True)
    version = subprocess.run([str(tool), '/VERSION' if args.target == 'windows' else '--version'],
                             check=True, capture_output=True, text=True)
    import re
    if not re.search(r'(?<![0-9.])v?' + re.escape(VERSIONS[args.target]) + r'(?![0-9.])', version.stdout + version.stderr):
        raise ValueError('Build tool version differs from the reviewed pin')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    if args.target == 'windows':
        target = output / 'cloud-soc-agent-setup.exe'
        subprocess.run([str(tool), '/DSOURCE=' + str(SOURCE), '/DOUTFILE=' + str(target),
                        str(SOURCE / 'packaging/agent.nsi')], check=True)
    else:
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
    print(json.dumps({'artifact': str(target), 'tool_version': VERSIONS[args.target], 'signed': False,
                      'installed': False, 'device_registered': False}))
    return 0


if __name__ == '__main__':
    sys.exit(main())
