"""Explicit local switches for a new unified installation; keys/registry untouched."""
import argparse
import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import fcntl

ROOT = Path('/opt/cloud-soc-agent')


def private(path):
    for p in [path, *path.parents]:
        info=p.lstat()
        if stat.S_ISLNK(info.st_mode) or info.st_uid!=0 or info.st_mode & 0o022:
            raise ValueError('Untrusted collection configuration')


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=['system','web','network'])
    parser.add_argument('enabled', choices=['on','off'])
    parser.add_argument('--site', help='An existing site ID; required for web')
    args=parser.parse_args()
    if os.geteuid()!=0:raise ValueError('Run as root')
    private(ROOT)
    lock=os.open(ROOT/'discovery.lock',os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600)
    private(ROOT/'discovery.lock')
    fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
    path=ROOT/'collection-profile.json'; private(path)
    profile=json.loads(path.read_text()); enabled=args.enabled=='on'
    switches=ROOT/'collection-switches.json'
    if switches.exists() or switches.is_symlink():private(switches)
    data=json.loads(switches.read_text()) if switches.exists() else {}
    if not isinstance(data,dict) or set(data)-{'system','web','network'}:raise ValueError('Unknown local switches')
    if profile.get('schema')!=1:raise ValueError('Unknown collection profile')
    if args.kind=='web':
        selected=[x for x in profile['web_inputs'] if x['id']=='cloud-soc-site-'+(args.site or '')]
        if len(selected)!=1:raise ValueError('Select exactly one configured site ID')
        data.setdefault('web',{})[args.site]=enabled
    elif args.kind=='network':
        if profile.get('network') is not True:raise ValueError('Network was not selected in this installation; existing unrelated collectors are not adopted')
        if not Path('/opt/cloud-soc-network/packetbeat.yml').is_file():raise ValueError('Network collector was not installed; create an approved network package first')
        result=subprocess.run(['systemctl','enable' if enabled else 'disable','--now','cloud-soc-packetbeat'],check=False,capture_output=True)
        if result.returncode:raise ValueError('Network service switch failed')
        data['network']=enabled
    else:
        data['system']=enabled
    fd, name=tempfile.mkstemp(prefix='.collection-', dir=ROOT)
    try:
        with os.fdopen(fd,'w') as stream:
            json.dump(data,stream); stream.flush(); os.fsync(stream.fileno())
        private(path); os.replace(name,switches)
    finally:
        if Path(name).exists():Path(name).unlink()
        os.close(lock)
    # Dynamic input reload preserves queues and registry. No Filebeat restart.
    subprocess.run(['systemctl','start','cloud-soc-discovery.service'],check=True)
    print('Collection switch applied; verify fresh central receipt separately.')


if __name__=='__main__':main()
