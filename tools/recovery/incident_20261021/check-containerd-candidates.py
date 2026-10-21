#!/usr/bin/env python3
"""Build/check independent recovery candidates. Never replace live containerd files."""
import hashlib
import json
import os
from pathlib import Path
import re
import resource
import subprocess
import tempfile

OUTPUTS=Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent/outputs')
BACKUP=Path('/var/tmp/cloud-soc-containerd-9UFBiZ')
SOURCE=BACKUP/'io.containerd.metadata.v1.bolt/meta.db'
EXPECTED='1f328d4629035a07d93d33028e332fe9be741ef3579109f06e3ef5083051ccbe'
PAGES=(599,616,683,727,734,735,746,747,753,755)
if os.geteuid()!=0:
    raise SystemExit('Run with sudo python3.')
resource.setrlimit(resource.RLIMIT_CORE,(0,0))
if hashlib.sha256(SOURCE.read_bytes()).hexdigest()!=EXPECTED:
    raise SystemExit('Backup checksum changed; no candidate created.')
for name in ('dockerd','containerd'):
    if subprocess.run(['pgrep','-x',name],capture_output=True).returncode==0:
        raise SystemExit('Runtime processes are active; no candidate created.')
tools=next((p for p in (Path('/tmp/cloud-soc-bbolt.m3thsu'),Path('/tmp/cloud-soc-bbolt.fAeMez'))
            if (p/'go/bin/go').is_file() and (p/'bin/bbolt').is_file()),None)
if tools is None:
    raise SystemExit('Previously verified bbolt toolkit was not found.')
run=Path(tempfile.mkdtemp(prefix='bbolt-candidates-',dir=BACKUP))
run.chmod(0o700)
print('candidate_directory='+str(run),flush=True)
env={**os.environ,'GOTOOLCHAIN':'local','GOMODCACHE':str(tools/'modules'),'GOCACHE':str(tools/'cache'),'GOWORK':'off'}
module=tools/'modules/go.etcd.io/bbolt@v1.4.3'
compiled=subprocess.run([str(tools/'go/bin/go'),'build','-o',str(run/'inventory'),str(OUTPUTS/'containerd-inventory.go')],
                        cwd=module,env=env,capture_output=True,text=True,timeout=180)
if compiled.returncode:
    (run/'build.private.log').write_text(compiled.stdout+compiled.stderr)
    raise SystemExit('Inventory build failed; private build log retained; no live changes.')
known={hashlib.sha256(p.name.encode()).hexdigest() for p in Path('/var/lib/docker/containers').glob('*')
       if p.is_dir() and re.fullmatch('[0-9a-f]{64}',p.name)}
report={'source_sha256':EXPECTED,'known_docker_container_count':len(known),'candidates':[]}
for page in PAGES:
    stage=run/f'root-{page}-stage.db';candidate=run/f'root-{page}.db'
    row={'root_page':page}
    try:
        for meta,source,target in ((0,SOURCE,stage),(1,stage,candidate)):
            result=subprocess.run([str(tools/'bin/bbolt'),'surgery','meta','update',str(source),
                '--meta-page',str(meta),'--fields',f'root:{page}','--output',str(target)],
                capture_output=True,text=True,timeout=20)
            if result.returncode:raise RuntimeError('candidate_creation_failed')
            target.chmod(0o600)
        checked=subprocess.run([str(tools/'bin/bbolt'),'check',str(candidate)],capture_output=True,text=True,timeout=20)
        (run/f'root-{page}.private.log').write_text(checked.stdout+checked.stderr)
        if checked.returncode!=0 or checked.stdout.strip()!='OK':
            row.update(status='check_failed',problem_pages=sorted(set(int(n) for n in re.findall(r'page (\d+)',checked.stdout+checked.stderr))))
        else:
            result=subprocess.run([str(run/'inventory'),str(candidate)],capture_output=True,text=True,timeout=15)
            if result.returncode:raise RuntimeError('containerd_inventory_failed')
            inventory=json.loads(result.stdout)
            hashes=set(inventory.pop('container_id_hashes'))
            row.update(status='check_ok',inventory=inventory,
                matched_docker_containers=len(hashes&known),candidate_sha256=hashlib.sha256(candidate.read_bytes()).hexdigest())
    except subprocess.TimeoutExpired:
        row['status']='candidate_check_timed_out'
    except Exception:
        row['status']='candidate_validation_failed'
    report['candidates'].append(row)
    print(json.dumps(row),flush=True)
    (run/'report.json').write_text(json.dumps(report,indent=2))
print('report='+str(run/'report.json'))
print('No candidate was selected or installed. Live metadata, images, snapshots and volumes were not changed.')
