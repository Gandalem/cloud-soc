"""Inspect extraction APIs and archived checkpoint headers; do not mutate indices."""
import hashlib
import json
import os
from pathlib import Path
import pwd
import struct
import subprocess
import tempfile

BASE = Path('/home/lyn/Documents/Codex/2026-10-21/cd-ubuntu-school-web-agent')
ARCHIVE = Path('/var/tmp/cloud-soc-raw21-check-2tq8dgn7')


def main():
    if os.geteuid() != 0:
        raise ValueError('Root required')
    os.umask(0o077)
    shard = ARCHIVE / 'archive-shard'
    expected = json.loads((ARCHIVE / 'manifest.json').read_text())
    verified = all((shard / name).is_file() and
                   hashlib.sha256((shard / name).read_bytes()).hexdigest() == digest
                   for name, digest in expected.items())
    if not verified:
        raise ValueError('Archived source hash mismatch')
    signatures = {}
    classes = ['org.elasticsearch.index.translog.TranslogReader',
        'org.elasticsearch.index.translog.Checkpoint',
        'org.elasticsearch.index.translog.TranslogSnapshot',
        'org.elasticsearch.index.translog.Translog',
        'org.elasticsearch.index.translog.Translog$Operation',
        'org.elasticsearch.index.translog.Translog$Index',
        'org.elasticsearch.index.translog.Translog$Delete',
        'org.elasticsearch.index.translog.Translog$Snapshot',
        'org.elasticsearch.index.translog.TranslogHeader',
        'org.elasticsearch.common.compress.CompressorFactory',
        'org.elasticsearch.index.mapper.Uid',
        'org.apache.lucene.index.CheckIndex']
    for cls in classes:
        p = subprocess.run(['docker', 'exec', 'cloud-soc-central-elasticsearch-1',
            '/usr/share/elasticsearch/jdk/bin/javap', '-p', '-classpath',
            '/usr/share/elasticsearch/lib/*', cls], capture_output=True, text=True, timeout=15)
        signatures[cls] = {'exit_code': p.returncode, 'text': p.stdout + p.stderr}
    checkpoint = (shard / 'translog/translog.ckp').read_bytes()
    tlog = shard / 'translog/translog-430.tlog'
    header = {'checkpoint_bytes': len(checkpoint), 'checkpoint_hex': checkpoint.hex(),
              'tlog_bytes': tlog.stat().st_size, 'tlog_sha256': hashlib.sha256(tlog.read_bytes()).hexdigest()}
    # A compound footer has fixed metadata, not source message text.
    damaged = shard / 'index/_768.cfs'
    with damaged.open('rb') as stream:
        stream.seek(-16, 2)
        header['damaged_compound_footer_hex'] = stream.read(16).hex()
    report = {'archive_verified': verified, 'archive_directory': str(ARCHIVE),
              'headers': header, 'api_signatures': signatures,
              'no_operations_replayed': True}
    fd, name = tempfile.mkstemp(prefix='translog-salvage-inspection-', suffix='.json', dir=BASE / 'work')
    with os.fdopen(fd, 'w') as stream:
        json.dump(report, stream, indent=2)
    owner = pwd.getpwnam('lyn')
    os.chown(name, owner.pw_uid, owner.pw_gid)
    print(json.dumps({'archive_verified': verified, 'translog_bytes': header['tlog_bytes'],
                      'api_inspection_success': all(v['exit_code'] == 0 for v in signatures.values()),
                      'private_report': name, 'operating_indices_changed': False}))


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'inspection_stopped': type(error).__name__}))
        raise SystemExit(1)
