#!/usr/bin/env python3
"""Read-only physical page summaries. Never emit bucket names, keys or values."""
import hashlib
import json
from pathlib import Path
import struct

SOURCE = Path('/var/tmp/cloud-soc-containerd-9UFBiZ/io.containerd.metadata.v1.bolt/meta.db')
EXPECTED = '1f328d4629035a07d93d33028e332fe9be741ef3579109f06e3ef5083051ccbe'
if SOURCE.stat().st_size > 512*1024*1024:
    raise SystemExit('Unexpected database size; no changes performed.')
data = SOURCE.read_bytes()
if hashlib.sha256(data).hexdigest() != EXPECTED:
    raise SystemExit('Backup checksum changed; no changes performed.')
page_size = struct.unpack_from('<I',data,24)[0]
if page_size < 1024 or page_size > 65536 or page_size & (page_size-1):
    raise SystemExit('Invalid page size.')
metas = [struct.unpack_from('<IIIIQQQQQQ',data,i*page_size+16) for i in (0,1)]
limit = min(max(m[7] for m in metas), len(data)//page_size)


def leaf(page):
    offset = page*page_size
    pid, flags, count, overflow = struct.unpack_from('<QHHI',data,offset)
    end = offset+(overflow+1)*page_size
    if pid != page or flags != 2 or end > len(data) or count > (end-offset-16)//16:
        return None
    entries = []
    for i in range(count):
        at = offset+16+i*16
        item_flags, pos, ksize, vsize = struct.unpack_from('<IIII',data,at)
        key_at = at+pos
        value_at = key_at+ksize
        if key_at < offset+16+count*16 or value_at+vsize > end:
            return None
        root = struct.unpack_from('<Q',data,value_at)[0] if item_flags & 1 and vsize >= 16 else None
        entries.append({'key':data[key_at:value_at], 'bucket':bool(item_flags & 1),
                        'value_bytes':vsize, 'bucket_root':root})
    return entries

root_page = metas[0][4] if metas[0][8] >= metas[1][8] else metas[1][4]
current = leaf(root_page)
if not current:
    raise SystemExit('Current root is not a valid leaf; no changes performed.')
summary = [{k:v for k,v in entry.items() if k != 'key'} for entry in current]
for entry in summary:
    entry['self_reference'] = entry['bucket_root'] == root_page
print(json.dumps({'checksum_verified':True,'page_size':page_size,'page_limit':limit,
                  'root_page':root_page,'root_entries':summary}))
keys = [entry['key'] for entry in current]
candidates = []
for page in range(2,limit):
    entries = leaf(page)
    if not entries or [entry['key'] for entry in entries] != keys:
        continue
    if not all(entry['bucket'] and entry['bucket_root'] is not None for entry in entries):
        continue
    roots = [entry['bucket_root'] for entry in entries]
    if all((root == 0 or 2 <= root < limit) and root != page for root in roots):
        candidates.append({'page':page,'child_roots':roots,
                           'has_inline_bucket':any(root == 0 for root in roots)})
print(json.dumps({'candidate_count':len(candidates),'candidate_root_pages':candidates}))
print('Read-only structure scan complete. Candidates are not yet validated or applied.')
