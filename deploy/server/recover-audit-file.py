"""Validate recovery of a masked audit record against its original file generation."""
import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'src'))
from cloud_soc.portal.log_contract import field  # noqa: E402
from cloud_soc.processing.contract import normalize  # noqa: E402
from cloud_soc.privacy import REDACTED  # noqa: E402


def verify_file(file, hits, source_identity):
    """Match the registered file identity and verify retained lines as anchors."""
    fields = ('organization.id', 'host.id', 'agent.id', 'log.file.path', 'log.file.inode', 'log.file.device_id')
    if not isinstance(source_identity, dict) or set(source_identity) != set(fields):
        raise ValueError('original_file_identity_required')
    mandatory = fields[:-1]
    if any(source_identity[key] in (None, '') for key in mandatory):
        raise ValueError('original_file_identity_incomplete')
    verified = []
    anchors = set()
    for hit in hits:
        source = hit.get('_source', {})
        tag = field(source, 'labels.log_source')
        if tag not in ('eks_audit', 'linux_auditd') or any(field(source, key) != source_identity[key] for key in fields):
            raise ValueError('original_file_identity_mismatch')
        offset = field(source, 'log.offset')
        if type(offset) is not int or offset < 0:
            raise ValueError('invalid_file_offset')
        if offset:
            file.seek(offset - 1)
            if file.read(1) != b'\n':
                raise ValueError('offset_not_at_line_start')
        file.seek(offset)
        line = file.readline(262146)
        if not line or len(line) > 262145:
            raise ValueError('invalid_original_line')
        original = line.rstrip(b'\r\n').decode('utf-8')
        retained = source.get('message')
        if isinstance(retained, str) and retained and retained != REDACTED:
            if retained != original:
                raise ValueError('retained_line_anchor_mismatch')
            anchors.add(offset)
        else:
            verified.append((hit, original))
    if len(anchors) < 3:
        raise ValueError('at_least_three_retained_anchors_required')
    return verified, len(anchors)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--original', type=Path, required=True)
    parser.add_argument('--identity', type=Path, required=True)
    parser.add_argument('--hits', type=Path, required=True, help='Private JSONL export of exact raw ES hits, including retained anchors')
    parser.add_argument('--processed-at', required=True)
    args = parser.parse_args()
    identity = json.loads(args.identity.read_text(encoding='utf-8'))
    hits = [json.loads(line) for line in args.hits.read_text(encoding='utf-8').splitlines() if line]
    counts = Counter()
    with args.original.open('rb') as file:
        verified, anchors = verify_file(file, hits, identity)
        file.seek(0)
        digest = hashlib.file_digest(file, 'sha256').hexdigest()
    for hit, original in verified:
        recovered = {**hit, '_source': {**hit['_source'], 'message': original}}
        _, record, _ = normalize(recovered, args.processed_at)
        counts[record['status']] += 1
    print(json.dumps({'anchors': anchors, 'matched_by_offset': len(verified), 'file_sha256': digest, 'counts': counts}))


if __name__ == '__main__':
    main()
