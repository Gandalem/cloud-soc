"""Read a pinned 7-B SQLite snapshot; never run processors or open its DB writable."""
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import stat

from cloud_soc.correlation.security_mall import Scope, reference, require, select_alert
from cloud_soc.correlation.store import encode
from cloud_soc.detection.engine import event_fingerprint
from cloud_soc.triage.engine import time_range
from cloud_soc.triage.policy import Policy, VERSION

FACTORS = frozenset({'existing_detection_risk', 'repeated_independent_application_denials',
    'authentication_sequence_already_in_base_risk', 'additional_streams_change_confidence_not_risk'})
UNCERTAINTIES = frozenset({'request_id_not_origin_authentication', 'application_id_may_be_spoofed',
    'observed_ip_may_be_proxy', 'correlation_not_compromise_confirmation', 'raw_contents_not_reverified_by_triage',
    'missing_streams', 'missing_streams_not_proof_of_absence', 'ambiguous_request_id', 'delayed_evidence',
    'receipt_precedes_event_clock_uncertainty', 'evidence_missing_or_integrity_unverified',
    'request_id_reused_multiple_web_events_no_join',
    'same_id_reuse_within_window_cannot_be_excluded'})


def private_bytes(path, limit):
    path = Path(path)
    require(path.is_absolute(), 'snapshot_path_invalid')
    for part in (path, *path.parents):
        info = part.lstat()
        require(not stat.S_ISLNK(info.st_mode) and not getattr(info, 'st_file_attributes', 0) &
                getattr(stat, 'FILE_ATTRIBUTE_REPARSE_POINT', 0), 'snapshot_link_forbidden')
    for part in (path, path.parent):
        info = part.stat()
        if os.name == 'posix':
            require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'snapshot_private_required')
    fd = os.open(path, os.O_RDONLY | getattr(os, 'O_NOFOLLOW', 0) | getattr(os, 'O_BINARY', 0))
    with os.fdopen(fd, 'rb') as stream:
        info = os.fstat(stream.fileno())
        if os.name == 'posix':
            require(info.st_uid == os.getuid() and not info.st_mode & 0o077, 'snapshot_private_required')
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit,
                'snapshot_file_invalid')
        data = stream.read(limit + 1)
        require(len(data) == info.st_size, 'snapshot_changed')
    return data


class MallInvestigation:
    """One immutable, server-selected scope/time frame. Browser input cannot select it.

    A pinned offline snapshot is deliberate: it has no live refresh or ES authority.
    Existing Operations.evidence rechecks alert evidence before returning this summary.
    """
    def __init__(self, config, mall_scope):
        require(set(config) == {'database', 'sha256', 'scope', 'start', 'end'}, 'snapshot_config_invalid')
        scope = dict(config['scope'])
        for key in ('normalized_indices', 'app_indices', 'edge_indices', 'alert_indices'):
            require(isinstance(scope.get(key), list), 'snapshot_scope_invalid')
            scope[key] = tuple(scope[key])
        self.scope = Scope(**scope)
        require(mall_scope is not None and self.scope.service == 'security-mall' and
                self.scope.alert_indices == (mall_scope['alerts'],), 'snapshot_alert_scope_invalid')
        policy = Policy()
        frame_range = time_range(config['start'], config['end'], policy)
        data = private_bytes(config['database'], 32 * 1024 * 1024)
        require(isinstance(config['sha256'], str) and re.fullmatch('[0-9a-f]{64}', config['sha256']) and
                hashlib.sha256(data).hexdigest() == config['sha256'], 'snapshot_digest_mismatch')
        db = sqlite3.connect(':memory:')
        try:
            require(hasattr(db, 'deserialize'), 'snapshot_sqlite_deserialize_required')
            db.deserialize(data)
            db.execute('PRAGMA query_only=ON')
            binding = encode({'version': VERSION, 'scope': asdict(self.scope), 'policy_id': policy.identity})
            require(db.execute("SELECT value FROM settings WHERE key='binding'").fetchone() == (binding,),
                    'snapshot_binding_mismatch')
            frame_id = event_fingerprint([VERSION, self.scope.identity, frame_range])
            row = db.execute('SELECT sequence,revision,document FROM frames WHERE id=?', (frame_id,)).fetchone()
            require(row is not None and len(row[2]) <= 16 * 1024 * 1024, 'snapshot_frame_missing')
            frame = json.loads(row[2])
            require(frame['version'] == VERSION and frame['schema_version'] == 1 and
                    frame['scope'] == self.scope.identity and frame['range'] == frame_range and
                    frame['policy_id'] == policy.identity and frame['correlation_revision'] == row[1] and
                    frame['revision_order']['sequence'] == row[0], 'snapshot_frame_invalid')
            require(db.execute("SELECT value FROM settings WHERE key='publisher'").fetchone() ==
                    (frame['revision_order']['publisher_id'],), 'snapshot_publisher_invalid')
            require(isinstance(frame['items'], list) and len(frame['items']) <= self.scope.max_events,
                    'snapshot_capacity_invalid')
            self.frame = frame
        finally:
            db.close()

    @classmethod
    def from_file(cls, path, mall_scope):
        return cls(json.loads(private_bytes(path, 16384)), mall_scope) if path else None

    def detail(self, principal, index, identifier, source, verify):
        absent = {'state': 'unavailable'}
        if not self.scope.visible(principal):
            return absent
        try:
            alert = select_alert({'_index': index, '_id': identifier, '_source': source}, self.scope)
            matches = [i for i in self.frame['items'] if alert['alert'] in i['linked_alert_ids']]
            if not matches:
                return {'state': 'not_found'}
            require(len(matches) == 1, 'snapshot_duplicate_alert')
            item = matches[0]
            require(item['scope'] == self.scope.identity and item['range'] == self.frame['range'] and
                    item['linked_alert_ids'] == [alert['alert']] and
                    item['correlation_revision'] == self.frame['correlation_revision'] and
                    item['rule_ids'] == [alert['rule_id']] and item['base_risk_score'] == alert['risk_score'] and
                    item['original_severity'] == alert['rule_severity'] and
                    item['original_risk_level'] == alert['risk_level'] and item['occurred_at'] == alert['occurred_at'],
                    'snapshot_alert_changed')
            refs = item['evidence_references']
            require(len(refs) <= self.scope.max_events, 'snapshot_capacity_invalid')
            for ref in refs:
                reference(ref['normalized'], self.scope.normalized_indices)
                reference(ref['raw'], self.scope.app_indices + self.scope.edge_indices)
            expected = {encode(r) for r in alert['evidence']}
            stored = {encode({k: r[k] for k in ('raw', 'normalized', 'event_hash')}) for r in refs}
            require(expected <= stored and len(alert['evidence']) <= 25, 'snapshot_evidence_changed')
            # Same current tenant/hash/raw identity checks as the original evidence API.
            if not all(verify(ref) for ref in source['cloud_soc']['provenance']['evidence']):
                return {'state': 'evidence_unavailable'}
            count = lambda value: type(value) is int and 0 <= value <= self.scope.max_events
            complete = item['evidence_completeness']
            require(complete['state'] in ('complete', 'partial', 'missing', 'ambiguous') and
                    item['evidence_confidence'] in ('limited', 'unverified', 'corroborated_metadata') and
                    type(item['triage_score']) is int and 0 <= item['triage_score'] <= 100 and
                    item['triage_priority'] in ('low', 'medium', 'high', 'critical') and
                    count(item['independent_request_count']) and
                    all(count(complete[k]) for k in ('bundle_count', 'verified_alert_references', 'unresolved_alert_references')),
                    'snapshot_summary_invalid')
            missing = complete['missing_streams']
            require(isinstance(missing, list) and set(missing) <= {'web', 'waf', 'app'}, 'snapshot_stream_invalid')
            factors = item['contributing_factors']
            require(all(f['code'] in FACTORS and type(f['points']) is int and 0 <= f['points'] <= 100
                        for f in factors), 'snapshot_factor_invalid')
            require(set(item['uncertainty_factors']) <= UNCERTAINTIES, 'snapshot_uncertainty_invalid')
            # Do not forward accounts, IPs, raw text, paths, reference locators or arbitrary explanation text.
            return {'state': 'available', 'source': 'validated_snapshot', 'range': self.frame['range'],
                'correlation_revision': item['correlation_revision'],
                'triage_score': item['triage_score'], 'triage_priority': item['triage_priority'],
                'evidence_confidence': item['evidence_confidence'], 'completeness': complete['state'],
                'bundle_count': complete['bundle_count'],
                'independent_request_count': item['independent_request_count'],
                'event_count': len({r['event_id'] for r in refs if r.get('event_id')}),
                'evidence_count': len(refs), 'verified_alert_references': complete['verified_alert_references'],
                'unresolved_alert_references': complete['unresolved_alert_references'],
                'streams': {k: 'observed' if complete['bundle_count'] and k not in missing else 'unconfirmed'
                            for k in ('web', 'waf', 'app')},
                'factors': [{'code': f['code'], 'points': f['points']} for f in factors],
                'uncertainties': item['uncertainty_factors']}
        except (KeyError, TypeError, ValueError):
            return absent
