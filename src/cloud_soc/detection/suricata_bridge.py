"""Independent forward-only EVE alert -> immutable alert -> idempotent case bridge.

Slack is owned by the existing notifier; this worker never reads webhook secrets.
"""
from contextlib import closing
from copy import deepcopy
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import time
import uuid

from cloud_soc.detection.engine import detect_rule, event_evidence, rule_revision
from cloud_soc.detection.rule_loader import load_rules
from cloud_soc.pipeline.alerts import build_security_alert, make_alert_id
from cloud_soc.elastic.repository import save_security_alert
from cloud_soc.portal.agent_status import parse_time
from cloud_soc.portal.cases import CaseStore, CaseError
from cloud_soc.portal.log_contract import field, document_reference
from cloud_soc.portal.operations import alert_row
from cloud_soc.processing.contract import NORMALIZED

ACTOR = 'suricata-automation'
RULE_IDS = ('IDS-SURICATA-HIGH-001', 'IDS-SURICATA-MEDIUM-001',
            'IDS-SURICATA-LOW-001', 'IDS-SURICATA-TEST-001')


def rules(workspace):
    rows = load_rules(Path(workspace) / 'rules/suricata.yml', enabled_only=False)
    if tuple(r['id'] for r in rows) != RULE_IDS or any(not r['enabled'] for r in rows):
        raise ValueError('suricata_rule_inventory_invalid')
    return rows


def validate_policy(workspace, value):
    configured = value.get('suricata_bridge')
    expected = {r['id']: rule_revision(r) for r in rules(workspace)}
    if configured != {'version': 1, 'rules': expected, 'start': 'baseline_new_documents_only'}:
        raise ValueError('suricata_rules_not_pinned')


def complete(response):
    if (response.get('timed_out') or response.get('terminated_early')
            or response.get('_shards', {}).get('failed', 0)):
        raise ValueError('suricata_search_incomplete')
    return response


class Source:
    def __init__(self, client):
        self.client = client

    def shards(self):
        found = self.client.indices.resolve_index(name=NORMALIZED)
        if (found.get('aliases') or found.get('data_streams')
                or [r['name'] for r in found.get('indices', [])] != [NORMALIZED]):
            raise ValueError('suricata_index_scope_changed')
        settings = self.client.indices.get_settings(index=NORMALIZED, flat_settings=True)
        if set(settings) != {NORMALIZED}:
            raise ValueError('suricata_index_scope_changed')
        cfg = settings[NORMALIZED]['settings']
        count = int(cfg['index.number_of_shards'])
        if not 1 <= count <= 32:
            raise ValueError('suricata_shard_budget_exceeded')
        return cfg['index.uuid'], list(range(count))

    def page(self, shard, after, baseline=False):
        result = complete(self.client.search(index=NORMALIZED, preference='_shards:' + str(shard),
            size=1 if baseline else 100, seq_no_primary_term=True,
            allow_partial_search_results=False,
            query={'match_all': {}} if baseline else {'range': {'_seq_no': {'gt': after}}},
            sort=[{'_seq_no': 'desc' if baseline else 'asc'}],
            source=False if baseline else True))
        return result['hits']['hits']


def process(client, cases, hit, selected):
    """One replay-safe unit. Case failure blocks checkpoint; ES conflicts are safe."""
    if hit.get('_index') != NORMALIZED or not isinstance(hit.get('_id'), str):
        raise ValueError('suricata_normalized_reference_invalid')
    event = deepcopy(hit.get('_source', {}))
    if field(event, 'cloud_soc.detail.adapter') != 'suricata_eve_v1':
        return 0
    if field(event, 'event.kind') != 'alert' or field(event, 'event.dataset') != 'suricata.eve':
        return 0
    # Only the reviewed adapter contract can supply evidence or identity.
    if (field(event, 'cloud_soc.normalizer_version') != 'suricata-eve-v1'
            or not isinstance(field(event, 'host.id'), str) or not field(event, 'host.id')
            or not parse_time(event.get('@timestamp'))):
        raise ValueError('suricata_normalized_contract_invalid')
    event['_cloud_soc_meta'] = {'index': NORMALIZED, 'document_id': hit['_id']}
    if not event_evidence(event)['complete']:
        raise ValueError('suricata_evidence_missing')
    raw = field(event, 'cloud_soc.provenance.raw')
    document_reference(raw['index'], raw['id'])
    if not raw['index'].startswith('soc-host-raw-'):
        raise ValueError('suricata_raw_scope_invalid')
    count = 0
    for rule in selected:
        for detection in detect_rule([event], rule):
            # Raw evidence anchors identity across equivalent normalized replays.
            detection['identity_anchor'] = field(event, 'cloud_soc.provenance.raw')
            identifier = make_alert_id(detection)
            document = build_security_alert(detection)
            document['host'] = {'id': field(event, 'host.id')}
            document['cloud_soc']['provenance']['sensor'] = {
                'signature_id': field(event, 'rule.id'),
                'severity': field(event, 'suricata.eve.alert.severity'),
                'type': 'ids', 'product': 'Suricata'}
            result = save_security_alert(client, document, index_name='security-alerts',
                document_id=identifier, refresh=False, index_prepared=True)
            if result.get('result') not in ('created', 'existing'):
                raise ValueError('suricata_alert_write_incomplete')
            token = str(uuid.uuid5(uuid.NAMESPACE_URL, 'cloud-soc-suricata-case:' + identifier))
            try:
                cases.create({'title': document['cloud_soc']['alert_title'], 'alert_id': identifier,
                              'priority': rule['severity']}, ACTOR, token,
                             lambda _: alert_row({'_id': identifier, '_source': document}))
            except CaseError as error:
                if error.code != 'alert_already_linked' or not cases.lookup(identifier, ACTOR)['case_id']:
                    raise
            count += 1
    return count


def cycle(client, cases, path, selected, source=None):
    source = source or Source(client)
    identity = hashlib.sha256(json.dumps({r['id']: rule_revision(r) for r in selected},
                                        sort_keys=True).encode()).hexdigest()
    counts = {'scanned': 0, 'matched': 0, 'baseline': 0}
    with closing(sqlite3.connect(path, timeout=5)) as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.execute('PRAGMA synchronous=FULL')
        db.executescript('''CREATE TABLE IF NOT EXISTS config(id INTEGER PRIMARY KEY, identity TEXT);
            CREATE TABLE IF NOT EXISTS cursors(shard INTEGER PRIMARY KEY, uuid TEXT, seq INTEGER);''')
        db.execute('BEGIN IMMEDIATE')
        saved = db.execute('SELECT identity FROM config WHERE id=1').fetchone()
        if saved and saved[0] != identity:
            raise ValueError('suricata_rule_change_requires_explicit_migration')
        db.execute('INSERT OR IGNORE INTO config VALUES(1,?)', (identity,))
        index_uuid, shards = source.shards()
        for shard in shards:
            cursor = db.execute('SELECT uuid,seq FROM cursors WHERE shard=?', (shard,)).fetchone()
            if cursor and cursor[0] != index_uuid:
                raise ValueError('suricata_index_replaced')
            baseline = cursor is None
            seq = cursor[1] if cursor else -1
            hits = source.page(shard, seq, baseline)
            if len(hits) > (1 if baseline else 100):
                raise ValueError('suricata_page_budget_exceeded')
            for hit in hits:
                number = hit.get('_seq_no')
                if type(number) is not int or number < 0 or (not baseline and number <= seq):
                    raise ValueError('suricata_sequence_invalid')
                if not baseline:
                    counts['matched'] += process(client, cases, hit, selected)
                    counts['scanned'] += 1
                seq = number
            counts['baseline'] += int(baseline)
            db.execute('INSERT INTO cursors VALUES(?,?,?) ON CONFLICT(shard) DO UPDATE SET seq=excluded.seq',
                       (shard, index_uuid, seq))
        db.commit()
    return counts


def main():
    from elasticsearch import Elasticsearch
    from cloud_soc.aws.__main__ import protected_key
    from cloud_soc.deployment.contract import digest, policy
    workspace = Path(__file__).resolve().parents[3]
    release = policy(workspace)
    validate_policy(workspace, release)
    contract = json.loads(Path('/run/runtime/contract.json').read_text())
    if not contract.get('prepared') or contract.get('policy_sha256') != digest(release):
        raise ValueError('suricata_runtime_not_prepared')
    state = Path('/bridge')
    if state.is_symlink() or not state.is_dir():
        raise ValueError('suricata_state_directory_missing')
    os.umask(0o077)
    # Dedicated actor recorded in existing case history; no human impersonation.
    cases = CaseStore('/cases/cases.sqlite', ACTOR)
    selected = rules(workspace)
    with Elasticsearch('https://elasticsearch:9200',
            api_key=protected_key('/run/keys/worker.key'), ca_certs='/run/certs/ca.crt',
            request_timeout=15, max_retries=0) as client:
        while True:
            try:
                print('suricata_bridge_success ' + json.dumps(cycle(
                    client, cases, state / 'cursor.sqlite', selected)), flush=True)
            except Exception as error:
                # Never expose webhook, credentials, raw payloads or URLs in errors.
                print('suricata_bridge_failed type=' + type(error).__name__ + '; cursor retained', flush=True)
            time.sleep(10)


if __name__ == '__main__':
    try:
        main()
    except Exception as error:
        raise SystemExit('suricata_bridge_configuration_failed type=' + type(error).__name__) from None
