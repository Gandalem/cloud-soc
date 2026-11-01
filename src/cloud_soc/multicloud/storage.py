"""Durable checkpoints advance only after acknowledged deterministic ES writes."""
import hashlib
import json
from pathlib import Path
import sqlite3
from elasticsearch import ConflictError, NotFoundError

from .normalize import normalize


class State:
    def __init__(self, path, scope):
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path)
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.execute('PRAGMA synchronous=FULL')
        self.db.execute('CREATE TABLE IF NOT EXISTS state (key TEXT PRIMARY KEY, value TEXT NOT NULL)')
        fingerprint = hashlib.sha256(json.dumps(scope, sort_keys=True).encode()).hexdigest()
        old = self.get('scope')
        if old and old != fingerprint:
            self.db.close()
            raise ValueError('Checkpoint scope mismatch; use a separate state file')
        self.put('scope', fingerprint)

    def get(self, key):
        row = self.db.execute('SELECT value FROM state WHERE key=?', (key,)).fetchone()
        return row[0] if row else None

    def put(self, key, value):
        with self.db:
            self.db.execute('INSERT INTO state VALUES (?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', (key, str(value)))

    def close(self):
        self.db.close()


class Sink:
    def __init__(self, es, scope):
        self.es, self.scope = es, scope

    def write(self, provider, raw):
        index, identifier, doc = normalize(provider, raw, self.scope)
        try:
            self.es.create(index=index, id=identifier, document=doc)
        except ConflictError:
            pass


TEMPLATE_NAME = 'soc-multicloud-v1'
INDEX_PATTERN = 'soc-multicloud-*'


def template_body():
    return {'settings': {'number_of_shards': 1, 'number_of_replicas': 0},
        'mappings': {'dynamic': 'strict', '_meta': {'cloud_soc': TEMPLATE_NAME}, 'properties': {
            '@timestamp': {'type': 'date'}, 'ecs': {'properties': {'version': {'type': 'keyword'}}},
            'organization': {'properties': {'id': {'type': 'keyword'}}},
            'cloud': {'properties': {'provider': {'type': 'keyword'}, 'region': {'type': 'keyword'}, 'account': {'properties': {'id': {'type': 'keyword'}}}}},
            'event': {'properties': {**{k: {'type': 'keyword'} for k in ('id','dataset','kind','category','type','action','outcome','provider')}, 'ingested': {'type': 'date'}}},
            'user': {'properties': {'id': {'type': 'keyword'}}}, 'resource': {'properties': {'id': {'type': 'keyword'}}},
            'source': {'properties': {'ip': {'type': 'ip'}}},
            'soc': {'properties': {'schema_version': {'type': 'integer'}, 'collector_id': {'type': 'keyword'}}}
        }}}


def inspect_template(es):
    try:
        entries = es.indices.get_index_template(name=TEMPLATE_NAME)['index_templates']
    except NotFoundError:
        return {'name': TEMPLATE_NAME, 'state': 'missing'}
    if len(entries) != 1 or entries[0]['name'] != TEMPLATE_NAME:
        raise ValueError('Unexpected multicloud template identity')
    current = entries[0]['index_template']
    mappings = current.get('template', {}).get('mappings', {})
    if (current.get('index_patterns') != [INDEX_PATTERN]
            or mappings.get('dynamic') != 'strict'
            or mappings.get('properties') != template_body()['mappings']['properties']
            or mappings.get('_meta', {}).get('cloud_soc') not in (None, TEMPLATE_NAME)):
        raise ValueError('Multicloud template conflict; existing definition preserved')
    return {'name': TEMPLATE_NAME, 'state': 'compatible', 'definition': current}


def install(es):
    inspect_template(es)
    # This changes only the future-index template, never existing data/settings.
    es.indices.put_index_template(name=TEMPLATE_NAME, index_patterns=[INDEX_PATTERN], priority=250,
        template=template_body(), meta={'cloud_soc': TEMPLATE_NAME})
