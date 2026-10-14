"""Read-only ES change scanner and one independent durable Slack sender."""
from contextlib import contextmanager
import json
import os
from pathlib import Path
import re
import time

from cloud_soc.notifications.messages import alert
from cloud_soc.notifications.store import LEVELS, SlackStore
from cloud_soc.notifications.transport import SlackError, send

INDICES = ('security-alerts', 'soc-alert-notices-v1')
READ_ROLE = {'cluster': [], 'indices': [{'names': list(INDICES), 'privileges': ['read', 'view_index_metadata']}]}


def complete(response):
    if response.get('timed_out') or response.get('terminated_early') or response.get('_shards', {}).get('failed', 0):
        raise SlackError('notification_search_incomplete', 503)
    return response


class Source:
    def __init__(self, client):
        self.client = client

    def shards(self, index):
        if not self.client.indices.exists(index=index):
            raise SlackError('notification_index_missing', 503)
        if set(self.client.indices.get_mapping(index=index)) != {index}:
            raise SlackError('notification_index_scope_changed', 503)
        found = self.client.indices.get_settings(index=index, flat_settings=True)
        if set(found) != {index}:
            raise SlackError('notification_index_scope_changed', 503)
        settings = found[index]['settings'];count = int(settings['index.number_of_shards'])
        if not 1 <= count <= 32:
            raise SlackError('notification_shard_budget_exceeded', 503)
        return [(str(settings['index.uuid']), shard) for shard in range(count)]

    def page(self, index, shard, after, *, baseline=False):
        response = complete(self.client.search(index=index, preference='_shards:' + str(shard),
            size=1 if baseline else 100, seq_no_primary_term=True, allow_partial_search_results=False,
            query={'match_all': {}} if baseline else {'range': {'_seq_no': {'gt': after}}},
            sort=[{'_seq_no': 'desc' if baseline else 'asc'}],
            source=False if baseline else ['rule.id', 'rule.name', 'organization.id', 'cloud_soc.severity', 'cloud_soc.risk_level', 'cloud_soc.alert_title',
                'cloud_soc.revision', 'cloud_soc.state', 'cloud_soc.event_count', 'notice', 'body']))
        hits = response['hits']['hits']
        if len(hits) > (1 if baseline else 100):
            raise SlackError('notification_page_invalid', 503)
        return hits


def event(index, hit, *, portal_url=None):
    source = hit['_source']
    if index == INDICES[0]:
        details = source.get('cloud_soc', {});identifier = hit['_id']
        revision, state = details.get('revision', 0), details.get('state', 'final')
        rule = source.get('rule', {}).get('id', '미기록');severity = details.get('risk_level', details.get('severity'))
        count = details.get('event_count');kind = 'final'
        title = details.get('alert_title') or source.get('rule', {}).get('name')
    else:
        meta = source.get('notice', {});details = source.get('body', {})
        identifier = meta.get('id');revision = meta.get('revision');state = meta.get('state')
        if state not in ('initial', 'verifying', 'delayed', 'confirmed', 'corrected'):
            raise SlackError('notification_notice_invalid', 503)
        if state == 'confirmed' and details.get('final_alert_id'):
            return None  # The linked immutable final alert is sent once via security-alerts.
        rule = details.get('rule_id', '미기록');severity = details.get('severity');count = details.get('observed_count');kind = 'notice'
        title = details.get('title')
    if (not isinstance(identifier, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,256}', identifier)
            or type(revision) is not int or revision < 0 or not isinstance(state, str) or len(state) > 32):
        raise SlackError('notification_event_invalid', 503)
    if severity not in LEVELS:
        return None  # Unknown severity must never silently meet the administrator's threshold.
    payload = alert(identifier=identifier, rule=rule, severity=severity, count=count, title=title,
                    kind=kind, state=state, portal_url=portal_url)
    return {'id': identifier, 'revision': revision, 'state': state, 'severity': severity, 'kind': kind, 'payload': payload}


def scan(store, source):
    with store.connect() as db:
        cfg = dict(db.execute('select * from config where id=1').fetchone())
    if not cfg['enabled'] or not cfg['secret']:
        return 'disabled'
    for index in INDICES:
        for index_uuid, shard in source.shards(index):
            scope = index + ':' + str(shard)
            with store.connect() as db:
                cursor = db.execute('select * from cursors where scope=?', (scope,)).fetchone()
            if cursor and (cursor['generation'] != cfg['generation'] or cursor['uuid'] != index_uuid):
                raise SlackError('notification_index_or_scope_changed', 503)
            baseline = cursor is None
            hits = source.page(index, shard, cursor['seq'] if cursor else -1, baseline=baseline)
            with store.connect() as db:
                db.execute('begin immediate')
                current = db.execute('select * from config where id=1').fetchone()
                if current['generation'] != cfg['generation']:
                    return 'configuration_changed'
                seq = cursor['seq'] if cursor else -1
                for hit in hits:
                    number = hit.get('_seq_no')
                    if type(number) is not int or number < 0 or not baseline and number <= seq:
                        raise SlackError('notification_sequence_invalid', 503)
                    seq = number
                    if baseline:
                        continue  # Establish a per-primary-shard baseline, including all old severities/rules.
                    item = event(index, hit, portal_url=os.environ.get('SOC_PUBLIC_URL'))
                    if item and LEVELS[item['severity']] >= LEVELS[cfg['minimum']]:
                        identity = ':'.join((index_uuid, item['kind'], item['id'], str(item['revision']), item['state']))
                        store.enqueue(db, current, identity, item['kind'], item['id'], item['revision'], item['state'], item['severity'], item['payload'])
                db.execute('insert into cursors values(?,?,?,?) on conflict(scope) do update set seq=excluded.seq',
                           (scope, cfg['generation'], index_uuid, seq))
    return 'active'


def deliver(store, *, sender=send):
    now = store.clock()
    with store.connect() as db:
        db.execute('begin immediate')
        if db.execute('select next_send from control where id=1').fetchone()[0] > now:
            return
        row = db.execute("select * from outbox where status in ('queued','retry') and next_try<=? order by next_try,id limit 1", (now,)).fetchone()
        if not row:
            return
        identifier, generation = row['id'], row['generation']
        db.execute("update outbox set status='inflight',attempts=attempts+1,updated=? where id=?", (now, identifier))
    # Durable intent precedes POST. Config changes take the same lock; after save/delete returns, an old URL cannot be used.
    with store.connect() as db:
        db.execute('begin immediate')
        cfg = db.execute('select * from config where id=1').fetchone()
        row = db.execute('select * from outbox where id=?', (identifier,)).fetchone()
        if (cfg['generation'] != generation or not cfg['secret'] or row['status'] != 'inflight'
                or row['kind'] != 'test' and not cfg['enabled']):
            db.execute("update outbox set status='cancelled',code='configuration_changed' where id=?", (identifier,))
            return
        from cloud_soc.notifications.transport import Result
        try:
            url = store.cipher(create=False).decrypt(cfg['secret'].encode()).decode()
            result = sender(url, json.loads(row['payload']))
        except Exception:
            result = Result('permanent', 'notification_credentials_or_sender_failed')
        status = result.outcome
        if status not in ('sent', 'retry', 'permanent', 'unknown'):
            raise SlackError('notification_sender_invalid', 503)
        if status == 'retry' and row['attempts'] >= 8:
            status = 'permanent'
        delay = max(result.retry_after, min(3600, 2 ** row['attempts'])) if status == 'retry' else 0
        db.execute('update outbox set status=?,code=?,next_try=?,updated=? where id=?',
                   (status, result.code, now + delay, store.clock(), identifier))
        db.execute('update control set next_send=? where id=1', (now + max(1, delay if result.code == 'slack_rate_limited' else 1),))


@contextmanager
def singleton(directory):
    import fcntl
    path = Path(directory) / 'worker.lock'
    if path.is_symlink():
        raise SlackError('notification_storage_unsafe', 503)
    with path.open('a') as lock:
        os.chmod(path, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield


def main():
    from elasticsearch import Elasticsearch
    store = SlackStore(os.environ.get('SOC_NOTIFICATION_STATE_DIR', '/notifications'))
    store.status()  # Create only the private, initially disabled schema; no key/URL is required.
    with singleton(store.directory):
        store.recover()
        with Elasticsearch('https://elasticsearch:9200', api_key=Path('/run/keys/worker.key').read_text().strip(),
                           ca_certs='/run/certs/ca.crt', request_timeout=5, max_retries=0) as client:
            source = Source(client)
            while True:
                try:
                    state = scan(store, source);deliver(store);store.heartbeat(state)
                except Exception:
                    # No exception repr, URL, token, response body or event content enters stdout/logs.
                    try:
                        store.heartbeat('failed', 'notification_cycle_failed')
                    except Exception:
                        pass
                time.sleep(2)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('notification_worker_stopped; protected details omitted') from None
