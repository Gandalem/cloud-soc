#!/usr/bin/env python3
"""Continuous real audit/EVE/kernel/business bridge; no event generation."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import select
import sqlite3
import ssl
import sys
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, build_opener, ProxyHandler, HTTPSHandler

from cloud_soc.parsers.security_scenario_export import project

INDEX = 'soc-host-raw-security-scenarios-local-v1'
AUDIT = re.compile(r'type=(\w+).*?msg=audit\(([\d.]+):(\d+)\):\s*(.*)')
FIELDS = re.compile(r'(\w+)=("[^"\n]*"|[^\s]+)')


def fields(text):
    return {key: value.strip('"') for key, value in FIELDS.findall(text)}


def envelope(stamp, kind, action, **values):
    return {'timestamp': stamp, 'security_scenario': {
        'schema': 'security-scenarios-v1', 'kind': kind, 'action': action,
        'outcome': 'success', **values}}


def audit_event(rows):
    syscall = next((fields(body) for kind, body in rows if kind == 'SYSCALL'), {})
    if syscall.get('success') != 'yes':
        return []
    key = syscall.get('key')
    # Only explicit administrator-installed watch keys, never guessed free text.
    kind = {'soc_file': 'server_file', 'soc_persist': 'server_persistence',
            'soc_defense': 'server_defense'}.get(key)
    if kind is None:
        return []
    actor = syscall.get('auid')
    if actor in (None, '4294967295', '-1', 'unset'):
        actor = syscall.get('uid')
    if actor is None:
        return []
    cwd = next((fields(body).get('cwd', '') for record_type, body in rows if record_type == 'CWD'), '')
    if cwd and not cwd.startswith('/') and re.fullmatch(r'(?:[0-9A-Fa-f]{2})+', cwd):
        cwd = bytes.fromhex(cwd).decode('utf-8', errors='strict')
    result = []
    for record_type, body in rows:
        item = fields(body)
        if record_type != 'PATH' or item.get('nametype') == 'PARENT':
            continue
        name = item.get('name', '')
        # Audit hex-encodes names containing spaces/non-ASCII.
        if not name.startswith('/') and re.fullmatch(r'(?:[0-9A-Fa-f]{2})+', name):
            name = bytes.fromhex(name).decode('utf-8', errors='strict')
        if not name.startswith('/') and cwd.startswith('/'):
            name = os.path.normpath(os.path.join(cwd, name))
        if not name.startswith('/'):
            continue
        allowed = {'server_file': ('/etc/hosts', '/etc/passwd', '/etc/group'),
                   'server_persistence': ('/etc/systemd/system', '/etc/cron.d', '/etc/cron.hourly', '/var/spool/cron/crontabs'),
                   'server_defense': ('/etc/audit', '/etc/ufw', '/etc/apparmor.d')}[kind]
        if not any(name == path or name.startswith(path + '/') for path in allowed):
            continue
        value = {'actor': 'uid:' + actor}
        if kind == 'server_file':
            value.update(object_path=name, critical_asset=True)
        elif kind == 'server_persistence':
            obj = 'cron' if name.startswith(('/etc/cron', '/var/spool/cron')) else (
                'systemd_timer' if name.endswith('.timer') else 'service')
            value.update(object_name=name, object_type=obj)
        else:
            value.update(object_name=name)
        action = 'policy_changed' if kind == 'server_defense' else 'modified'
        if kind == 'server_file' and item.get('nametype') == 'DELETE':
            action = 'deleted'
        if kind == 'server_persistence' and item.get('nametype') == 'CREATE':
            action = 'created'
        result.append((kind, action, value))
    # A single syscall counts once, even when PATH includes several affected names.
    return result[:1]


def eve(document):
    stamp = document['timestamp']
    base = {key: document[source] for key, source in (
        ('source_ip', 'src_ip'), ('destination_ip', 'dest_ip')) if source in document}
    if document.get('event_type') == 'dns':
        dns = document.get('dns', {})
        if dns.get('rcode') != 'NXDOMAIN' or dns.get('type') not in ('answer', 'response'):
            return []
        # Responses flow from DNS server to requesting client.
        base = {'source_ip': document['dest_ip']}
        name = dns.get('rrname')
        if not name and dns.get('queries'):
            name = dns['queries'][0].get('rrname')
        if not name:
            return []
        return [envelope(stamp, 'network_dns', 'query', **base, dns_name=name, dns_rcode='NXDOMAIN')]
    if document.get('event_type') == 'alert':
        alert = document['alert']
        return [envelope(stamp, 'network_ids', 'alert', **base,
            signature_id=str(alert['signature_id']), signature_name=alert['signature'])]
    return []


def kernel(document):
    message = document.get('MESSAGE', '')
    # Explicit drop-log prefixes only; unrelated kernel messages are ignored.
    if '[UFW BLOCK]' not in message and 'SOC_DROP ' not in message:
        return []
    values = fields(message)
    if not all(key in values for key in ('SRC', 'DST', 'DPT')):
        return []
    stamp = datetime.fromtimestamp(int(document['__REALTIME_TIMESTAMP']) / 1e6, timezone.utc).isoformat()
    return [envelope(stamp, 'network_firewall', 'dropped', source_ip=values['SRC'],
        destination_ip=values['DST'], destination_port=int(values['DPT']))]


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--source', choices=('auditd', 'eve', 'kernel', 'business'), required=True)
    p.add_argument('--state', type=Path, required=True)
    p.add_argument('--organization', required=True)
    p.add_argument('--host', required=True)
    p.add_argument('--service', default='security-mall')
    p.add_argument('--es-url', default='https://192.168.1.159:9200')
    p.add_argument('--ca-file', type=Path, required=True)
    p.add_argument('--key-file', type=Path, required=True)
    a = p.parse_args()
    os.umask(0o077)
    if not a.es_url.startswith('https://') or a.state.is_symlink():
        raise ValueError('Unsafe endpoint/state')
    a.state.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    import fcntl
    lock = open(str(a.state) + '.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    db = sqlite3.connect(a.state)
    db.execute('CREATE TABLE IF NOT EXISTS inbox (id TEXT PRIMARY KEY, body TEXT, delivered INTEGER NOT NULL DEFAULT 0)')
    opener = build_opener(ProxyHandler({}), HTTPSHandler(context=ssl.create_default_context(cafile=str(a.ca_file))))
    auth = 'ApiKey ' + a.key_file.read_text().strip()
    if auth == 'ApiKey ':
        raise ValueError('Empty writer key')

    def deliver():
        while True:
            row = db.execute('SELECT id,body FROM inbox WHERE delivered=0 LIMIT 1').fetchone()
            if row is None:
                return
            while True:
                req = Request(a.es_url.rstrip('/') + '/' + INDEX + '/_create/' + row[0], method='PUT',
                    data=row[1].encode(), headers={'Authorization': auth, 'Content-Type': 'application/json'})
                try:
                    with opener.open(req, timeout=30) as response:
                        response.read()
                    break
                except HTTPError as error:
                    if error.code == 409:
                        break
                    if error.code not in (429, 502, 503, 504):
                        raise RuntimeError('Writer HTTP ' + str(error.code)) from None
                except (URLError, TimeoutError):
                    pass
                print('Delivery waiting; pending event retained', flush=True)
                time.sleep(5)
            db.execute('UPDATE inbox SET delivered=1,body=NULL WHERE id=?', (row[0],))
            db.commit()
            print(json.dumps({'source': a.source, 'received_by_central': 1}), flush=True)

    def emit(document, identity):
        projected = project(document, organization=a.organization, host=a.host, service=a.service)
        projected['event']['id'] = identity
        identifier = hashlib.sha256((a.organization + '\0' + a.host + '\0' + a.source + '\0' + identity).encode()).hexdigest()
        db.execute('INSERT OR IGNORE INTO inbox(id,body) VALUES (?,?)',
                   (identifier, json.dumps(projected, ensure_ascii=True)))
        db.commit()
        deliver()

    pending = {}
    def finish(serial):
        stamp, rows = pending.pop(serial)
        for number, (kind, action, values) in enumerate(audit_event(rows)):
            emit(envelope(stamp, kind, action, **values), serial + ':' + str(number))
    deliver()
    # Binary line buffering with select supports quiet audit event completion.
    buffer = b''
    while True:
        ready, _, _ = select.select([sys.stdin.fileno()], [], [], 2)
        if not ready:
            for serial in list(pending):
                finish(serial)
            continue
        chunk = os.read(sys.stdin.fileno(), 65536)
        if not chunk:
            for serial in list(pending):
                finish(serial)
            if buffer:
                print('Incomplete final source line ignored; keep original source file', flush=True)
            return
        buffer += chunk
        if len(buffer) > 2**21 and b'\n' not in buffer:
            raise ValueError('Source line exceeds limit')
        while b'\n' in buffer:
            raw, buffer = buffer.split(b'\n', 1)
            if len(raw) > 2**21:
                print('Oversized source record rejected', flush=True)
                continue
            try:
                line = raw.decode('utf-8')
                if a.source == 'auditd':
                    match = AUDIT.search(line)
                    if match:
                        kind, epoch, serial, body = match.groups()
                        serial = epoch + ':' + serial
                        if serial not in pending:
                            pending[serial] = (datetime.fromtimestamp(float(epoch), timezone.utc).isoformat(), [])
                        pending[serial][1].append((kind, body))
                        if kind == 'EOE':
                            finish(serial)
                        if len(pending) > 256:
                            finish(next(iter(pending)))
                else:
                    document = json.loads(line)
                    events = eve(document) if a.source == 'eve' else kernel(document) if a.source == 'kernel' else [document]
                    for i, event in enumerate(events):
                        emit(event, hashlib.sha256(raw).hexdigest() + ':' + str(i))
            except (ValueError, KeyError, TypeError, UnicodeError, OverflowError):
                print('Source metadata rejected; original record preserved at producer', flush=True)


if __name__ == '__main__':
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as error:
        print('Collector stopped: ' + type(error).__name__ + '; no source payload/credentials printed', file=sys.stderr)
        raise SystemExit(1)
