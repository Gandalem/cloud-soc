"""One bounded read-only probe, durable incident transitions and Slack delivery.

Run from a host timer in a short-lived container, independently of Portal/notifier.
Only this monitor's state is writable. No ES documents or checkpoints are changed.
"""
from datetime import datetime, timezone
import argparse
import json
import math
import os
from pathlib import Path
import sys
import time
import os
from pathlib import Path
import time
DEFAULTS = {'window': 300, 'last_receipt': 300, 'checkpoint': 300,
            'disk_warning': 75, 'disk_critical': 85, 'disk_recovery': 70,
            'low_ratio': 0.2, 'baseline_minimum': 100, 'bad_cycles': 2, 'good_cycles': 2}
WORKERS = ('normalizer', 'normalizer-priority')


def validate_policy(value):
    if set(value) != set(DEFAULTS) or value['window'] != 300:
        raise ValueError('Unsupported monitor policy')
    for key in ('last_receipt', 'checkpoint'):
        if type(value[key]) is not int or not 60 <= value[key] <= 3600:
            raise ValueError('Invalid delay threshold')
    if not 0 < value['disk_recovery'] < value['disk_warning'] < value['disk_critical'] < 100:
        raise ValueError('Invalid disk thresholds')
    if not 0 < value['low_ratio'] < 1 or value['baseline_minimum'] < 1:
        raise ValueError('Invalid traffic baseline')
    if any(type(value[k]) is not int or not 1 <= value[k] <= 10 for k in ('bad_cycles', 'good_cycles')):
        raise ValueError('Invalid debounce')
    return value


def epoch(value):
    parsed = datetime.fromisoformat(value.replace('Z', '+00:00'))
    if parsed.tzinfo is None:
        raise ValueError('Aware timestamp required')
    return parsed.timestamp()


def checked(value):
    if value.get('timed_out') or value.get('terminated_early') or value.get('_shards', {}).get('failed'):
        raise ValueError('Incomplete metrics')
    return value


def collect(client, now, disk):
    from cloud_soc.portal.log_contract import INDICES
    from cloud_soc.elastic.index_scope import index_batches
    result = {'at': now, 'disk': disk, 'input': None, 'workers': None}
    try:
        resolved = client.indices.resolve_index(name=','.join(INDICES), expand_wildcards='open')
        if resolved.get('aliases') or resolved.get('data_streams'):
            raise ValueError('Unexpected intake scope')
        names = [r['name'] for r in resolved.get('indices', [])]
        if not names:
            raise ValueError('No intake indices')
        current, previous, latest = 0, 0, None
        for batch in index_batches(names):
            r = checked(client.search(index=batch, size=0, allow_partial_search_results=False,
                query={'range': {'event.ingested': {'gte': 'now-24h'}}},
                aggs={'recent': {'filter': {'range': {'event.ingested': {'gte': 'now-5m'}}}},
                      'previous': {'filter': {'range': {'event.ingested': {'gte': 'now-35m', 'lt': 'now-5m'}}}},
                      'latest': {'max': {'field': 'event.ingested'}}}))['aggregations']
            current += r['recent']['doc_count']
            previous += r['previous']['doc_count']
            value = r['latest'].get('value')
            if value is not None:
                latest = max(latest or value, value)
        result['input'] = {'recent': current, 'baseline': previous / 6,
                           'last_age': None if latest is None else now - latest / 1000}
    except Exception:
        result['input_error'] = 'intake_metrics_unavailable'
    try:
        docs = client.mget(index='soc-pipeline-status', ids=list(WORKERS))['docs']
        if len(docs) != len(WORKERS) or {d['_id'] for d in docs} != set(WORKERS):
            raise ValueError('Incomplete workers')
        result['workers'] = {}
        for d in docs:
            source = d.get('_source', {})
            result['workers'][d['_id']] = {'state': source.get('state'),
                'age': now - epoch(source['checkpoint']) if source.get('checkpoint') else None}
    except Exception:
        result['workers'] = None
        result['worker_error'] = 'checkpoint_metrics_unavailable'
    return result


def conditions(sample, policy, previous):
    """No failed read is interpreted as zero traffic or recovery."""
    found = {}
    disk = sample.get('disk')
    if not isinstance(disk, (int, float)) or not math.isfinite(disk) or not 0 <= disk <= 100:
        found['disk'] = ('critical', '디스크 사용률 조회 실패')
    else:
        active = previous.get('disk', {}).get('active', False)
        threshold = policy['disk_recovery'] if active else policy['disk_warning']
        severity = 'critical' if disk >= policy['disk_critical'] else 'warning' if disk >= threshold else None
        found['disk'] = (severity, f'디스크 사용률 {disk:.1f}%')
    intake = sample.get('input')
    if intake is None:
        found['input'] = ('critical', '수신 지표 조회 실패 · Elasticsearch 연결/인덱스 확인 필요')
        # Hold earlier receipt/rate incidents until their metrics can be read again.
    else:
        found['input'] = (None, '수신 지표 조회 정상')
        age = intake['last_age']
        found['receipt'] = ('critical' if age is None or age < -60 or age > policy['last_receipt'] else None,
                            '24시간 내 수신 없음' if age is None else f'마지막 수신 경과 {round(age)}초')
        count, baseline = intake['recent'], intake['baseline']
        bad = count == 0 or baseline >= policy['baseline_minimum'] and count < baseline * policy['low_ratio']
        found['volume'] = ('critical' if count == 0 else 'warning' if bad else None,
                           f'최근 5분 {count}건 · 이전 30분의 5분 평균 {baseline:.1f}건')
    workers = sample.get('workers')
    if workers is None:
        found['workers'] = ('critical', '정규화 체크포인트 조회 실패')
    else:
        found['workers'] = (None, '정규화 체크포인트 조회 정상')
        for name in WORKERS:
            row = workers[name]
            age = row['age']
            bad = row['state'] not in ('success', 'running') or age is None or age < -60 or age > policy['checkpoint']
            found[name] = ('critical' if bad else None,
                          f'{name}: 상태 {row["state"]} · 처리 지연 {round(age) if age is not None else "미확인"}초')
    return found


def transition(state, sample, policy):
    incidents = state.setdefault('incidents', {})
    queue = state.setdefault('events', [])
    observed = conditions(sample, policy, incidents)
    for key in incidents.keys() - observed.keys():
        incidents[key]['bad'] = incidents[key]['good'] = 0
    for key, (severity, detail) in observed.items():
        item = incidents.setdefault(key, {'active': False, 'bad': 0, 'good': 0, 'sequence': 0})
        item['bad'] = item['bad'] + 1 if severity else 0
        item['good'] = item['good'] + 1 if not severity else 0
        trigger = severity and item['bad'] >= policy['bad_cycles'] and (
            not item['active'] or item.get('severity') == 'warning' and severity == 'critical')
        recovery = item['active'] and not severity and item['good'] >= policy['good_cycles']
        if trigger or recovery:
            item['active'] = bool(trigger)
            item['severity'] = severity
            item['sequence'] += 1
            at = datetime.fromtimestamp(sample['at'], timezone.utc).isoformat()
            title = '장애' if trigger else '복구'
            queue.append({'id': f'{key}:{item["sequence"]}', 'key': key, 'status': 'queued',
                          'attempts': 0, 'next_try': sample['at'],
                          'payload': {'text': f'[Cloud SOC 운영감시 · {title}] {key}\n{detail}\n{at}\n'
                                      '전체 수신 기준이며 개별 장치의 정상 여부는 별도 확인이 필요합니다.',
                                      'unfurl_links': False, 'unfurl_media': False}})
    state['sample'] = sample
    # Keep all unsettled/ambiguous deliveries and a bounded settled audit tail.
    pending = [e for e in queue if e['status'] not in ('sent', 'permanent')]
    settled = [e for e in queue if e['status'] in ('sent', 'permanent')][-100:]
    state['events'] = pending + settled
    return state


def save(path, state):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Unsafe monitor state')
    tmp = path.with_suffix('.tmp')
    fd = os.open(tmp, os.O_CREAT | os.O_TRUNC | os.O_WRONLY | getattr(os, 'O_NOFOLLOW', 0), 0o600)
    with os.fdopen(fd, 'w') as f:
        json.dump(state, f, ensure_ascii=True)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    os.chmod(path, 0o600)


def webhook(settings):
    """Read the existing destination without changing notification configuration."""
    from cryptography.fernet import Fernet
    if not settings or not settings.get('enabled') or not settings.get('secret'):
        return None
    return Fernet(settings['key'].encode()).decrypt(settings['secret'].encode()).decode()


def dispatch(state, path, *, sender, destination, clock=time.time):
    now = clock()
    if 'slack_retry_until' not in state:
        # Older watchdogs recorded rate limits only on the event that received the 429.
        state['slack_retry_until'] = max((e['next_try'] for e in state['events']
                                         if e.get('code') == 'slack_rate_limited'), default=0)
    recovered = False
    for event in state['events']:
        if event['status'] == 'sending':
            event.update(status='unknown', code='delivery_unconfirmed')
            recovered = True
    if recovered:
        save(path, state)  # Persist recovery even when nothing can be sent this cycle.
    if state['slack_retry_until'] > now:
        return
    due = next((e for e in state['events'] if e['status'] in ('queued', 'retry', 'blocked') and e['next_try'] <= now), None)
    if not due:
        return
    try:
        url = destination()
    except Exception:
        url = None
    if not url:
        due.update(status='blocked', next_try=now + 60, code='notification_destination_unavailable')
        save(path, state)
        return
    due.update(status='sending', attempts=due['attempts'] + 1)
    save(path, state)
    try:
        result = sender(url, due['payload'])
        outcome, code, delay = result.outcome, result.code, result.retry_after
    except Exception:
        outcome, code, delay = 'unknown', 'delivery_unconfirmed', 0
    if code == 'slack_rate_limited':
        now = clock()
        state['slack_retry_until'] = now + delay
    if outcome not in ('sent', 'retry', 'permanent', 'unknown'):
        outcome = 'unknown'
    if outcome == 'retry' and due['attempts'] >= 8:
        outcome = 'permanent'
    due.update(status=outcome, code=code, next_try=now + max(delay, min(3600, 2 ** due['attempts'])))
    save(path, state)


def main():
    from elasticsearch import Elasticsearch
    from cloud_soc.notifications.transport import send
    parser = argparse.ArgumentParser()
    parser.add_argument('--state', default='/health/state.json')
    parser.add_argument('--dry-run', action='store_true')
    parser.add_argument('--test-notification', action='store_true')
    args = parser.parse_args()
    data = json.load(sys.stdin)
    now = time.time()
    policy = validate_policy(DEFAULTS | data.get('policy', {}))
    path = Path(args.state)
    if path.is_symlink():
        raise ValueError('Unsafe state')
    state = json.loads(path.read_text()) if path.exists() else {}
    with Elasticsearch('https://elasticsearch:9200',
                       basic_auth=('cloud_soc_agent_monitor', Path('/run/monitor-password').read_text().strip()),
                       ca_certs='/run/ca.crt', request_timeout=5, max_retries=0) as client:
        sample = collect(client, now, data.get('disk'))
    if args.test_notification:
        if args.dry_run:
            raise ValueError('Test notification cannot be dry-run')
        state.setdefault('incidents', {})
        state.setdefault('events', []).append({'id': f'test:{int(now)}', 'key': 'test', 'status': 'queued',
            'attempts': 0, 'next_try': now,
            'payload': {'text': '[Cloud SOC 운영감시 · 설치 시험]\n'
                        '장애 경보가 아닙니다. 수신량·마지막 수신·정규화 체크포인트·디스크 감시의 알림 경로를 확인합니다.',
                        'unfurl_links': False, 'unfurl_media': False}})
        state['sample'] = sample
    else:
        transition(state, sample, policy)
    if not args.dry_run:
        save(path, state)
        dispatch(state, path, sender=send, destination=lambda: webhook(data.get('notification')))
    try:
        configured = bool(webhook(data.get('notification')))
    except Exception:
        configured = False
    print(json.dumps({'sample': sample, 'incidents': state['incidents'],
                      'deliveries': [{'id': e['id'], 'status': e['status'], 'code': e.get('code')} for e in state['events']],
                      'dry_run': args.dry_run, 'notification_configured': configured}))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        raise SystemExit('health_watchdog_failed; protected details omitted') from None



class WorkerHeartbeat:
    """K8s exec Liveness/Readiness Probe용 파일 기반 워커 생존 신호기"""

    def __init__(self, worker_name: str, base_dir: str = "/tmp/cloud-soc-health") -> None:
        self.base_dir = Path(base_dir)
        self.base_dir.mkdir(parents=True, exist_ok=True)
        self.liveness_file = self.base_dir / f"{worker_name}.alive"
        self.readiness_file = self.base_dir / f"{worker_name}.ready"

    def mark_ready(self) -> None:
        self.readiness_file.touch(exist_ok=True)
        self.beat()

    def beat(self) -> None:
        now = time.time()
        self.liveness_file.touch(exist_ok=True)
        os.utime(self.liveness_file, (now, now))

    def mark_unready(self) -> None:
        if self.readiness_file.exists():
            self.readiness_file.unlink()