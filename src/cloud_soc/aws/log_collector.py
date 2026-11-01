"""Explicit CloudWatch groups, whole-window checkpoints, create-only replay."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import re
import sqlite3
import time

from cloud_soc.aws.cloudtrail import iso, timestamp
from cloud_soc.aws.collector import CollectionError, State  # shared durable checkpoint contract
from cloud_soc.aws.service_logs import KINDS, project, required

__all__ = ['LogSettings', 'State', 'poll_source', 'run_cycle']
DELIVERY_CHECK_STREAM = 'log_stream_created_by_aws_to_validate_log_delivery_subscriptions'


@dataclass(frozen=True)
class LogSource:
    id: str
    kind: str
    region: str
    log_group: str
    resource_id: str


@dataclass(frozen=True)
class LogSettings:
    account_id: str
    organization: str
    sources: tuple[LogSource, ...]
    lookback_hours: int = 48
    overlap_minutes: int = 1560

    @property
    def regions(self):
        # Existing State keys need not be geographic regions. Each group has its own cursor.
        return tuple(source.id for source in self.sources)

    def fingerprint(self):
        return hashlib.sha256(json.dumps({'schema': 'cloudwatch-logs-v1', 'account': self.account_id,
            'org': self.organization, 'sources': [vars(s) for s in self.sources],
            'lookback': self.lookback_hours, 'overlap': self.overlap_minutes}, sort_keys=True).encode()).hexdigest()

    @classmethod
    def parse(cls, value):
        try:
            if not isinstance(value, dict) or set(value) - {'account_id', 'organization', 'sources', 'lookback_hours', 'overlap_minutes'}:
                raise ValueError()
            account, org = value['account_id'], value['organization']
            if not isinstance(account, str) or not re.fullmatch(r'[0-9]{12}', account):
                raise ValueError()
            if not isinstance(org, str) or not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', org):
                raise ValueError()
            hours, overlap = value.get('lookback_hours', 48), value.get('overlap_minutes', 1560)
            if type(hours) is not int or not 1 <= hours <= 720 or type(overlap) is not int or not 15 <= overlap <= 4320:
                raise ValueError()
            entries = value['sources']
            if not isinstance(entries, list) or not 1 <= len(entries) <= 20:
                raise ValueError()
            sources, ids, groups = [], set(), set()
            for item in entries:
                if not isinstance(item, dict) or set(item) != {'id', 'kind', 'region', 'log_group', 'resource_id'}:
                    raise ValueError()
                if any(not isinstance(v, str) for v in item.values()):
                    raise ValueError()
                source = LogSource(**item)
                if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', source.id) or source.kind not in KINDS:
                    raise ValueError()
                if not re.fullmatch(r'(?:us|eu|ap|sa|ca|me|af|il|mx)-(?:[a-z]+-)?[a-z]+-[0-9]', source.region) or source.region.startswith('us-gov-'):
                    raise ValueError()
                if not re.fullmatch(r'[.\-_/#A-Za-z0-9]{1,512}', source.log_group):
                    raise ValueError()
                required(source.resource_id)
                if source.kind.startswith('rds_') and source.log_group != '/aws/rds/instance/' + source.resource_id + '/' + source.kind.removeprefix('rds_'):
                    raise ValueError()
                if source.id in ids or (source.region, source.log_group) in groups:
                    raise ValueError()
                ids.add(source.id)
                groups.add((source.region, source.log_group))
                sources.append(source)
            return cls(account, org, tuple(sorted(sources, key=lambda s: s.id)), hours, overlap)
        except (KeyError, ValueError, TypeError):
            raise CollectionError('invalid_cloudwatch_config') from None


def poll_source(settings, state, source, client, sink, *, now, sleep=time.sleep, max_pages=100):
    now = timestamp(now)
    state.db.execute('BEGIN IMMEDIATE')
    try:
        floor, watermark = (timestamp(v) for v in state.db.execute(
            'SELECT floor,watermark FROM progress WHERE region=?', (source.id,)).fetchone())
        start = max(floor, watermark - timedelta(minutes=settings.overlap_minutes))
        end = min(watermark + timedelta(hours=1), now - timedelta(minutes=5))
        if end < watermark or end <= floor:
            state.db.execute('COMMIT')
            return {'source': source.id, 'status': 'waiting', 'created': 0, 'duplicates': 0}
        token, seen, created, duplicates, delivery_checks = None, set(), 0, 0, 0
        for _ in range(max_pages):
            request = {'logGroupName': source.log_group, 'startTime': int(start.timestamp() * 1000),
                       'endTime': int(end.timestamp() * 1000), 'limit': 1000, 'unmask': False}
            if token is not None:
                request['nextToken'] = token
            sleep(0.25)
            try:
                page = client.filter_log_events(**request)
            except Exception as error:
                response = getattr(error, 'response', {})
                aws_code = response.get('Error', {}).get('Code') if isinstance(response, dict) else None
                codes = {'AccessDeniedException': 'aws_access_denied', 'ResourceNotFoundException': 'aws_log_group_missing',
                         'ThrottlingException': 'aws_throttled', 'ExpiredTokenException': 'aws_credentials_expired'}
                raise CollectionError(codes.get(aws_code, 'aws_logs_read_failed')) from None
            events = page.get('events') if isinstance(page, dict) else None
            if not isinstance(events, list) or len(events) > 1000:
                raise CollectionError('invalid_aws_logs_page')
            for envelope in events:
                try:
                    stamp = envelope['timestamp']
                    if type(stamp) is not int or not request['startTime'] <= stamp <= request['endTime']:
                        raise ValueError()
                    # AWS writes delivery probes to this reserved stream. These
                    # are neither native service events nor parser failures.
                    if envelope.get('logStreamName') == DELIVERY_CHECK_STREAM:
                        delivery_checks += 1
                        continue
                    documents = project(envelope, account=settings.account_id, organization=settings.organization,
                        region=source.region, group=source.log_group, kind=source.kind, resource_id=source.resource_id)
                except (ValueError, TypeError, KeyError):
                    raise CollectionError('invalid_service_log_event') from None
                for index, identifier, document in documents:
                    if sink.create(index, identifier, document):
                        created += 1
                    else:
                        duplicates += 1
            token = page.get('nextToken')
            if token is None:
                state.db.execute('UPDATE progress SET watermark=?,last_attempt=?,last_success=?,error=NULL,created=?,duplicates=? WHERE region=?',
                    (iso(end), iso(now), iso(now), created, duplicates, source.id))
                state.db.execute('COMMIT')
                return {'source': source.id, 'status': 'ok', 'watermark': iso(end), 'created': created,
                        'duplicates': duplicates, 'ignored_delivery_checks': delivery_checks}
            if not isinstance(token, str) or not 0 < len(token) <= 8192 or token in seen:
                raise CollectionError('invalid_pagination')
            seen.add(token)
        raise CollectionError('page_limit_reached')
    except BaseException:
        if state.db.in_transaction:
            state.db.execute('ROLLBACK')
        raise


def run_cycle(settings, state, sts, clients, sink, *, now=None, sleep=time.sleep, max_pages=100):
    now = timestamp(now or datetime.now(timezone.utc))
    try:
        identity = sts.get_caller_identity()
        if identity.get('Account') != settings.account_id or not str(identity.get('Arn', '')).startswith('arn:aws:'):
            raise CollectionError('aws_account_mismatch')
    except Exception as error:
        code = 'aws_account_mismatch' if isinstance(error, CollectionError) else 'aws_identity_unavailable'
        for source in settings.sources:
            try:
                state.fail(source.id, now, code)
            except sqlite3.OperationalError:
                pass
        raise CollectionError(code) from None
    results = []
    for source in settings.sources:
        try:
            result = poll_source(settings, state, source, clients[source.region], sink, now=now,
                                 sleep=sleep, max_pages=max_pages)
        except Exception as error:
            code = str(error) if isinstance(error, CollectionError) else 'collection_failed'
            try:
                state.fail(source.id, now, code)
            except sqlite3.OperationalError:
                pass
            result = {'source': source.id, 'status': 'error', 'code': code}
        results.append(result)
    return results
