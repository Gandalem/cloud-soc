"""Cloud-native transports; no cloud resources are created by these collectors."""
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import time
from urllib.request import Request, urlopen

from .normalize import utc


def secret(name):
    from cloud_soc.secret_store import read, required, SecretError
    value, filename = os.environ.get(name), os.environ.get(name + '_FILE')
    if required() and value:raise SecretError('inline_secret_forbidden')
    if value and filename:
        raise ValueError('Choose one secret source')
    if filename:
        from pathlib import Path
        path = Path(filename)
        if os.name != 'nt' and path.stat().st_mode & 0o077:
            raise ValueError('Secret files must be private')
        value = read(path) if required() or path.read_bytes().lstrip().startswith(b'{') else path.read_text().strip()
    if not value:
        raise ValueError('Missing secret: ' + name)
    return value


def window(scope, state, *, cursor_key='watermark', lag=timedelta(minutes=5)):
    floor = datetime.fromisoformat(scope['start'].replace('Z', '+00:00'))
    if floor.utcoffset() is None:
        raise ValueError('start must include timezone')
    cursor = datetime.fromisoformat((state.get(cursor_key) or scope['start']).replace('Z', '+00:00'))
    end = min(cursor + timedelta(minutes=15), datetime.now(timezone.utc) - lag)
    return max(floor, cursor - timedelta(minutes=10)), end, cursor


class AWS:
    def __init__(self, scope):
        import boto3
        from botocore.config import Config
        session = boto3.Session(profile_name=scope.get('profile'), region_name=scope['region'])
        config = Config(retries={'total_max_attempts': 5, 'mode': 'adaptive'}, connect_timeout=5, read_timeout=30)
        from cloud_soc.secret_store import required, SecretError
        if required():
            credentials=session.get_credentials()
            if scope.get('profile') or credentials is None or credentials.method not in ('iam-role','container-role','assume-role-with-web-identity'):raise SecretError('aws_workload_identity_required')
        self.client = session.client('cloudtrail', config=config)
        self.sts = session.client('sts', config=config)
        if self.sts.get_caller_identity()['Account'] != str(scope['account']):
            raise ValueError('AWS caller account mismatch')

    def poll(self, scope, state, sink):
        start, end, cursor = window(scope, state)
        if end <= cursor:
            return
        if start < datetime.now(timezone.utc) - timedelta(days=90):
            raise ValueError('AWS Event History retention exceeded; explicit archive recovery required')
        pages = self.client.get_paginator('lookup_events').paginate(
            StartTime=start, EndTime=end, PaginationConfig={'PageSize': 50})
        for page in pages:
            for event in page.get('Events', []):
                raw = json.loads(event['CloudTrailEvent'])
                if raw.get('awsRegion') != scope['region']:
                    raise ValueError('AWS region mismatch')
                sink.write('aws', raw)
            time.sleep(0.6)
        state.put('watermark', utc(end))

    def close(self):
        self.client.close()
        self.sts.close()


class Naver:
    def __init__(self, scope):
        self.access = secret(scope['access_key_env'])
        self.key = secret(scope['secret_key_env']).encode()

    def poll(self, scope, state, sink):
        start, end, cursor = window(scope, state)
        if end > cursor:
            self._collect(scope, start, end, sink)
            state.put('watermark', utc(end))
        # User-reported publication delay: retain a separate replay cursor rather
        # than rewinding an existing live watermark or deleting the state DB.
        late_start, late_end, late_cursor = window(scope, state,
            cursor_key='naver_late_watermark_v1', lag=timedelta(hours=24, minutes=5))
        if late_end > late_cursor:
            self._collect(scope, late_start, late_end, sink)
            state.put('naver_late_watermark_v1', utc(late_end))
            state.put('late_poll_state', 'processed')
        else:
            state.put('late_poll_state', 'waiting_for_publication')

    def _collect(self, scope, start, end, sink):
        if start < datetime.now(timezone.utc) - timedelta(days=30):
            raise ValueError('Naver activity query retention exceeded; explicit archive recovery required')
        path = '/api/v1/activities'
        for page in range(10000):
            stamp = str(int(time.time() * 1000))
            message = f'POST {path}\n{stamp}\n{self.access}'.encode()
            signature = base64.b64encode(hmac.new(self.key, message, hashlib.sha256).digest()).decode()
            payload = json.dumps({'fromEventTime': int(start.timestamp()*1000), 'toEventTime': int(end.timestamp()*1000), 'page': page, 'size': 100}).encode()
            req = Request('https://cloudactivitytracer.apigw.ntruss.com' + path, data=payload, method='POST', headers={
                'Content-Type': 'application/json', 'x-ncp-apigw-timestamp': stamp,
                'x-ncp-iam-access-key': self.access, 'x-ncp-apigw-signature-v2': signature})
            # The endpoint is a literal HTTPS Public CAT origin above, never user supplied.
            with urlopen(req, timeout=30) as response:  # nosec B310
                body = response.read(16 * 1024 * 1024 + 1)
            if len(body) > 16 * 1024 * 1024:
                raise ValueError('Naver response size exceeded')
            data = json.loads(body)
            if not isinstance(data.get('items'), list) or type(data.get('hasMore')) is not bool:
                raise ValueError('Unexpected Naver response')
            for raw in data['items']:
                sink.write('naver', raw)
            if not data['hasMore']:
                return
            time.sleep(0.3)
        raise ValueError('Naver page limit reached; checkpoint preserved')

    def close(self):
        pass


def receive_azure(scope, sink):
    from azure.eventhub import EventHubConsumerClient
    from azure.eventhub.extensions.checkpointstoreblob import BlobCheckpointStore
    checkpoint = BlobCheckpointStore.from_connection_string(
        secret(scope['storage_connection_env']), scope['checkpoint_container'])
    client = EventHubConsumerClient.from_connection_string(
        secret(scope['eventhub_connection_env']), consumer_group=scope['consumer_group'],
        eventhub_name=scope['eventhub'], checkpoint_store=checkpoint)
    import threading
    stopped = threading.Event()
    errors = []
    def event(partition, envelope):
        if envelope is None or stopped.is_set():
            return
        try:
            payload = json.loads(envelope.body_as_str(encoding='UTF-8'))
            records = payload.get('records') if isinstance(payload, dict) else None
            if not isinstance(records, list):
                raise ValueError('Expected Azure diagnostic records array')
            for raw in records:
                sink.write('azure', raw)
            partition.update_checkpoint(envelope)
        except Exception as exc:
            errors.append(exc)
            stopped.set()

    def error(_partition, exception):
        errors.append(exception)
        stopped.set()

    def receive():
        try:
            client.receive(on_event=event, on_error=error,
                starting_position=datetime.fromisoformat(scope['start'].replace('Z', '+00:00')))
        except Exception as exc:
            errors.append(exc)
        finally:
            stopped.set()

    worker = threading.Thread(target=receive, name='azure-receive', daemon=True)
    worker.start()
    try:
        while not stopped.wait(1):
            pass
    finally:
        client.close()
        worker.join()
        checkpoint.close()
    if errors:
        raise errors[0]
