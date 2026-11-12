"""Separate school snapshot workspace; never mutate or rewrite stored evidence."""
from copy import deepcopy
import os
from pathlib import Path
import re
from threading import Lock
import time

from flask import jsonify, request
from werkzeug.wrappers import Response

HEADER = 'HTTP_X_CLOUD_SOC_DATASET'
READS = {'search', 'count', 'get', 'mget', 'field_caps', 'open_point_in_time', 'close_point_in_time'}
INDEX_READS = {'resolve_index', 'get_mapping', 'get_settings', 'exists'}
ARCHIVE_ENDPOINTS = {
    'auth_me', 'login', 'login_config', 'login_page', 'logout', 'auth_asset', 'index', 'static_file',
    'logs', 'log_updates', 'log_detail', 'log_access', 'log_source',
    'operations_summary', 'alert_detail', 'alert_site_context', 'healthz',
    'case_list', 'case_link', 'case_detail', 'case_create', 'case_update',
    'dashboard_get', 'dashboard_save', 'dashboards_get', 'dashboards_write',
}


def logical_name(value, prefix):
    if not isinstance(value, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.*-]{0,239}', value):
        raise ValueError('Invalid archive index')
    if value.startswith(prefix) or not (value.startswith(('soc-', 'raw-logs-')) or value in ('security-alerts', 'normalized-events')):
        raise ValueError('Index outside archive scope')
    return prefix + value


def translate_metadata(value, prefix):
    """Translate transport metadata only; _source and hashes stay byte-equivalent."""
    if isinstance(value, list):
        return [translate_metadata(item, prefix) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        output_key = key[len(prefix):] if key.startswith(prefix) else key
        if key == '_source':
            result[output_key] = item
        elif key in ('_index', 'index', 'name') and isinstance(item, str) and item.startswith(prefix):
            result[output_key] = item[len(prefix):]
        else:
            result[output_key] = translate_metadata(item, prefix)
    return result


class ArchiveClient:
    def __init__(self, client, prefix, *, pits=None):
        if not re.fullmatch(r'school-import-[0-9]{8}-', prefix):
            raise ValueError('Fixed archive prefix required')
        self._client, self.prefix = client, prefix
        self._pits = pits if pits is not None else ({}, Lock())
        self.indices = ArchiveIndices(self)
        self.security = ArchiveSecurity(self)

    def options(self, **kwargs):
        return ArchiveClient(self._client.options(**kwargs), self.prefix, pits=self._pits)

    def _names(self, value):
        if isinstance(value, (list, tuple)):
            return [self._names(item) for item in value]
        return ','.join(logical_name(item, self.prefix) for item in value.split(','))

    def _invoke(self, target, method, **kwargs):
        kwargs = deepcopy(kwargs)
        for key in ('index', 'name'):
            if key in kwargs:
                kwargs[key] = self._names(kwargs[key])
        pits, lock = self._pits
        with lock:
            now = time.monotonic()
            for key in list(pits):
                if pits[key] < now:
                    del pits[key]
            pit = (kwargs.get('body') or {}).get('pit') or kwargs.get('pit')
            if method == 'search' and 'index' not in kwargs:
                if not isinstance(pit, dict) or pit.get('id') not in pits:
                    raise ValueError('Archive PIT required')
            if method == 'close_point_in_time' and kwargs.get('id') not in pits:
                raise ValueError('Archive PIT required')
        response = getattr(target, method)(**kwargs)
        body = getattr(response, 'body', response)
        if isinstance(body, dict):
            with lock:
                if method == 'open_point_in_time' and body.get('id'):
                    pits[body['id']] = time.monotonic() + 660
                if method == 'search' and body.get('pit_id'):
                    pits[body['pit_id']] = time.monotonic() + 660
                if method == 'close_point_in_time':
                    pits.pop(kwargs.get('id'), None)
            mapped = translate_metadata(body, self.prefix)
            if hasattr(response, 'meta'):
                return type(response)(meta=response.meta, body=mapped)
            return mapped
        return response

    def __getattr__(self, name):
        if name not in READS:
            raise AttributeError('Archive client supports bounded reads only')
        return lambda **kwargs: self._invoke(self._client, name, **kwargs)


class ArchiveIndices:
    def __init__(self, parent):
        self.parent = parent

    def __getattr__(self, name):
        if name not in INDEX_READS:
            raise AttributeError('Archive index writes are disabled')
        return lambda **kwargs: self.parent._invoke(self.parent._client.indices, name, **kwargs)


class ArchiveSecurity:
    def __init__(self, parent):
        self.parent = parent

    def authenticate(self):
        return self.parent._client.security.authenticate()


def decorate(app, dataset):
    @app.after_request
    def dataset_metadata(response):
        response.headers['X-Cloud-SOC-Dataset'] = dataset
        response.vary.add('X-Cloud-SOC-Dataset')
        if request.endpoint == 'auth_me' and response.status_code == 200:
            body = response.get_json()
            body['dataset'] = dataset
            body['datasets'] = [
                {'id': 'live', 'name': 'EC2 운영'},
                {'id': 'school', 'name': '학교 기록 · 2026-11-09 백업'},
            ]
            if dataset == 'school':
                body['navigation'] = ['logs.html', 'operations.html', 'cases.html', 'dashboard.html']
            response.set_data(app.json.dumps(body))
        return response

    if dataset == 'school':
        @app.before_request
        def archive_boundary():
            # App authentication, organization policy and CSRF run first.
            if request.endpoint not in ARCHIVE_ENDPOINTS:
                return jsonify(code='archive_operation_unavailable',
                    error='학교 백업 기록에서는 로그·경보·사건·대시보드를 사용할 수 있습니다. 장치·키·수집 설정은 EC2 운영으로 전환하세요.'), 409


class DatasetDispatcher:
    def __init__(self, live, school):
        self.live, self.school = live, school

    def __call__(self, environ, start_response):
        dataset = environ.get(HEADER, 'live')
        if dataset not in ('live', 'school'):
            return Response('Unknown dataset', status=400)(environ, start_response)
        app = self.school if dataset == 'school' else self.live
        return app(environ, start_response)


def build_workspaces(settings, *, issuer=None, monitor=None, archive_dir, prefix):
    from cloud_soc.portal.app import create_app
    archive_dir = Path(archive_dir)
    if not (archive_dir / 'packages.sqlite3').is_file():
        raise ValueError('Verified restored school DBs required')
    live = create_app(settings, issuer=issuer, monitor=monitor)
    school_settings = dict(settings)
    school_settings.update(
        STATE_DIR=archive_dir, AUTH_STATE_DIR=settings['STATE_DIR'],
        ENROLLMENT_ENABLED=False, NOTIFICATION_STATE_DIR=archive_dir / 'notifications',
        PROCESSING_SCOPE=None, MANAGED_WORKER_CONFIG=None, MALL_LAB_SCOPE=None,
        MALL_TRIAGE_SNAPSHOT_FILE=None,
    )
    school = create_app(school_settings, issuer=live.extensions['issuer'],
        monitor=ArchiveClient(live.extensions['monitor'], prefix))
    decorate(live, 'live')
    decorate(school, 'school')
    dispatcher = DatasetDispatcher(live.wsgi_app, school.wsgi_app)
    live.wsgi_app = dispatcher
    live.extensions['school_archive'] = school
    return live


def create_app():
    from cloud_soc.portal.app import settings_from_environment
    return build_workspaces(settings_from_environment(),
        archive_dir=os.environ['SOC_ARCHIVE_STATE_DIR'],
        prefix=os.environ['SOC_ARCHIVE_PREFIX'])
