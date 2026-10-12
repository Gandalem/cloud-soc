"""Per-principal display preferences; never store telemetry or query authority."""
from contextlib import contextmanager
import json
import sqlite3
from pathlib import Path
from cloud_soc.privacy import sensitive

WIDGETS = ('overview', 'pipeline', 'intake', 'trend', 'severity', 'alerts', 'processing', 'cases')
# Legacy display preferences remain readable without rewriting the stored row.
ACTIVE_WIDGETS = ('overview', 'intake', 'trend', 'severity', 'alerts', 'cases')
DEFAULT = {'name': '내 대시보드', 'period': 1440, 'theme': 'light', 'widgets': [
    {'id': name, 'size': 'wide' if name in ('overview', 'alerts') else 'normal'} for name in ACTIVE_WIDGETS]}


class DashboardError(Exception):
    def __init__(self, message, status=400):
        super().__init__(message)
        self.status = status


def validate(value):
    if not isinstance(value, dict) or set(value) != {'name', 'period', 'theme', 'widgets'}:
        raise DashboardError('대시보드 설정 형식을 확인하세요.')
    name = value['name']
    if (not isinstance(name, str) or not 1 <= len(name.strip()) <= 48 or sensitive(name)
            or any(ord(char) < 32 for char in name)):
        raise DashboardError('이름은 비밀정보 없이 1~48자로 입력하세요.')
    if type(value['period']) is not int or value['period'] not in (60, 1440, 10080) or value['theme'] not in ('light', 'dark'):
        raise DashboardError('조회 기간과 테마를 확인하세요.')
    widgets = value['widgets']
    if not isinstance(widgets, list) or not 1 <= len(widgets) <= len(WIDGETS):
        raise DashboardError('위젯을 1개 이상 선택하세요.')
    seen = set()
    for row in widgets:
        if (not isinstance(row, dict) or set(row) != {'id', 'size'} or not isinstance(row['id'], str)
                or row['id'] not in WIDGETS or row['id'] in seen or row['size'] not in ('normal', 'wide')):
            raise DashboardError('위젯 종류·크기·중복을 확인하세요.')
        seen.add(row['id'])
    return {**value, 'name': name.strip()}


class DashboardStore:
    def __init__(self, path):
        self.path = Path(path)
        with self.connect() as db:
            db.execute('CREATE TABLE IF NOT EXISTS dashboards (actor TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL)')

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        try:
            with db:
                yield db
        finally:
            db.close()

    def get(self, actor):
        with self.connect() as db:
            row = db.execute('SELECT revision,body FROM dashboards WHERE actor=?', (actor,)).fetchone()
        return {'revision': row[0], 'layout': validate(json.loads(row[1]))} if row else {
            'revision': 0, 'layout': json.loads(json.dumps(DEFAULT))}

    def save(self, actor, payload):
        if not isinstance(payload, dict) or set(payload) != {'revision', 'layout'}:
            raise DashboardError('저장할 설정을 확인하세요.')
        revision = payload['revision']
        if type(revision) is not int or not 0 <= revision < 2**31:
            raise DashboardError('설정 버전을 확인하세요.')
        layout = validate(payload['layout'])
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT revision FROM dashboards WHERE actor=?', (actor,)).fetchone()
            if revision != (current[0] if current else 0):
                raise DashboardError('다른 창에서 설정이 바뀌었습니다. 다시 불러온 뒤 저장하세요.', 409)
            db.execute('INSERT INTO dashboards VALUES(?,?,?) ON CONFLICT(actor) DO UPDATE SET revision=excluded.revision,body=excluded.body',
                       (actor, revision + 1, json.dumps(layout, ensure_ascii=False)))
        return {'revision': revision + 1, 'layout': layout}
