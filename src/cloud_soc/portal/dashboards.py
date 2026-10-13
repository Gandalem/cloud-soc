"""Per-principal display preferences; never store telemetry or query authority."""
from contextlib import contextmanager
import json
import sqlite3
from pathlib import Path
import secrets
from cloud_soc.privacy import sensitive
from cloud_soc.portal.dashboard_widgets import safe_title, valid_layout, template, TEMPLATES, instance, REGISTRY

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
            db.execute('CREATE TABLE IF NOT EXISTS dashboard_collections (actor TEXT PRIMARY KEY, revision INTEGER NOT NULL, body TEXT NOT NULL)')

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

    def collection(self, actor, role):
        # Read-only compatibility view: neither legacy preferences nor collection rows are written.
        with self.connect() as db:
            row = db.execute('SELECT revision,body FROM dashboard_collections WHERE actor=?', (actor,)).fetchone()
        body = json.loads(row[1]) if row else {'default_id': 'legacy', 'dashboards': []}
        legacy = self.get(actor)['layout']
        converted = {**legacy, 'widgets': [instance(w['id'], n, size=12 if w['size'] == 'wide' else 6)
                     for n, w in enumerate(legacy['widgets'])
                     if w['id'] in ACTIVE_WIDGETS]}
        x, y, height = 0, 0, 0
        for item in converted['widgets']:
            if x + item['w'] > 12:
                x, y, height = 0, y + height, 0
            item['x'], item['y'] = x, y
            x, height = x + item['w'], max(height, item['h'])
        return {'revision': row[0] if row else 0, **body,
                'legacy': {'id': 'legacy', 'favorite': False, 'layout': converted}}

    def mutate(self, actor, role, payload):
        if not isinstance(payload, dict) or 'revision' not in payload or 'action' not in payload:
            raise DashboardError('대시보드 작업 형식을 확인하세요.')
        revision, action = payload['revision'], payload['action']
        keys = {'create': {'template', 'name'}, 'save': {'id', 'layout'}, 'rename': {'id', 'name'},
                'duplicate': {'id', 'name'}, 'delete': {'id'}, 'default': {'id'}, 'favorite': {'id', 'favorite'}}
        if (type(revision) is not int or not 0 <= revision < 2**31 or not isinstance(action, str)
                or action not in keys or set(payload) != {'revision', 'action'} | keys[action]):
            raise DashboardError('허용된 대시보드 작업과 설정만 사용하세요.')
        if 'name' in payload and not safe_title(payload['name']):
            raise DashboardError('이름은 비밀정보·HTML 없이 1~48자로 입력하세요.')
        if 'id' in payload and (not isinstance(payload['id'], str) or len(payload['id']) > 64):
            raise DashboardError('대시보드 식별자를 확인하세요.')
        if action == 'save' and not valid_layout(payload['layout'], role):
            raise DashboardError('위젯 종류·권한·크기·설정을 확인하세요.')
        if action == 'favorite' and type(payload['favorite']) is not bool:
            raise DashboardError('즐겨찾기 설정을 확인하세요.')
        selected = None
        with self.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            current = db.execute('SELECT revision,body FROM dashboard_collections WHERE actor=?', (actor,)).fetchone()
            if revision != (current[0] if current else 0):
                raise DashboardError('다른 창에서 구성이 바뀌었습니다. 편집을 보존한 뒤 서버 구성을 다시 불러오세요.', 409)
            body = json.loads(current[1]) if current else {'default_id': 'legacy', 'dashboards': []}
            rows = body['dashboards']
            target = next((row for row in rows if row['id'] == payload.get('id')), None)
            if action == 'create':
                key = payload['template']
                if not isinstance(key, str) or key not in (*TEMPLATES, 'legacy'):
                    raise DashboardError('기본 템플릿을 확인하세요.')
                layout = self.collection(actor, role)['legacy']['layout'] if key == 'legacy' else template(key, role)
                layout['name'] = payload['name'].strip()
            elif action == 'duplicate':
                if payload['id'] == 'legacy':
                    layout = self.collection(actor, role)['legacy']['layout']
                elif target:
                    layout = json.loads(json.dumps(target['layout']))
                else:
                    raise DashboardError('대시보드를 찾을 수 없습니다.', 404)
                layout['name'] = payload['name'].strip()
                # Role changes must not duplicate newly forbidden diagnostic widgets.
                layout['widgets'] = [w for w in layout['widgets'] if not REGISTRY[w['type']]['admin'] or role == 'admin']
            elif action == 'default' and payload['id'] == 'legacy':
                body['default_id'] = 'legacy'
                selected = 'legacy'
            elif not target:
                raise DashboardError('대시보드를 찾을 수 없습니다.', 404)
            if action in ('create', 'duplicate'):
                if len(rows) >= 20:
                    raise DashboardError('개인 대시보드는 최대 20개까지 저장할 수 있습니다.')
                selected = secrets.token_hex(16)
                rows.append({'id': selected, 'favorite': False, 'layout': layout})
            elif target:
                selected = target['id']
                if action == 'save':
                    target['layout'] = payload['layout']
                elif action == 'rename':
                    target['layout']['name'] = payload['name'].strip()
                elif action == 'delete':
                    rows.remove(target)
                    if body['default_id'] == selected:
                        body['default_id'] = 'legacy'
                    selected = body['default_id']
                elif action == 'default':
                    body['default_id'] = selected
                elif action == 'favorite':
                    target['favorite'] = payload['favorite']
            encoded = json.dumps(body, ensure_ascii=False)
            if len(encoded.encode('utf-8')) > 256 * 1024:
                raise DashboardError('대시보드 설정 저장 한도를 초과했습니다.')
            db.execute('INSERT INTO dashboard_collections VALUES(?,?,?) ON CONFLICT(actor) DO UPDATE SET revision=excluded.revision,body=excluded.body',
                       (actor, revision + 1, encoded))
            # Return this transaction's snapshot; a later writer must not mix its revision
            # or delete this selected dashboard between commit and response construction.
            result = {'revision': revision + 1, **json.loads(encoded),
                      'legacy': self.collection(actor, role)['legacy'], 'selected_id': selected}
        return result
