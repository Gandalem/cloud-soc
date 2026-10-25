"""Device-owned installation requests. No long-lived publisher secret is stored here."""
from datetime import datetime, timezone
import hashlib
import json
import os
import re
import stat
import uuid

from cryptography.fernet import Fernet, InvalidToken

from cloud_soc.portal.enrollment import EnrollmentError
from cloud_soc.portal.packages import validate_spec
ID = re.compile(r'[a-f0-9]{32}\Z')


def now():
    return datetime.now(timezone.utc).isoformat()


def identifier(value):
    if not isinstance(value, str) or not ID.fullmatch(value):
        raise ValueError('요청 식별자가 올바르지 않습니다.')
    return value


def fingerprint(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=True, sort_keys=True,
                                     separators=(',', ':')).encode()).hexdigest()


def label(value):
    if (not isinstance(value, str) or not 1 <= len(value.strip()) <= 100
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise ValueError('장치 이름은 제어 문자 없는 1~100자로 입력하세요.')
    return value.strip()


class Devices:
    def __init__(self, store, enrollments):
        self.store, self.enrollments = store, enrollments
        self.key_path = store.database.parent / 'device-transfer.key'
        with store.connect() as db:
            db.execute('''CREATE TABLE IF NOT EXISTS managed_devices (
                id TEXT PRIMARY KEY, label TEXT NOT NULL, organization TEXT NOT NULL,
                os TEXT NOT NULL, purpose TEXT NOT NULL, package_id TEXT NOT NULL UNIQUE,
                state TEXT NOT NULL, version INTEGER NOT NULL, created TEXT NOT NULL, updated TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS device_operations (
                id TEXT PRIMARY KEY, device_id TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL,
                fingerprint TEXT NOT NULL, state TEXT NOT NULL, result TEXT NOT NULL,
                created TEXT NOT NULL, updated TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS device_transfers (
                device_id TEXT PRIMARY KEY, operation_id TEXT NOT NULL, enrollment_id TEXT NOT NULL,
                sealed BLOB, created TEXT NOT NULL)''')
            db.execute('''CREATE TABLE IF NOT EXISTS device_audit (
                seq INTEGER PRIMARY KEY, device_id TEXT NOT NULL, actor TEXT NOT NULL,
                action TEXT NOT NULL, operation_id TEXT NOT NULL, at TEXT NOT NULL)''')

    def _cipher(self, *, create=True):
        # This key encrypts ONLY short-lived enrollment handoffs, never publisher keys.
        # It is excluded from backups. Missing/unreadable cached handoffs require explicit renewal.
        path = self.key_path
        if not path.exists():
            if not create:
                raise EnrollmentError('handoff_unavailable', 409, '설치 전달 정보가 없습니다. 기존 등록 정보를 정리하고 갱신하세요.')
            try:
                fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            except FileExistsError:
                pass
            else:
                with os.fdopen(fd, 'wb') as stream:
                    stream.write(Fernet.generate_key())
                    stream.flush()
                    os.fsync(stream.fileno())
        info = path.lstat()
        if (path.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_nlink != 1
                or os.name != 'nt' and info.st_mode & 0o077):
            raise EnrollmentError('handoff_unavailable', 503, '설치 전달 정보를 열 수 없습니다.')
        return Fernet(path.read_bytes())

    @staticmethod
    def _operation(db, request_id, actor, action, body):
        identifier(request_id)
        row = db.execute('SELECT * FROM device_operations WHERE id=?', (request_id,)).fetchone()
        if row and (row['actor'] != actor or row['action'] != action or row['fingerprint'] != fingerprint(body)):
            raise EnrollmentError('device_request_conflict', 409, '같은 요청 ID의 내용 또는 사용자가 다릅니다.')
        return row

    @staticmethod
    def _audit(db, device, actor, action, operation):
        db.execute('INSERT INTO device_audit (device_id,actor,action,operation_id,at) VALUES (?,?,?,?,?)',
                   (device, actor, action, operation, now()))

    def create(self, actor, request_id, data):
        if (not isinstance(data, dict) or set(data) - {'label', 'organization', 'os', 'purpose', 'system', 'network', 'sites'}
                or data.get('purpose') not in ('server', 'web', 'custom')):
            raise ValueError('장치 이름·조직·OS·수집 목적을 확인하세요.')
        display = label(data.get('label'))
        device_id = uuid.uuid4().hex
        spec = validate_spec({'name': 'device-' + device_id, 'organization': data.get('organization'),
            'os': data.get('os'), 'network': data.get('network', False),
            'system': data.get('system', True), 'sites': data.get('sites', [])}, self.store.endpoint)
        from cloud_soc.portal.windows_native import require_scope
        require_scope(spec)
        if data['purpose'] == 'web' and not spec['sites']:
            raise ValueError('웹 서버는 실제 수집할 웹 로그 경로를 지정하세요.')
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            existing = self._operation(db, request_id, actor, 'create', data)
            if existing:
                return self.detail(existing['device_id'])
            if db.execute('SELECT count(*) FROM managed_devices').fetchone()[0] >= 200:
                raise EnrollmentError('device_limit', 409, '장치 관리 한도 200개에 도달했습니다.')
            package = self.store.create({k: spec[k] for k in ('name', 'organization', 'os', 'network', 'system', 'sites')},
                                        connection=db, managed_device_id=device_id)
            at = now()
            db.execute('INSERT INTO managed_devices VALUES (?,?,?,?,?,?,?,1,?,?)',
                (device_id, display, spec['organization'], spec['os'], data['purpose'], package['id'], 'requested', at, at))
            db.execute('INSERT INTO device_operations VALUES (?,?,?,?,?,?,?,?,?)',
                (request_id, device_id, actor, 'create', fingerprint(data), 'complete', '{}', at, at))
            self._audit(db, device_id, actor, 'create', request_id)
        return self.detail(device_id)

    def _device(self, db, device_id):
        identifier(device_id)
        row = db.execute('SELECT * FROM managed_devices WHERE id=?', (device_id,)).fetchone()
        if row is None:
            raise KeyError(device_id)
        return dict(row)

    def detail(self, device_id):
        with self.store.connect() as db:
            device = self._device(db, device_id)
            sessions = db.execute('SELECT * FROM enrollments WHERE package_id=? ORDER BY created DESC,id DESC',
                                  (device['package_id'],)).fetchall()
            keys = [self.store.public_key(r) for r in db.execute(
                'SELECT * FROM issued_keys WHERE package_id=? ORDER BY created_at DESC,id', (device['package_id'],))]
            transfer = db.execute('SELECT enrollment_id FROM device_transfers WHERE device_id=?', (device_id,)).fetchone()
            operations = [dict(r) for r in db.execute(
                'SELECT id,action,state,created,updated FROM device_operations WHERE device_id=? ORDER BY created DESC,id LIMIT 20', (device_id,))]
        latest = next((s for s in sessions if transfer and s['id'] == transfer['enrollment_id']), None)
        complete = next((s for s in sessions if s['state'] == 'complete'), None)
        state = device['state']
        if state not in ('ended', 'revocation_pending'):
            state = 'received' if complete else 'awaiting_receipt' if latest and latest['state'] == 'issued' else 'requested'
            if latest and latest['state'] in ('issuing', 'cleanup_pending'):
                state = 'attention'
            if next((o['state'] for o in operations if o['action'] == 'prepare'), None) == 'uncertain':
                state = 'attention'
            if latest and latest['state'] == 'unused' and latest['expires'] <= int(self.enrollments.clock()):
                state = 'registration_expired'
            if keys and any(k['status'] in ('expired', 'revoked', 'unavailable', 'missing') for k in keys):
                state = 'attention'
        device.update(state=state, keys=keys, operations=operations,
            registration=self.enrollments.public(latest) if latest else None,
            receipt_at=datetime.fromtimestamp(complete['completed'], timezone.utc).isoformat() if complete and complete['completed'] else None,
            agents=json.loads(complete['agents']) if complete and complete['agents'] else {},
            service_state='unknown', analysis_state='unknown', uninstalled=False)
        # An installation probe proves initial transport, not live heartbeat, ordinary logs or detection.
        return device

    def listing(self, *, view='active', query='', page=1, size=25):
        if (view not in ('active', 'attention', 'history', 'all') or not isinstance(query, str) or len(query) > 100
                or type(page) is not int or not 1 <= page <= 10000 or type(size) is not int or not 1 <= size <= 100):
            raise ValueError('장치 조회 조건을 확인하세요.')
        with self.store.connect() as db:
            ids = [r[0] for r in db.execute('SELECT id FROM managed_devices ORDER BY created DESC,id')]
        rows = [self.detail(i) for i in ids]
        rows = [r for r in rows if (view == 'all' or (view == 'history' and r['state'] == 'ended')
                or (view == 'active' and r['state'] != 'ended')
                or (view == 'attention' and r['state'] in ('attention', 'registration_expired', 'revocation_pending')))
                and query.casefold() in ' '.join(str(r[k]) for k in ('id', 'label', 'organization', 'os')).casefold()]
        return {'devices': rows[(page-1)*size:page*size], 'total': len(rows), 'page': page, 'size': size}

    def prepare(self, actor, device_id, request_id, data):
        if (not isinstance(data, dict) or set(data) != {'renew', 'days'} or type(data['renew']) is not bool
                or type(data['days']) is not int or data['days'] not in (1, 7, 30, 90)):
            raise ValueError('등록 정보 갱신 여부와 키 유효 기간을 확인하세요.')
        body = {'device_id': device_id, **data}
        # Reject unsupported/unavailable native releases before minting a handoff.
        device_spec = self.store.get(self.detail(device_id)['package_id'])
        from cloud_soc.portal.windows_native import require_scope, release
        require_scope(device_spec)
        if device_spec['os'] == 'windows':
            release(self.store)
        cipher = self._cipher()
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            device = self._device(db, device_id)
            existing = self._operation(db, request_id, actor, 'prepare', body)
            if existing:
                if existing['state'] == 'complete':
                    return self.detail(device_id)
                raise EnrollmentError('registration_uncertain', 409, '이전 발급 결과를 확인한 후 등록 정보를 갱신하세요.')
            if device['state'] in ('ended', 'revocation_pending'):
                raise EnrollmentError('device_closed', 409, '종료 또는 차단 중인 장치는 등록할 수 없습니다.')
            old = db.execute('SELECT e.* FROM device_transfers t JOIN enrollments e ON e.id=t.enrollment_id WHERE t.device_id=?', (device_id,)).fetchone()
            if old and old['state'] in ('issued', 'complete'):
                raise EnrollmentError('device_already_registered', 409, '이미 키가 전달된 장치입니다. 상태 확인 또는 명시적 복구 절차를 사용하세요.')
            if old and not data['renew']:
                if old['state'] == 'unused' and old['expires'] > int(self.enrollments.clock()):
                    return self.detail(device_id)
                raise EnrollmentError('registration_renew_required', 409, '이전 등록 상태를 확인하고 등록 정보 갱신을 선택하세요.')
            pending = db.execute("SELECT 1 FROM device_operations WHERE device_id=? AND action='prepare' AND state='preparing'", (device_id,)).fetchone()
            if pending and not data['renew']:
                raise EnrollmentError('registration_in_progress', 409, '진행 중인 등록 준비가 있습니다. 상태를 확인하세요.')
            if pending:
                db.execute("UPDATE device_operations SET state='uncertain',updated=? WHERE device_id=? AND action='prepare' AND state='preparing'", (now(), device_id))
            abandoned = db.execute("SELECT * FROM enrollments WHERE package_id=? AND state!='complete'", (device['package_id'],)).fetchall()
            generation = device['version'] + 1
            db.execute('UPDATE managed_devices SET version=?,updated=? WHERE id=?', (generation, now(), device_id))
            at = now()
            db.execute('INSERT INTO device_operations VALUES (?,?,?,?,?,?,?,?,?)',
                (request_id, device_id, actor, 'prepare', fingerprint(body), 'preparing', '{}', at, at))
            self._audit(db, device_id, actor, 'prepare_requested', request_id)
        try:
            for previous in abandoned:
                self._revoke_session(previous)
                self.enrollments.cancel(previous['id'])
            reply = self.enrollments.mint(device['package_id'], {'days': data['days'], 'target_label': device['label']}, sid=request_id)
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                current = self._device(db, device_id)
                if current['state'] in ('ended', 'revocation_pending') or current['version'] != generation:
                    raise RuntimeError('Device was closed during preparation')
                db.execute('INSERT INTO device_transfers VALUES (?,?,?,?,?) ON CONFLICT(device_id) DO UPDATE SET operation_id=excluded.operation_id,enrollment_id=excluded.enrollment_id,sealed=excluded.sealed,created=excluded.created',
                    (device_id, request_id, reply['id'], cipher.encrypt(json.dumps(reply).encode()), now()))
                db.execute("UPDATE device_operations SET state='complete',updated=? WHERE id=?", (now(), request_id))
                self._audit(db, device_id, actor, 'prepare_complete', request_id)
        except Exception:
            try:
                self.enrollments.cancel(request_id)
            except (EnrollmentError, KeyError, OSError):
                pass
            # The deterministic session ID remains discoverable even when the local handoff commit failed.
            with self.store.connect() as db:
                db.execute("UPDATE device_operations SET state='uncertain',updated=? WHERE id=?", (now(), request_id))
            raise EnrollmentError('registration_uncertain', 503, '등록 준비를 완료하지 못했습니다. 같은 장치의 상태를 확인한 뒤 갱신하세요.') from None
        return self.detail(device_id)

    def download(self, device_id):
        device = self.detail(device_id)
        with self.store.connect() as db:
            row = db.execute('SELECT t.*,e.state,e.expires,e.package_sha256 FROM device_transfers t JOIN enrollments e ON e.id=t.enrollment_id WHERE t.device_id=?', (device_id,)).fetchone()
        if device['state'] in ('ended', 'revocation_pending') or not row or row['state'] != 'unused' or row['expires'] <= int(self.enrollments.clock()):
            raise EnrollmentError('download_unavailable', 409, '사용 가능한 신규 설치 정보가 없습니다. 장치 상태를 확인하세요.')
        try:
            reply = json.loads(self._cipher(create=False).decrypt(row['sealed']))
        except (InvalidToken, TypeError, ValueError):
            raise EnrollmentError('handoff_unavailable', 409, '설치 전달 정보가 없습니다. 기존 등록 정보를 정리하고 갱신하세요.') from None
        package, archive = self.store.get(device['package_id'], archive=True)
        # The original archive hash remains the existing enrollment contract. The outer handoff is separate.
        from cloud_soc.portal.device_bundle import bundle
        native = None
        if package['os'] == 'windows':
            from cloud_soc.portal.windows_native import require_scope, release
            require_scope(package)
            native = release(self.store)
        return bundle(package, archive, {'device_id': device_id, 'enrollment_id': row['enrollment_id'],
            'token': reply['token'], 'expires': row['expires'], 'package_sha256': row['package_sha256']}, native=native), f"device-{device_id}-install.zip"

    def activity(self, device_id):
        device = self.detail(device_id)
        if self.enrollments.monitor is None:
            raise EnrollmentError('activity_unavailable', 503, '수신 조회 계정에 연결하지 못했습니다.')
        with self.store.connect() as db:
            sessions = db.execute("SELECT * FROM enrollments WHERE package_id=? AND state='complete'", (device['package_id'],)).fetchall()
        latest = None
        references = []
        try:
            from cloud_soc.portal.status_setup import PIPELINE_ID
            for session in sessions:
                agents = json.loads(session['agents'])
                for key in json.loads(session['key_ids']):
                    scope = key['scope']
                    platform = 'windows' if device['os'] == 'windows' else 'linux'
                    index = f'soc-host-raw-{platform}-*' if scope == 'host' else f'soc-network-{platform}-*'
                    terms = {'agent.id': agents[scope], 'organization.id': device['organization'],
                        'cloud_soc_enrollment.id': session['id'], 'cloud_soc_enrollment.key_id': key['id']}
                    result = self.enrollments.monitor.search(index=index, size=1, allow_no_indices=True,
                        ignore_unavailable=True, allow_partial_search_results=False,
                        query={'bool': {'filter': [{'term': {k: v}} for k, v in terms.items()],
                                        'must_not': [{'term': {'event.action': 'installation_probe'}}]}},
                        sort=[{'event.ingested': {'order': 'desc', 'unmapped_type': 'date'}}],
                        source=['event.ingested'])
                    if result.get('timed_out') is not False or result.get('_shards', {}).get('failed') != 0:
                        raise RuntimeError('Partial activity query')
                    for hit in result['hits']['hits']:
                        if not isinstance(hit.get('_index'), str) or not hit['_index'].startswith(index[:-1]):
                            raise RuntimeError('Unexpected activity index')
                        configured = self.enrollments.monitor.indices.get_settings(index=hit['_index'], flat_settings=True)
                        if configured[hit['_index']]['settings'].get('index.final_pipeline') != PIPELINE_ID:
                            raise RuntimeError('Untrusted activity index')
                        at = hit.get('_source', {}).get('event', {}).get('ingested')
                        parsed = datetime.fromisoformat(at.replace('Z', '+00:00'))
                        if parsed.tzinfo is None:
                            raise RuntimeError('Naive ingestion timestamp')
                        parsed = parsed.astimezone(timezone.utc)
                        if latest is None or parsed > latest:
                            latest = parsed
                        references.append({'index': hit['_index'], 'id': hit['_id'], 'scope': scope})
        except Exception:
            raise EnrollmentError('activity_unavailable', 503, '일반 로그 수신을 확인하지 못했습니다. 정상이나 경보 0건으로 처리하지 않습니다.') from None
        return {'device_id': device_id, 'observed_at': latest.isoformat() if latest else None,
                'references': references, 'heartbeat': 'unknown', 'analysis': 'unknown'}

    def _revoke_session(self, session):
        spec = json.loads(session['spec'])
        for scope in self.enrollments.scopes(spec):
            name = self.enrollments.key_name(session['id'], scope)
            keys = self.enrollments.issuer.security.get_api_key(name=name, owner=True).get('api_keys')
            if not isinstance(keys, list):
                raise RuntimeError('Unconfirmed owned keys')
            for key in keys:
                if (key.get('name') != name or key.get('metadata', {}).get('package_id') != session['package_id']
                        or key.get('metadata', {}).get('organization') != spec['organization']):
                    raise RuntimeError('Remote key binding differs')
            result = self.enrollments.issuer.security.invalidate_api_key(name=name, owner=True)
            if type(result.get('error_count')) is not int or result['error_count'] != 0:
                raise RuntimeError('Remote revocation failed')
            after = self.enrollments.issuer.security.get_api_key(name=name, owner=True).get('api_keys')
            if not isinstance(after, list) or any(k.get('name') != name or k.get('invalidated') is not True for k in after):
                raise RuntimeError('Remote revocation unconfirmed')
            confirmed = set(result.get('invalidated_api_keys', [])) | set(result.get('previously_invalidated_api_keys', []))
            confirmed |= {k['id'] for k in after if isinstance(k.get('id'), str)}
            if any(k['id'] not in confirmed for k in keys):
                raise RuntimeError('Remote key disappeared without confirmation')
            for key in keys:
                self.store.mark_revoked(key['id'])
            for known in json.loads(session['key_ids']):
                if known['id'] in confirmed:
                    self.store.mark_revoked(known['id'])

    def end(self, actor, device_id, request_id):
        body = {'device_id': device_id}
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            device = self._device(db, device_id)
            operation = self._operation(db, request_id, actor, 'end', body)
            if operation and operation['state'] == 'complete':
                return self.detail(device_id)
            if not operation:
                at = now()
                db.execute('INSERT INTO device_operations VALUES (?,?,?,?,?,?,?,?,?)',
                    (request_id, device_id, actor, 'end', fingerprint(body), 'pending', '{}', at, at))
                self._audit(db, device_id, actor, 'end_requested', request_id)
            db.execute("UPDATE managed_devices SET state='revocation_pending',version=version+1,updated=? WHERE id=?", (now(), device_id))
            # Include failed preparation reservations: a crash may precede the transfer link commit.
            sessions = db.execute('SELECT * FROM enrollments WHERE package_id=?', (device['package_id'],)).fetchall()
        try:
            for session in sessions:
                self._revoke_session(session)
                if session['state'] != 'complete':
                    self.enrollments.cancel(session['id'])
            with self.store.connect() as db:
                unresolved = db.execute('SELECT id FROM issued_keys WHERE package_id=? AND revoked_at IS NULL', (device['package_id'],)).fetchall()
            if unresolved:
                raise RuntimeError('Unconfirmed local key histories remain')
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                db.execute("UPDATE managed_devices SET state='ended',updated=? WHERE id=?", (now(), device_id))
                db.execute('UPDATE device_transfers SET sealed=NULL WHERE device_id=?', (device_id,))
                db.execute("UPDATE device_operations SET state='complete',updated=? WHERE id=?", (now(), request_id))
                self._audit(db, device_id, actor, 'end_complete', request_id)
        except Exception:
            with self.store.connect() as db:
                db.execute("UPDATE device_operations SET state='uncertain',updated=? WHERE id=?", (now(), request_id))
            raise EnrollmentError('device_revocation_pending', 503, '접근 차단을 모두 확인하지 못했습니다. 같은 요청을 재시도하세요. 장치 자료는 삭제하지 않았습니다.') from None
        return self.detail(device_id)
