"""Manual expiry extension, with one durable dispatch and read-only reconciliation.

No API-key secret is read, issued or returned. Reuse device_operations so backups
retain the attempt barrier together with the device and its audit trail.
"""
import hashlib
import json
import time

from cloud_soc.portal.enrollment import EnrollmentError


SKEW_MS = 5000
DAYS = (1, 7, 30, 90)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def policy(platform):
    return {'cloud_soc_host': {'cluster': ['monitor'], 'indices': [{
        'names': [f'soc-host-raw-{platform}-*', 'soc-agent-health-*'],
        'privileges': ['auto_configure', 'create_doc']}]}}


def normalized_role(role):
    """Accept only harmless server-inserted defaults; unknown grants fail closed."""
    role = dict(role)
    for name in ('applications', 'run_as', 'remote_indices', 'remote_cluster', 'global'):
        if name in role and not role[name]:
            del role[name]
    for name in ('metadata', 'transient_metadata', 'description'):
        if name in role and role[name] in ({}, {'enabled': True}, ''):
            del role[name]
    role['cluster'] = sorted(role.get('cluster', []))
    indices = []
    for entry in role.get('indices', []):
        entry = dict(entry)
        if entry.get('allow_restricted_indices') is False:
            del entry['allow_restricted_indices']
        entry['names'] = sorted(entry['names'])
        entry['privileges'] = sorted(entry['privileges'])
        indices.append(entry)
    role['indices'] = sorted(indices, key=lambda item: json.dumps(item, sort_keys=True))
    return role


def snapshot_covers(limits, expected):
    """Conservative proof of the *whole* assigned policy in every intersection.

    Only exact or simple trailing-star prefixes; no privilege alias, DLS/FLS or restricted role
    inference. Reject equivalent but unprovable policies rather than expanding
    an accidentally narrower key when ES refreshes the owner's snapshot.
    """
    if not isinstance(limits, list) or not limits:
        return False
    for group in limits:
        if not isinstance(group, dict) or not group:
            return False
        roles = [r for r in group.values() if isinstance(r, dict)
                 and not r.get('restriction') and r.get('transient_metadata', {}).get('enabled', True)]
        clusters = {p for r in roles for p in r.get('cluster', [])}
        if not set(expected['cluster']) <= clusters and 'all' not in clusters:
            return False
        for wanted in expected['indices']:
            for name in wanted['names']:
                grants = {p for r in roles for index in r.get('indices', [])
                          if any(pattern == name or pattern.endswith('*') and pattern.count('*') == 1
                                 and not any(c in pattern for c in '?[]') and name.startswith(pattern[:-1])
                                 for pattern in index.get('names', []))
                          and not index.get('query') and not index.get('field_security')
                          for p in index.get('privileges', [])}
                if not set(wanted['privileges']) <= grants and 'all' not in grants:
                    return False
    return True


class KeyExtensions:
    def __init__(self, devices):
        self.devices, self.store = devices, devices.store
        self.clock = time.time

    @staticmethod
    def public(row):
        result = json.loads(row['result'])
        return {k: v for k, v in {**result, 'id': row['id'], 'state': row['state']}.items()
                if k in ('id', 'state', 'key_id', 'days', 'before_expiration', 'target_expiration',
                         'expiration', 'created')}

    def _local(self, db, device_id, key_id):
        device = self.devices._device(db, device_id)
        if device['state'] in ('ended', 'revocation_pending'):
            raise EnrollmentError('device_closed', 409, '종료 또는 접근 차단 중인 장치입니다.')
        package = db.execute('SELECT * FROM packages WHERE id=?', (device['package_id'],)).fetchone()
        key = db.execute('SELECT * FROM issued_keys WHERE id=? AND package_id=?',
                         (key_id, device['package_id'])).fetchone()
        if not package or not key or key['revoked_at'] or key['scope'] != 'host':
            raise EnrollmentError('key_extension_ineligible', 409, '이 장치의 사용 가능한 로그 수집 키가 아닙니다.')
        spec = self.store.public(package)
        if (spec['network'] or spec.get('managed_device_id') != device_id
                or spec['organization'] != device['organization'] or key['organization'] != device['organization']):
            raise EnrollmentError('key_extension_ineligible', 409, '조직 연결이 확인된 로그 전용 장치만 연장할 수 있습니다.')
        sessions = db.execute("SELECT * FROM enrollments WHERE package_id=? AND state='complete'",
                              (device['package_id'],)).fetchall()
        sessions = [s for s in sessions if {'id': key_id, 'scope': 'host'} in
                    [{k: x[k] for k in ('id', 'scope')} for x in json.loads(s['key_ids'])]]
        if len(sessions) != 1 or json.loads(sessions[0]['spec']) != spec:
            raise EnrollmentError('key_extension_ineligible', 409, '설치 완료 기록과 키 연결을 확인할 수 없습니다.')
        return device, key, sessions[0]

    def _client(self):
        # Security updates are never transport-retried: expiration is relative.
        return self.devices.enrollments.issuer.options(max_retries=0, retry_on_timeout=False, request_timeout=5)

    def _remote(self, client, device, session, key_id):
        response = client.security.get_api_key(id=key_id, owner=True, with_limited_by=True)
        # ES's direct HTTP response need not carry Date. Use the already allowed
        # monitor API's actual node clock; never fall back to a guessed timestamp.
        statistics = client.nodes.stats(metric='jvm', filter_path='_nodes,nodes.*.timestamp')
        nodes, counts = statistics.get('nodes'), statistics.get('_nodes', {})
        if (not isinstance(nodes, dict) or not nodes or counts.get('failed') != 0
                or counts.get('successful') != counts.get('total') or counts.get('total') != len(nodes)
                or any(type(node.get('timestamp')) is not int for node in nodes.values())):
            raise EnrollmentError('key_extension_clock', 503, '검색 서버의 시각을 확인하지 못했습니다.')
        if any(abs(node['timestamp'] - self.clock() * 1000) > SKEW_MS for node in nodes.values()):
            raise EnrollmentError('key_extension_clock', 409, '서버 시각 차이가 큽니다. 시각 동기화 후 다시 요청하세요.')
        rows = response.get('api_keys')
        if not isinstance(rows, list) or len(rows) != 1:
            raise ValueError('Unconfirmed owned key')
        row = rows[0]
        expected = policy('windows' if device['os'] == 'windows' else 'linux')
        metadata = row.get('metadata', {})
        if (row.get('id') != key_id or row.get('type') != 'rest' or row.get('invalidated') is not False
                or row.get('name') != self.devices.enrollments.key_name(session['id'], 'host')
                or any(metadata.get(k) != v for k, v in {
                    'package_id': device['package_id'], 'organization': device['organization'],
                    'enrollment_id': session['id'], 'scope': 'host'}.items())
                or type(row.get('expiration')) is not int or row['expiration'] <= self.clock() * 1000
                or set(row.get('role_descriptors', {})) != set(expected)
                or normalized_role(row['role_descriptors']['cloud_soc_host']) != normalized_role(expected['cloud_soc_host'])
                or not snapshot_covers(row.get('limited_by'), expected['cloud_soc_host'])):
            raise EnrollmentError('key_extension_ineligible', 409, '키의 유효기간·소유 연결·최소 권한을 확인할 수 없어 연장하지 않았습니다.')
        owner = client.security.authenticate()
        if (owner.get('authentication_type') != 'realm' or owner.get('username') != row.get('username')
                or owner.get('authentication_realm', {}).get('name') != row.get('realm')):
            raise EnrollmentError('key_extension_owner', 409, '기존 발급 소유자 계정으로만 연장할 수 있습니다.')
        grants = client.security.has_privileges(cluster=['monitor', 'manage_own_api_key'],
                                                index=expected['cloud_soc_host']['indices'])
        if grants.get('has_all_requested') is not True:
            raise EnrollmentError('key_extension_privileges', 409, '발급 계정의 현재 수집 권한이 부족합니다.')
        return row

    @staticmethod
    def _stamp(row):
        return digest({k: row.get(k) for k in ('id', 'name', 'username', 'realm', 'type', 'expiration',
                                               'invalidated', 'metadata', 'role_descriptors', 'limited_by')})

    def preview(self, actor, device_id, request_id, data):
        if (not isinstance(data, dict) or set(data) != {'key_id', 'days'}
                or not isinstance(data['key_id'], str) or not 1 <= len(data['key_id']) <= 256
                or type(data['days']) is not int or data['days'] not in DAYS):
            raise ValueError('키와 연장 기간(1·7·30·90일)을 선택하세요.')
        body = {'device_id': device_id, **data}
        try:
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                existing = self.devices._operation(db, request_id, actor, 'extend_key', body)
                if existing:
                    if existing['device_id'] != device_id:
                        raise ValueError('Device differs')
                    return self.public(existing)
                device, _, session = self._local(db, device_id, data['key_id'])
                pending = db.execute("SELECT * FROM device_operations WHERE device_id=? AND action='extend_key' AND state IN ('preview','attempted','uncertain')", (device_id,)).fetchall()
                if pending:
                    raise EnrollmentError('key_extension_pending', 409, '이 장치에 확인 중인 연장 요청이 있습니다. 기존 요청을 확인하세요.')
                remote = self._remote(self._client(), device, session, data['key_id'])
                target = remote['expiration'] + data['days'] * 86400000
                result = {**data, 'before_expiration': remote['expiration'], 'target_expiration': target,
                          'before_hash': self._stamp(remote), 'created': int(self.clock() * 1000)}
                marker = {'request_id': request_id, 'target_expiration': target}
                result['metadata_hash'] = digest({**remote['metadata'], 'cloud_soc_expiry_extension': marker})
                at = self._now()
                db.execute('INSERT INTO device_operations VALUES (?,?,?,?,?,?,?,?,?)',
                           (request_id, device_id, actor, 'extend_key', digest(body), 'preview', json.dumps(result), at, at))
                self.devices._audit(db, device_id, actor, 'key_extension_preview', request_id)
                return self.public(db.execute('SELECT * FROM device_operations WHERE id=?', (request_id,)).fetchone())
        except (EnrollmentError, ValueError):
            raise
        except Exception:
            raise EnrollmentError('key_extension_unavailable', 503, '키 연장 정보를 확인하거나 저장하지 못했습니다.') from None

    def _operation(self, db, actor, device_id, request_id):
        from cloud_soc.portal.device_management import identifier
        identifier(request_id)
        row = db.execute("SELECT * FROM device_operations WHERE id=? AND device_id=? AND actor=? AND action='extend_key'",
                         (request_id, device_id, actor)).fetchone()
        if row is None:
            raise EnrollmentError('key_extension_not_found', 404, '연장 요청을 찾지 못했습니다.')
        return row

    def cancel(self, actor, device_id, request_id):
        with self.store.connect() as db:
            db.execute('BEGIN IMMEDIATE')
            row = self._operation(db, actor, device_id, request_id)
            if row['state'] == 'preview':
                db.execute("UPDATE device_operations SET state='cancelled',updated=? WHERE id=?", (self._now(), request_id))
                self.devices._audit(db, device_id, actor, 'key_extension_cancelled', request_id)
            elif row['state'] != 'cancelled':
                raise EnrollmentError('key_extension_attempted', 409, '이미 제출한 요청은 취소할 수 없습니다. 서버 결과를 다시 확인하세요.')
            return self.public(db.execute('SELECT * FROM device_operations WHERE id=?', (request_id,)).fetchone())

    def _finish(self, db, row, remote):
        result = {**json.loads(row['result']), 'expiration': remote['expiration']}
        db.execute("UPDATE issued_keys SET expiration=?,server_state='active',checked_at=? WHERE id=? AND revoked_at IS NULL",
                   (remote['expiration'], self._now(), result['key_id']))
        db.execute("UPDATE device_operations SET state='complete',result=?,updated=? WHERE id=?",
                   (json.dumps(result), self._now(), row['id']))
        self.devices._audit(db, row['device_id'], row['actor'], 'key_extension_complete', row['id'])

    @staticmethod
    def _now():
        from cloud_soc.portal.device_management import now
        return now()

    def apply(self, actor, device_id, request_id):
        dispatch = False
        try:
            # This barrier survives process death and local completion failures.
            with self.store.connect() as db:
                db.execute('BEGIN IMMEDIATE')
                row = self._operation(db, actor, device_id, request_id)
                if row['state'] == 'complete':
                    return self.public(row)
                if row['state'] not in ('preview', 'attempted', 'uncertain'):
                    raise EnrollmentError('key_extension_closed', 409, '취소되거나 실패한 연장 요청입니다.')
                data = json.loads(row['result'])
                self._local(db, device_id, data['key_id'])
                if row['state'] == 'preview':
                    if self.clock() * 1000 - data['created'] > 600000:
                        raise EnrollmentError('key_extension_preview_expired', 409, '확인 화면의 유효시간이 지났습니다. 취소 후 다시 선택하세요.')
                    dispatch = True
                    db.execute("UPDATE device_operations SET state='attempted',updated=? WHERE id=?", (self._now(), request_id))
                    self.devices._audit(db, device_id, actor, 'key_extension_requested', request_id)
            with self.store.connect() as db:
                # Serialize our update with device end; end then revokes this same key.
                db.execute('BEGIN IMMEDIATE')
                row = self._operation(db, actor, device_id, request_id)
                if row['state'] == 'complete':
                    return self.public(row)
                device, _, session = self._local(db, device_id, data['key_id'])
                client = self._client()
                remote = self._remote(client, device, session, data['key_id'])
                if dispatch:
                    if self._stamp(remote) != data['before_hash']:
                        raise ValueError('Remote key changed since preview')
                    remaining = data['target_expiration'] - int(self.clock() * 1000)
                    if remaining <= 0:
                        raise ValueError('Expired target')
                    marker = {'request_id': request_id, 'target_expiration': data['target_expiration']}
                    # Preserve binding and other metadata. Explicit immutable grant cap.
                    client.security.update_api_key(id=data['key_id'], expiration=f'{remaining}ms',
                        role_descriptors=policy('windows' if device['os'] == 'windows' else 'linux'),
                        metadata={**remote['metadata'], 'cloud_soc_expiry_extension': marker})
                    remote = self._remote(client, device, session, data['key_id'])
                if (digest(remote['metadata']) != data['metadata_hash']
                        or abs(remote['expiration'] - data['target_expiration']) > SKEW_MS
                        or remote['expiration'] <= data['before_expiration']):
                    raise ValueError('Unconfirmed extension')
                self._finish(db, row, remote)
                return self.public(db.execute('SELECT * FROM device_operations WHERE id=?', (request_id,)).fetchone())
        except EnrollmentError:
            raise
        except Exception:
            # Never echo an upstream response: it may contain authentication details.
            raise EnrollmentError('key_extension_uncertain', 503,
                '연장 완료를 확인하지 못했습니다. 같은 요청의 서버 결과를 다시 확인하세요. 키를 재발급하거나 연장을 중복 제출하지 않습니다.') from None
