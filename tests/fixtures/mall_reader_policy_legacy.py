"""Frozen failing Reader/policy from manifest 9503834c; exec in CLI globals for synthetic replay only."""

LEGACY_SOURCE = r'''
class Reader:
    """Fixed TLS endpoint and read-only operation allowlist, even with a wrong key."""
    def __init__(self, key, ca):
        value = validation_credential(key)
        self.auth = 'ApiKey ' + value['encoded']
        self.expiration = value['expiration']
        try:
            context = ssl.create_default_context(cafile=str(ca))
        except (OSError, ssl.SSLError):
            raise ValidationError('reader_ca_invalid') from None
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(),
            urllib.request.HTTPSHandler(context=context))

    def request(self, method, path, body=None):
        permitted = (method == 'GET' and path == '/_security/user/_privileges' or
                     method == 'POST' and path == '/_security/user/_has_privileges' or
                     method == 'POST' and path in {
                         '/' + index + '/' + operation for index in APPROVED_INDICES for operation in ('_search', '_mget')})
        require(permitted, 'es_operation_forbidden')
        if path.endswith('/_mget'):
            require(isinstance(body, dict) and set(body) == {'ids'} and
                    isinstance(body['ids'], list) and 0 < len(body['ids']) <= MAX_HITS and
                    all(isinstance(identifier, str) and identifier for identifier in body['ids']),
                    'es_operation_forbidden')
        require(self.expiration > int(time.time() * 1000), 'reader_expired')
        req = urllib.request.Request('https://127.0.0.1:19200' + path, method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={'Authorization': self.auth, 'Content-Type': 'application/json'})
        try:
            with self.opener.open(req, timeout=15) as response:
                raw = response.read(16 * 1024 * 1024 + 1)
                require(len(raw) <= 16 * 1024 * 1024, 'es_response_limit')
                return json.loads(raw)
        except urllib.error.HTTPError as error:
            raise ValidationError({401: 'reader_authentication_failed', 403: 'reader_permission_denied'}.get(error.code, 'es_http_error')) from None
        except ssl.SSLCertVerificationError:
            raise ValidationError('es_tls_verification_failed') from None
        except urllib.error.URLError as error:
            if isinstance(error.reason, ssl.SSLCertVerificationError):
                reason = 'es_tls_verification_failed'
            elif isinstance(error.reason, TimeoutError):
                reason = 'es_connection_timeout'
            else:
                reason = 'es_connection_failed'
            raise ValidationError(reason) from None
        except TimeoutError:
            raise ValidationError('es_connection_timeout') from None
        except (ValueError, UnicodeError):
            raise ValidationError('es_response_invalid') from None

def reader_policy(client):
    """Inspect own effective grants, without adding cluster/security privileges."""
    value = client.request('GET', '/_security/user/_privileges')
    require(isinstance(value, dict) and set(value) <= {
        'cluster', 'global', 'indices', 'applications', 'run_as', 'remote_indices', 'remote_cluster', 'data_source'},
        'reader_privilege_response_invalid')
    require(all(value.get(name) == [] for name in ('cluster', 'global', 'applications', 'run_as')) and
            all(not value.get(name) for name in ('remote_indices', 'remote_cluster', 'data_source')),
            'reader_excess_privileges')
    rows = value.get('indices')
    require(isinstance(rows, list) and bool(rows), 'reader_scope_missing')
    for row in rows:
        require(isinstance(row, dict), 'reader_privilege_response_invalid')
        names = row.get('names');grants = row.get('privileges')
        if isinstance(names, str):
            names = [names]
        require(isinstance(names, list) and bool(names) and all(n in APPROVED_INDICES for n in names),
                'reader_excess_index_scope')
        require(isinstance(grants, list) and bool(grants) and
                all(p in ('read', 'view_index_metadata') for p in grants) and
                row.get('allow_restricted_indices') is False, 'reader_excess_privileges')
'''
