"""Admin-only package API. Production entry point is Gunicorn behind TLS."""

import argparse
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import ssl
import threading
from urllib.parse import urlsplit

from elasticsearch import Elasticsearch
from flask import Flask, abort, g, jsonify, redirect, request, send_file, send_from_directory

from cloud_soc.portal.packages import PackageStore, validate_endpoint
from cloud_soc.portal.agent_status import decode_cursor, snapshot
from cloud_soc.portal.log_query import LogReader, LogQueryError
from cloud_soc.portal.collection_health import snapshot as health_snapshot
from cloud_soc.portal.collection_components import snapshot as component_snapshot
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.cases import CaseStore, CaseError
from cloud_soc.portal.auth import COOKIE, PUBLIC, Sessions, load_users, permitted
from cloud_soc.portal.basic_auth import BasicAuthGuard
from cloud_soc.privacy import redact_metadata
from cloud_soc.logging_config import configure_logging
from cloud_soc.portal.enrollment import Enrollments, EnrollmentError
from cloud_soc.portal.log_access import LogAccessPolicy, LogPrincipal, read_policy
from cloud_soc.portal.source_access import ProtectedSourceReader, SourceAudit
from cloud_soc.portal.mall_scope import read_scope, validate_scope
from cloud_soc.portal.mall_investigation import MallInvestigation
from cloud_soc.portal.rule_management import RuleDraftStore, RuleError
from cloud_soc.portal.rule_library import RuleLibrary
from cloud_soc.portal.insight_state import InsightStore, InsightError
from cloud_soc.portal.dashboard_insights import InsightReader, evidence_flow
from cloud_soc.portal.agent_status import parse_time as datetime_from_iso

PROJECT = Path(__file__).resolve().parents[3]


def settings_from_environment():
    def secret(name):
        value = Path(os.environ[name]).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError(f"Empty secret file: {name}")
        return value

    from cloud_soc.processing.mall_runtime import private_json
    ca_path = Path(os.environ["SOC_CA_FILE"])
    ca = ca_path.read_bytes()
    # Reject malformed certificates before making downloadable bundles.
    ssl.create_default_context(cadata=ca.decode("ascii"))
    public_url = os.environ["SOC_PUBLIC_URL"].rstrip("/")
    parsed = urlsplit(public_url)
    if (not parsed.hostname or parsed.port == 0 or parsed.path or parsed.query or parsed.fragment or parsed.username
            or parsed.scheme not in ("https", "http")
            or (parsed.scheme == "http" and parsed.hostname not in ("127.0.0.1", "localhost"))):
        raise ValueError("SOC_PUBLIC_URL must be an HTTPS origin (HTTP only on loopback)")
    return {
        "STATE_DIR": Path(os.environ.get("SOC_STATE_DIR", "state/portal")),
        "AGENT_SOURCE": PROJECT / "deploy" / "agents",
        "WINDOWS_INSTALLER_DIR": os.environ.get('SOC_WINDOWS_INSTALLER_DIR'),
        "WINDOWS_INSTALLER_SHA256": os.environ.get('SOC_WINDOWS_INSTALLER_SHA256'),
        "WINDOWS_INSTALLER_ALLOW_LAB": os.environ.get('SOC_WINDOWS_INSTALLER_ALLOW_LAB') == '1',
        "CA_BYTES": ca,
        "PUBLIC_URL": public_url,
        "LAN_URL": os.environ.get("SOC_PORTAL_LAN_ORIGIN"),
        "USERS_FILE": os.environ.get("SOC_USERS_FILE"),
        "RUNTIME_CONTRACT_FILE": os.environ.get('SOC_RUNTIME_CONTRACT_FILE'),
        "NOTIFICATION_STATE_DIR": os.environ.get('SOC_NOTIFICATION_STATE_DIR'),
        "ENROLLMENT_ENABLED": os.environ.get("SOC_ENROLLMENT_ENABLED") == "1",
        "ENDPOINT": validate_endpoint(os.environ.get("SOC_AGENT_ENDPOINT") or os.environ["SOC_ELASTIC_ENDPOINT"]),
        "ADMIN_USER": os.environ.get("SOC_ADMIN_USER", "admin"),
        "ADMIN_HASH": secret("SOC_ADMIN_HASH_FILE"),
        "ES_URL": os.environ["SOC_INTERNAL_ES_URL"],
        "ES_PASSWORD": secret("SOC_ISSUER_PASSWORD_FILE"),
        "CA_FILE": str(ca_path),
        "MONITOR_PASSWORD": secret("SOC_MONITOR_PASSWORD_FILE") if os.environ.get("SOC_MONITOR_PASSWORD_FILE") else None,
        "PORTAL_READ_API_KEY": secret("SOC_PORTAL_READ_API_KEY_FILE") if os.environ.get("SOC_PORTAL_READ_API_KEY_FILE") else None,
        "PROCESSING_SCOPE": private_json(os.environ['SOC_PROCESSING_SCOPE_FILE']) if os.environ.get('SOC_PROCESSING_SCOPE_FILE') else None,
        "MANAGED_WORKER_CONFIG": private_json(os.environ['SOC_MANAGED_WORKER_CONFIG_FILE']) if os.environ.get('SOC_MANAGED_WORKER_CONFIG_FILE') else None,
        "GEOIP_DATABASE": os.environ.get("SOC_GEOIP_DATABASE"),
        "HEARTBEAT_TLS_PROXIES": tuple(x.strip() for x in os.environ.get("SOC_HEARTBEAT_TLS_PROXIES", "").split(",") if x.strip()),
        "MALL_LAB_SCOPE": read_scope(os.environ.get('SOC_MALL_LAB_SCOPE_FILE')),
        "MALL_TRIAGE_SNAPSHOT_FILE": os.environ.get('SOC_MALL_TRIAGE_SNAPSHOT_FILE'),
        "LOG_ACCESS_POLICY": read_policy(os.environ["SOC_LOG_ACCESS_POLICY_FILE"]) if os.environ.get("SOC_LOG_ACCESS_POLICY_FILE") else None,
    }


def create_app(settings=None, *, issuer=None, monitor=None):
    configure_logging()
    settings = settings if settings is not None else settings_from_environment()
    origins = {urlsplit(settings["PUBLIC_URL"]).netloc.lower(): settings["PUBLIC_URL"]}
    if settings.get("LAN_URL"):
        lan = urlsplit(settings["LAN_URL"])
        try:
            address = ipaddress.ip_address(lan.hostname)
        except ValueError as error:
            raise ValueError("SOC_PORTAL_LAN_ORIGIN must be a private HTTPS IP origin") from error
        if (lan.scheme != "https" or lan.username or lan.password or lan.path or lan.query or lan.fragment
                or lan.port not in (None, 443) or not address.is_private or address.is_unspecified or address.is_multicast):
            raise ValueError("SOC_PORTAL_LAN_ORIGIN must be a private HTTPS IP origin")
        host = f"[{address}]" if address.version == 6 else str(address)
        origins[host] = f"https://{host}"
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=8192, TRUSTED_HOSTS=[urlsplit(origin).hostname for origin in origins.values()])
    store = PackageStore(Path(settings["STATE_DIR"]), Path(settings["AGENT_SOURCE"]), settings["CA_BYTES"], settings["ENDPOINT"],
                         portal_url=settings["PUBLIC_URL"] if settings["PUBLIC_URL"].startswith("https://") else None,
                         windows_installer_dir=settings.get('WINDOWS_INSTALLER_DIR'),
                         windows_installer_sha256=settings.get('WINDOWS_INSTALLER_SHA256'),
                         windows_installer_allow_lab=settings.get('WINDOWS_INSTALLER_ALLOW_LAB', False))
    app.extensions["packages"] = store
    users = load_users(settings["USERS_FILE"]) if settings.get("USERS_FILE") else None
    sessions = Sessions(Path(settings["STATE_DIR"]) / "sessions.sqlite", users) if users else None
    app.extensions["sessions"] = sessions
    if issuer is None:
        issuer = Elasticsearch(settings["ES_URL"], basic_auth=("cloud_soc_issuer", settings["ES_PASSWORD"]),
                               ca_certs=settings["CA_FILE"], request_timeout=5, max_retries=0)
    app.extensions["issuer"] = issuer
    if monitor is None and settings.get('PORTAL_READ_API_KEY'):
        monitor = Elasticsearch(settings['ES_URL'], api_key=settings['PORTAL_READ_API_KEY'],
                                ca_certs=settings['CA_FILE'], request_timeout=5, max_retries=0)
    if monitor is None and settings.get("MONITOR_PASSWORD"):
        monitor = Elasticsearch(settings["ES_URL"], basic_auth=("cloud_soc_agent_monitor", settings["MONITOR_PASSWORD"]),
                                ca_certs=settings["CA_FILE"], request_timeout=5, max_retries=0)
    app.extensions["monitor"] = monitor
    enrollments = Enrollments(store, issuer, monitor)
    app.extensions["enrollments"] = enrollments
    from cloud_soc.portal.device_management import Devices
    devices = Devices(store, enrollments)
    app.extensions['managed_devices'] = devices
    access_policy = LogAccessPolicy(settings["ADMIN_USER"], settings["ADMIN_HASH"], settings.get("LOG_ACCESS_POLICY"))
    basic_guard = BasicAuthGuard(Path(settings["STATE_DIR"]) / "basic-auth.sqlite", access_policy) if sessions is None else None
    app.extensions["basic_auth"] = basic_guard
    if users:
        for username, policy_user in access_policy.users.items():
            if username in users:
                expected_role = "analyst" if policy_user[1] == "investigator" else "viewer"
                if users[username]["role"] != expected_role:
                    raise ValueError("Session and log access roles must agree")
    audit = SourceAudit(Path(settings["STATE_DIR"]) / "log-access.sqlite")
    app.extensions["log_access"] = access_policy
    app.extensions["source_audit"] = audit
    from cloud_soc.portal.dashboards import DashboardStore, DashboardError
    dashboards = DashboardStore(Path(settings['STATE_DIR']) / 'dashboards.sqlite')
    app.extensions['dashboards'] = dashboards
    from cloud_soc.notifications.store import SlackStore
    from cloud_soc.notifications.transport import SlackError, addresses
    slack = SlackStore(settings.get('NOTIFICATION_STATE_DIR') or Path(settings['STATE_DIR']) / 'notifications')
    app.extensions['slack'] = slack

    @app.errorhandler(SlackError)
    def slack_error(error):
        messages = {'invalid_slack_webhook': 'Slack 공식 Incoming Webhook 주소를 확인하세요.',
            'slack_address_unavailable': 'Slack 연결 주소를 확인하지 못했습니다. 잠시 후 다시 시도하세요.',
            'slack_settings_changed': '다른 작업에서 설정이 변경됐습니다. 새로고침 후 다시 저장하세요.',
            'slack_webhook_required': 'Webhook을 먼저 등록하세요.',
            'slack_duplicate_risk_confirmation_required': '이미 수신됐을 수 있습니다. 중복 위험을 확인해야 재전송할 수 있습니다.',
            'slack_manual_retry_unavailable': '설정 변경 전 이력이거나 현재 재전송할 수 없는 상태입니다.',
            'slack_manual_retry_rate_limited': '테스트·수동 재전송 요청이 많습니다. 잠시 후 다시 시도하세요.',
            'slack_test_rate_limited': '테스트 요청이 많습니다. 잠시 후 다시 시도하세요.'}
        response = jsonify(code=error.code, error=messages.get(error.code, 'Slack 설정을 처리하지 못했습니다. 입력과 서버 상태를 확인하세요.'))
        response.status_code = error.status
        if error.status == 429:
            response.headers['Retry-After'] = '30'
        return response

    def slack_request(*, allow_args=False):
        if g.role != 'admin' or request.args and not allow_args:
            abort(403)
        if request.method != 'GET' and not sessions and request.headers.get('Origin') not in origins.values():
            abort(403)

    @app.get('/api/settings/notifications/slack')
    def slack_settings_get():
        slack_request()
        return jsonify(slack.status())

    @app.post('/api/settings/notifications/slack')
    def slack_settings_save():
        slack_request()
        return jsonify(slack.save(request.get_json(), check_address=addresses))

    @app.delete('/api/settings/notifications/slack')
    def slack_settings_delete():
        slack_request();body = request.get_json()
        if not isinstance(body, dict) or set(body) != {'revision'}:
            raise SlackError('invalid_slack_settings')
        return jsonify(slack.delete(body['revision']))

    @app.post('/api/settings/notifications/slack/test')
    def slack_settings_test():
        slack_request()
        if request.get_json() != {}:
            raise SlackError('invalid_slack_settings')
        return jsonify(slack.test()), 202

    @app.get('/api/settings/notifications/slack/unconfirmed')
    def slack_unconfirmed_get():
        slack_request(allow_args=True)
        offset = request.args.get('offset', '0')
        if set(request.args) - {'offset'} or len(request.args.getlist('offset')) > 1 or not offset.isascii() or not offset.isdigit() or len(offset) > 6:
            raise SlackError('invalid_slack_settings')
        return jsonify(slack.unconfirmed(int(offset)))

    @app.post('/api/settings/notifications/slack/retry')
    def slack_unconfirmed_retry():
        slack_request()
        return jsonify(slack.retry_unconfirmed(request.get_json(), actor=g.principal)), 202

    @app.errorhandler(DashboardError)
    def dashboard_error(error):
        return jsonify(error=str(error)), error.status

    @app.get('/api/dashboard')
    def dashboard_get():
        if request.args:
            abort(400)
        try:
            return jsonify(dashboards.get(g.principal))
        except sqlite3.Error:
            return jsonify(error='대시보드 구성을 불러오지 못했습니다. 잠시 후 다시 시도하세요.'), 503

    @app.post('/api/dashboard')
    def dashboard_save():
        if request.args:
            abort(400)
        try:
            return jsonify(dashboards.save(g.principal, request.get_json()))
        except sqlite3.Error:
            return jsonify(error='구성을 저장하지 못했습니다. 편집 내용은 유지됩니다. 다시 시도하세요.'), 503

    @app.get('/api/dashboards')
    def dashboards_get():
        from cloud_soc.portal.dashboard_widgets import catalog, TEMPLATES, template
        if request.args:
            abort(400)
        try:
            return jsonify(**dashboards.collection(g.principal, g.role), catalog=catalog(g.role),
                           templates=[{'id': key, 'name': value[0], 'layout': template(key, g.role)} for key, value in TEMPLATES.items()])
        except sqlite3.Error:
            return jsonify(error='대시보드 목록을 불러오지 못했습니다.'), 503

    @app.post('/api/dashboards')
    def dashboards_write():
        if request.args:
            abort(400)
        try:
            return jsonify(dashboards.mutate(g.principal, g.role, request.get_json()))
        except sqlite3.Error:
            return jsonify(error='저장하지 못했습니다. 편집 내용은 유지됩니다.'), 503
    log_readers = {}
    log_reader_lock = threading.Lock()
    def reader_for(principal):
        # Fixed startup principals, at most 20 read-only identities + admin.
        with log_reader_lock:
            if principal.username not in log_readers:
                log_readers[principal.username] = LogReader(monitor, secret=settings["ADMIN_HASH"],
                    principal=settings["PUBLIC_URL"] + "/" + principal.cursor_principal,
                    organizations=principal.organizations, mall_scope=mall_scope)
            return log_readers[principal.username]
    mall_scope = validate_scope(settings.get('MALL_LAB_SCOPE'))
    try:
        mall_investigation = MallInvestigation.from_file(settings.get('MALL_TRIAGE_SNAPSHOT_FILE'), mall_scope)
    except (OSError, ValueError, TypeError, KeyError, sqlite3.Error):
        mall_investigation = None
        app.logger.warning('Mall investigation snapshot unavailable; existing alert access retained.')
    processing_scope=settings.get('PROCESSING_SCOPE')
    managed_config=settings.get('MANAGED_WORKER_CONFIG')
    managed_library=Path(settings['STATE_DIR'])/'cases.sqlite'
    operations = Operations(monitor, mall_scope=mall_scope, processing_scope=processing_scope,
                            managed_library=managed_library, managed_config=managed_config)
    def operations_for(principal):
        # Per-request instances ensure evidence hashes are rechecked, including for admins.
        return Operations(monitor, organizations=principal.organizations, mall_scope=mall_scope,
                          mall_investigation=mall_investigation, principal=principal, processing_scope=processing_scope,
                          managed_library=managed_library, managed_config=managed_config)

    case_organizations = None
    if users:
        case_organizations = {name: None if row["role"] == "admin" else access_policy.users.get(name, (None, None, ()))[2]
                              for name, row in users.items()}
    cases = CaseStore(Path(settings["STATE_DIR"]) / "cases.sqlite", settings["ADMIN_USER"],
                      principals=set(users) if users else None,
                      owners={name for name, row in users.items() if row["role"] != "viewer"} if users else None,
                      organizations=case_organizations)
    app.extensions["cases"] = cases
    insights = InsightStore(Path(settings["STATE_DIR"]) / "dashboard-insights.sqlite")
    app.extensions["insights"] = insights
    insight_readers = {}
    insight_lock = threading.Lock()
    rule_organizations = set(access_policy.admin_source_organizations)
    for policy_user in access_policy.users.values():
        rule_organizations.update(policy_user[2])
    rule_drafts = RuleDraftStore(cases.path, rule_organizations)
    app.extensions['rule_drafts'] = rule_drafts
    rule_library = RuleLibrary(cases.path, rule_organizations)
    app.extensions['rule_library'] = rule_library

    @app.errorhandler(RuleError)
    def rule_error(error):
        return jsonify(code=error.code, error=str(error)), error.status

    def rule_request():
        if g.role != 'admin' or request.args:
            abort(403 if g.role != 'admin' else 400)

    def library_response(operation, status=200):
        rule_request()
        # Preserve the small default on every other API. JSON file content can
        # expand sixfold through escaping, while the decoded file stays <=256KiB.
        request.max_content_length = 2 * 1024 * 1024 if request.endpoint == 'rule_library_import' else 65536
        try:
            return jsonify(operation()), status
        except sqlite3.Error:
            return jsonify(code='rule_storage_unavailable', error='규칙을 저장하거나 조회하지 못했습니다.'), 503

    @app.get('/api/settings/rule-library')
    def rule_library_list():
        return library_response(lambda: rule_library.listing(g.log_principal))

    @app.post('/api/settings/rule-library')
    def rule_library_create():
        return library_response(lambda: rule_library.create(request.get_json(), g.log_principal), 201)

    @app.get('/api/settings/rule-library/<identifier>')
    def rule_library_detail(identifier):
        return library_response(lambda: rule_library.detail(identifier, g.log_principal))

    @app.post('/api/settings/rule-library/<identifier>/<action>')
    def rule_library_action(identifier, action):
        return library_response(lambda: rule_library.action(identifier, action, request.get_json(), g.log_principal))

    @app.post('/api/settings/rule-library/import/<mode>')
    def rule_library_import(mode):
        if mode not in ('preview', 'create'):
            abort(404)
        return library_response(lambda: rule_library.import_rules(request.get_json(), g.log_principal, preview=mode == 'preview'))

    @app.get('/api/settings/rule-library/export')
    def rule_library_export():
        rule_request()
        response = jsonify(rule_library.export(g.log_principal))
        response.headers['Content-Disposition'] = 'attachment; filename="rules.json"'
        return response

    @app.get('/api/settings/rule-library/template.csv')
    def rule_library_template():
        rule_request()
        from cloud_soc.detection.authoring import csv_template
        response = app.response_class('\ufeff' + csv_template(), mimetype='text/csv')
        response.headers['Content-Disposition'] = 'attachment; filename="rules-template.csv"'
        return response

    @app.get('/api/settings/rules')
    def rule_management_list():
        rule_request()
        return jsonify(rule_drafts.listing(g.log_principal))

    @app.post('/api/settings/rules')
    def rule_management_create():
        rule_request()
        return jsonify(rule_drafts.create(request.get_json(), g.log_principal)), 201

    @app.get('/api/settings/rules/<identifier>')
    def rule_management_detail(identifier):
        rule_request()
        return jsonify(rule_drafts.detail(identifier, g.log_principal))

    @app.post('/api/settings/rules/<identifier>/<action>')
    def rule_management_action(identifier, action):
        rule_request()
        return jsonify(rule_drafts.action(identifier, action, request.get_json(), g.log_principal))

    @app.get('/api/settings/rules/<identifier>/export')
    def rule_management_export(identifier):
        rule_request()
        response = app.response_class(rule_drafts.export(identifier, g.log_principal), mimetype='application/yaml')
        response.headers['Content-Disposition'] = 'attachment; filename="rule-' + identifier + '.yml"'
        return response

    @app.errorhandler(CaseError)
    def case_error(error):
        return jsonify(code=error.code, error=str(error)), error.status

    @app.errorhandler(EnrollmentError)
    def enrollment_error(error):
        return jsonify(code=error.code, error=str(error)), error.status

    def case_response(operation):
        try:
            return jsonify(operation())
        except LogQueryError as error:
            return jsonify(code=error.code, error=str(error)), error.status
        except sqlite3.Error:
            return jsonify(code="case_storage_unavailable", error="사건 저장소에 접근하지 못했습니다. 같은 요청으로 재시도하거나 관리자에게 확인하세요."), 503

    def fetch_case_alert(identifier):
        return json.loads(operations_for(g.log_principal).detail([("id", identifier)]))["alert"]

    @app.get("/api/cases")
    def case_list():
        return case_response(lambda: cases.listing(request.args.items(multi=True), g.principal))

    @app.get("/api/case-link")
    def case_link():
        if set(request.args) != {"alert_id"} or len(request.args.getlist("alert_id")) != 1:
            return jsonify(error="경보 참조를 확인하세요."), 400
        return case_response(lambda: cases.lookup(request.args["alert_id"], g.principal))

    @app.post("/api/cases")
    def case_create():
        return case_response(lambda: cases.create(request.get_json(), g.principal,
                             request.headers.get("Idempotency-Key"), fetch_case_alert))

    @app.get("/api/cases/<identifier>")
    def case_detail(identifier):
        if set(request.args) - {"before"} or len(request.args.getlist("before")) > 1:
            return jsonify(error="지원하지 않는 조회 조건입니다."), 400
        return case_response(lambda: cases.detail(identifier, g.principal, request.args.get("before")))

    @app.patch("/api/cases/<identifier>")
    def case_update(identifier):
        return case_response(lambda: cases.update(identifier, request.get_json(), g.principal,
                             request.headers.get("Idempotency-Key"), fetch_case_alert))

    @app.before_request
    def protect():
        # Exact authority check also blocks DNS rebinding and unexpected ports.
        request_origin = origins.get(request.host.lower())
        if request_origin is None:
            abort(400)
        if request.endpoint=='insight_heartbeat':
            if (request.method!='POST' or not request.is_json or request.args or request.cookies
                    or request.headers.get('Origin') or request.headers.get('Sec-Fetch-Site')
                    or request.headers.get('X-Cloud-SOC')!='heartbeat'):
                abort(403)
            secure=request.is_secure or (request.remote_addr in settings.get('HEARTBEAT_TLS_PROXIES',())
                                         and request.headers.get('X-Forwarded-Proto')=='https')
            if urlsplit(settings['PUBLIC_URL']).scheme!='https' or not secure:
                return jsonify(code='heartbeat_tls_required',error='상태 보고에는 TLS 연결이 필요합니다.'),503
            return
        # Only these machine endpoints use token authentication. Admin routes
        # retain Basic authentication and their existing CSRF/Origin checks.
        if request.endpoint in {"enrollment_exchange", "enrollment_receipt", "enrollment_abort"}:
            if not settings.get("ENROLLMENT_ENABLED"):
                return jsonify(code="enrollment_disabled", error="단일 설치 토큰 기능은 아직 활성화되지 않았습니다."), 503
            if (request.method != "POST" or not request.is_json or request.args
                    or request.headers.get("Origin") or request.headers.get("Sec-Fetch-Site")
                    or request.headers.get("X-Cloud-SOC") != "installer"):
                abort(403)
            if urlsplit(settings["PUBLIC_URL"]).scheme != "https":
                return jsonify(code="enrollment_tls_required", error="설치 토큰은 HTTPS 중앙 포털에서만 사용할 수 있습니다."), 503
            # Compose exposes only the TLS gateway; it replaces this header.
            # Never publish the portal container's internal HTTP port directly.
            if request.scheme != "https" and request.headers.get("X-Forwarded-Proto") != "https":
                abort(403)
            return
        if sessions is None and request.endpoint not in PUBLIC:
            credentials = request.authorization
            principal = None
            if request.headers.get("Authorization"):
                basic = credentials is not None and credentials.type.lower() == "basic"
                try:
                    principal, wait = basic_guard.authenticate(credentials.username if basic else None,
                        (credentials.password or "") if basic else None, request.remote_addr)
                except sqlite3.Error:
                    return jsonify(code="authentication_unavailable", error="로그인을 확인하지 못했습니다. 잠시 후 다시 시도하세요."), 503
                if wait:
                    response = jsonify(code="authentication_throttled", error="로그인 시도가 많습니다. 잠시 후 다시 시도하세요.")
                    response.status_code = 429
                    response.headers["Retry-After"] = str(wait)
                    return response
            if principal is None:
                response = jsonify(error="관리자 로그인이 필요합니다.")
                response.status_code = 401
                response.headers["WWW-Authenticate"] = 'Basic realm="Cloud SOC Admin", charset="UTF-8"'
                return response
        # A Slack link is a cross-site top-level navigation, not an API request.
        # Only an exact alert detail/login destination is eligible; authentication below is unchanged.
        alert_id = request.args.get('alert', '')
        alert_navigation = (set(request.args) == {'alert'} and len(request.args.getlist('alert')) == 1
                            and re.fullmatch(r'[0-9a-f]{64}', alert_id) is not None)
        external_navigation = (request.method in ('GET', 'HEAD') and alert_navigation
            and request.headers.get('Sec-Fetch-Mode') == 'navigate'
            and request.headers.get('Sec-Fetch-Dest') == 'document'
            and request.headers.get('Sec-Fetch-User') == '?1'
            and (request.endpoint == 'login_page' or request.endpoint == 'static_file'
                 and (request.view_args or {}).get('filename') == 'workbench.html'))
        if request.headers.get("Sec-Fetch-Site") == "cross-site" and not external_navigation:
            abort(403)
        origin = request.headers.get("Origin")
        if origin and origin != request_origin:
            abort(403)
        if request.method not in ("GET", "HEAD", "OPTIONS"):
            if request.headers.get("X-Cloud-SOC") != "portal" or not request.is_json:
                abort(403)
        if request.endpoint in PUBLIC:
            return
        if sessions:
            identity = sessions.get(request.cookies.get(COOKIE))
            if not identity:
                if request.method in ("GET", "HEAD") and (request.path == "/" or request.path.endswith(".html")):
                    if alert_navigation and request.path == '/workbench.html':
                        return redirect('/login?alert=' + alert_id)
                    return redirect("/login")
                return jsonify(code="login_required", error="로그인이 필요합니다."), 401
            g.principal, g.role, g.csrf = identity["user"], identity["role"], identity["csrf"]
            policy_user = access_policy.users.get(g.principal)
            if policy_user:
                policy_role, organizations = policy_user[1], policy_user[2]
                source_organizations = organizations if access_policy.enabled and policy_role == "investigator" else ()
                principal = LogPrincipal(g.principal, policy_role, organizations, source_organizations)
            elif g.role == "admin":
                principal = LogPrincipal(g.principal, "admin", None,
                    access_policy.admin_source_organizations if access_policy.enabled else ())
            else:
                principal = LogPrincipal(g.principal, "viewer", (), ())
            if not permitted(request.endpoint, request.method, g.role, (request.view_args or {}).get("filename")):
                abort(403)
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), g.csrf):
                    abort(403)
        else:
            g.principal, g.role, g.csrf = principal.username, principal.role, None
        g.log_principal = principal
        if principal.role != "admin":
            log_routes = {"logs", "log_updates", "log_detail", "log_access", "log_source", "auth_me", "logout", "auth_asset"}
            log_assets = {"live-refresh.js", "live-refresh.css", "logs.html", "logs.js", "logs.css", "source-view.js", "auth-client.js", "styles.css", "agents.css", "shell.js", "shell.css", "assets/mark.svg"}
            if sessions:
                # Session RBAC permits case writes only for analysts; all case data is tenant-scoped.
                log_routes |= {"index", "case_list", "case_link", "case_detail", "case_create", "case_update", "dashboard_get", "dashboard_save", "dashboards_get", "dashboards_write"}
                log_assets |= {"assets/world-countries-110m.json"}
                log_assets |= {"index.html", "dashboard.html", "dashboard.js", "dashboard.css", "dashboard-builder.js", "dashboard-widgets.js", "dashboard-insights.js", "dashboard-insight-metrics.js", "dashboard-insights.css", "dashboard-builder.css", "alert-notices.js", "alert-notices.css", "operations.html", "operations.js", "operations.css", "cases.html", "cases.js", "cases.css", "workbench.html", "investigation.js", "mall-alerts.js"}
                if principal.organizations:
                    log_routes |= {"operations_summary", "operations_status", "alert_detail", "alert_site_context", "notice_list", "notice_detail", "insight_data"}
            if request.endpoint not in log_routes and not (request.endpoint == "static_file" and (request.view_args or {}).get("filename") in log_assets):
                abort(403)

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        styles = "'self'"
        response.headers["Content-Security-Policy"] = f"default-src 'self'; script-src 'self'; style-src {styles}; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
        return response

    @app.errorhandler(KeyError)
    def missing(_error):
        return jsonify(error="패키지를 찾을 수 없습니다."), 404

    @app.errorhandler(ValueError)
    def invalid(error):
        return jsonify(error=str(error)), 400

    @app.errorhandler(sqlite3.IntegrityError)
    def conflict(_error):
        return jsonify(error="같은 OS에 동일한 패키지명이 있습니다."), 409

    @app.errorhandler(sqlite3.OperationalError)
    def storage_unavailable(_error):
        return jsonify(code="storage_unavailable", error="저장소가 일시적으로 사용 중이거나 접근할 수 없습니다. 같은 설치 시도로 재시도하세요."), 503

    @app.errorhandler(500)
    def failed(_error):
        return jsonify(error="서버 작업에 실패했습니다. 관리자 로그를 확인하세요."), 500

    @app.get("/login")
    def login_page():
        return send_from_directory(PROJECT / "prototype", "login.html")

    @app.get("/api/auth/config")
    def login_config():
        return jsonify(mode="session" if sessions else "basic")

    @app.get("/theme.js")
    @app.get("/theme.css")
    @app.get("/auth-client.js")
    @app.get("/login.js")
    @app.get("/login/styles.css")
    @app.get("/login/agents.css")
    @app.get("/login/mark.svg")
    def auth_asset():
        assets = {"/theme.js": "theme.js", "/theme.css": "theme.css", "/auth-client.js": "auth-client.js", "/login.js": "login.js",
                  "/login/styles.css": "styles.css", "/login/agents.css": "agents.css",
                  "/login/mark.svg": "assets/mark.svg"}
        return send_from_directory(PROJECT / "prototype", assets[request.path])

    @app.post("/api/auth/login")
    def login():
        if sessions is None:
            return jsonify(error="세션 로그인이 활성화되지 않았습니다."), 404
        body = request.get_json()
        if not isinstance(body, dict) or set(body) != {"username", "password"}:
            abort(400)
        token = sessions.login(body["username"], body["password"])
        if not token:
            return jsonify(error="로그인 실패. 계정·비밀번호를 확인하고 반복 실패 시 5분 후 재시도하세요."), 401
        sessions.logout(request.cookies.get(COOKIE, ""))
        response = jsonify(ok=True)
        response.set_cookie(COOKIE, token, max_age=sessions.ttl, secure=settings["PUBLIC_URL"].startswith("https://"),
                            httponly=True, samesite="Strict", path="/")
        return response

    @app.get("/api/auth/me")
    def auth_me():
        navigation = ["logs.html"]
        if g.log_principal.role == "admin":
            navigation += ["index.html", "dashboard.html", "cases.html", "devices.html", "agents.html", "agents.html#keys", "agent-status.html", "settings-slack.html", "settings-rules.html"]
        elif sessions:
            navigation += ["index.html", "dashboard.html", "cases.html"]
        return jsonify(user=g.principal, role=g.role, csrf=g.csrf,
                       mode="session" if sessions else "basic", navigation=navigation)

    @app.post("/api/auth/logout")
    def logout():
        if sessions:
            sessions.logout(request.cookies.get(COOKIE, ""))
        response = jsonify(ok=True)
        response.delete_cookie(COOKIE, path="/", secure=settings["PUBLIC_URL"].startswith("https://"),
                               httponly=True, samesite="Strict")
        return response

    @app.get("/api/healthz")
    def healthz():
        try:
            if monitor is None:
                raise RuntimeError("monitor_missing")
            monitor.security.authenticate()
            with cases.connect() as db:
                db.execute("SELECT 1").fetchone()
        except Exception:
            return jsonify(status="unavailable"), 503
        return jsonify(status="ready")

    @app.get("/api/portal")
    def portal():
        try:
            issuer.info()
            status = "connected"
        except Exception:
            status = "unavailable"
        return jsonify(endpoint=settings["ENDPOINT"], version="9.5.2", elasticsearch=status,
                       enrollment_enabled=bool(settings.get("ENROLLMENT_ENABLED")),
                       ca_sha256=hashlib.sha256(settings["CA_BYTES"]).hexdigest(),
                       packages=[p for p in store.list() if not p.get('managed_device_id')], max_packages=200)

    @app.get('/api/agents/components')
    def collection_components():
        if request.args: return jsonify(error='지원하지 않는 조회 조건입니다.'),400
        if monitor is None: return jsonify(error='수집 상태 조회 계정이 준비되지 않았습니다.'),503
        try:
            return jsonify(component_snapshot(monitor))
        except Exception:
            return jsonify(error='항목별 수신을 조회하지 못했습니다. 연결·권한·보고 상태를 확인하세요.'),503

    @app.get("/api/agents/status")
    def agent_status():
        if set(request.args) - {"cursor"} or len(request.args.getlist("cursor")) > 1:
            return jsonify(error="지원하지 않는 조회 조건입니다."), 400
        after = decode_cursor(request.args.get("cursor"))
        if monitor is None:
            return jsonify(error="접속 현황 조회 계정이 준비되지 않았습니다. 중앙 서버 업데이트 절차를 확인하세요.",
                           code="monitor_not_configured"), 503
        try:
            return jsonify(snapshot(monitor, after=after))
        except Exception:
            # Upstream errors can contain credentials or raw documents. Never echo them.
            return jsonify(error="수신 현황을 조회하지 못했습니다. 서버 연결·조회 권한·수신 시각 설정을 확인하세요.",
                           code="status_unavailable"), 503

    def log_response(operation, projector=redact_metadata):
        try:
            return app.response_class(json.dumps(projector(json.loads(operation(request.args.items(multi=True))))), mimetype="application/json")
        except LogQueryError as error:
            return jsonify(code=error.code, error=str(error)), error.status

    @app.get("/api/agents/health")
    def collection_health():
        if set(request.args) - {"cursor"} or len(request.args.getlist("cursor")) > 1:
            return jsonify(error="지원하지 않는 조회 조건입니다."), 400
        after = decode_cursor(request.args.get("cursor"))
        if monitor is None:
            return jsonify(error="수집 품질 조회 계정이 준비되지 않았습니다."), 503
        try:
            return app.response_class(health_snapshot(monitor, after), mimetype="application/json")
        except Exception:
            return jsonify(error="수집 품질 보고를 조회하지 못했습니다. 권한·매핑·보고 형식을 확인하세요."), 503

    @app.get("/api/logs")
    def logs():
        return log_response(reader_for(g.log_principal).page)

    @app.get('/api/logs/updates')
    def log_updates():
        # A disposable head snapshot; polling never creates a retained paging cursor.
        return log_response(lambda pairs: reader_for(g.log_principal).page(pairs, preview=True))

    @app.get("/api/logs/detail")
    def log_detail():
        return log_response(reader_for(g.log_principal).detail)

    @app.get("/api/logs/access")
    def log_access():
        if request.args:
            abort(400)
        return jsonify(access_policy.capabilities(g.log_principal))

    @app.post("/api/logs/source")
    def log_source():
        if request.args:
            abort(400)
        try:
            def unique_pairs(pairs):
                data = {}
                for key, value in pairs:
                    if key in data:
                        raise ValueError()
                    data[key] = value
                return data
            try:
                data = json.loads(request.get_data(), object_pairs_hook=unique_pairs)
            except (ValueError, UnicodeError):
                data = None
            content = ProtectedSourceReader(reader_for(g.log_principal), audit).read(g.log_principal, data)
            return app.response_class(content, mimetype="application/json")
        except LogQueryError as error:
            return jsonify(code=error.code, error=str(error)), error.status

    @app.get("/api/reprocessing/history")
    def reprocessing_history():
        from cloud_soc.portal.reprocessing_history import history
        try:
            data = json.loads(history(monitor, request.args.items(multi=True)))
            # Each row remains privacy-filtered; the bounded collection may exceed 256 rows.
            rows = data.pop("rows")
            response = redact_metadata(data)
            response["rows"] = [redact_metadata(row) for row in rows]
            return jsonify(response)
        except LogQueryError as error:
            return jsonify(code=error.code, error=str(error)), error.status

    @app.errorhandler(InsightError)
    def insight_error(error):
        messages = {
            'credential_already_delivered_rotate_required':'이 요청의 자격 증명은 이미 발급됐습니다. 장치 목록에서 회전을 선택하세요.',
            'request_conflict':'같은 요청 ID에 다른 내용이 사용됐습니다.',
            'revision_conflict':'다른 작업에서 변경됐습니다. 목록을 새로 불러오세요.',
            'query_event_capacity':'조회 범위를 줄여 주세요. 집계 한도를 넘었습니다.',
            'query_time_limit':'조회 시간이 한도를 넘었습니다. 기간을 줄여 주세요.',
            'record_conflict':'같은 식별자의 기존 기록과 내용이 다릅니다.',
            'geo_database_required':'IP 위치 자료를 연결해 주세요.',
            'geo_dependency_required':'위치 조회 구성 요소를 설치해 주세요.',
            'device_authentication_failed':'장치 인증을 확인할 수 없습니다.',
            'report_sequence_conflict':'보고 순서가 이전 기록과 충돌합니다.',
            'stale_or_future_report':'장치 시각 또는 보고 시각을 확인하세요.'}
        return jsonify(code=error.code,error=messages.get(error.code,'대시보드 자료를 처리하지 못했습니다. 입력·권한·연결 상태를 확인하세요.')),error.status

    def insight_reader():
        p=g.log_principal
        with insight_lock:
            if p.username not in insight_readers:insight_readers[p.username]=InsightReader(reader_for(p))
            return insight_readers[p.username]

    @app.get('/api/dashboard-data/<kind>')
    def insight_data(kind):
        if g.log_principal.organizations is not None and not g.log_principal.organizations:abort(403)
        if kind=='fleet':
            if g.role!='admin':abort(403)
            offset=request.args.get('offset','0')
            if set(request.args)-{'offset'} or len(request.args.getlist('offset'))>1 or not re.fullmatch(r'[0-9]{1,5}',offset):abort(400)
            offset=int(offset);value=insights.fleet();value['display_limit']=50;value['offset']=offset
            value['next_offset']=offset+50 if offset+50<value['total'] else None;value['rows']=value['rows'][offset:offset+50]
            return jsonify(value)
        if kind=='evidence':
            if set(request.args)-{'id','offset'} or any(len(request.args.getlist(k))!=1 for k in request.args):abort(400)
            offset=request.args.get('offset','0')
            if not re.fullmatch(r'[0-9]{1,5}',offset):abort(400)
            return jsonify(evidence_flow(operations_for(g.log_principal),request.args.get('id',''),int(offset)))
        try:
            if kind=='cloud-alerts':
                from cloud_soc.portal.dashboard_insights import selection
                f,values,offset=selection(request.args.items(multi=True))
                if set(values)-{'start','end'}:raise InsightError('invalid_query')
                delta=(datetime_from_iso(f.end)-datetime_from_iso(f.start)).total_seconds()
                return jsonify({'state':'ok','sections':{'alerts':operations_for(g.log_principal).series(
                    [operations_for(g.log_principal).alert_index],'@timestamp',f.start,f.end,
                    '5m' if delta<=86400 else '1h',alerts=True,cloud_only=True)}})
            if kind=='cloud':return jsonify(insight_reader().cloud(request.args.items(multi=True)))
            if kind=='geo':
                from cloud_soc.portal.insight_metrics import geographic
                return jsonify(geographic(insight_reader(),request.args.items(multi=True),settings.get('GEOIP_DATABASE')))
            if kind=='account-alerts':
                from cloud_soc.portal.insight_metrics import account_alert_links
                return jsonify(account_alert_links(insight_reader(),operations_for(g.log_principal),request.args.items(multi=True)))
            if kind=='accounts':
                from cloud_soc.portal.insight_metrics import account_overview
                value=account_overview(insight_reader(),insights,g.log_principal.organizations,request.args.items(multi=True));value['can_manage']=g.role=='admin';return jsonify(value)
            if kind=='evaluation':
                from cloud_soc.portal.insight_metrics import evaluation_summary
                value=evaluation_summary(insights,g.log_principal.organizations,request.args.items(multi=True));value['can_manage']=g.role=='admin';return jsonify(value)
        except (InsightError,LogQueryError):raise
        except Exception:
            return jsonify(code='insight_unavailable',error='자료를 조회하지 못했습니다. 기존 표시 내용은 유지됩니다.'),503
        abort(404)

    @app.post('/api/dashboard-records/<kind>')
    def insight_record(kind):
        if g.role!='admin' or request.args:abort(403)
        from cloud_soc.portal.insight_metrics import validate_policy,validate_assessment,validate_evaluation,assessment_score
        validators={'policy':validate_policy,'assessment':validate_assessment,'evaluation':validate_evaluation}
        if kind not in validators:abort(404)
        body=request.get_json();validators[kind](body)
        if kind=='assessment':
            policies=[r['body'] for r in insights.records('policy',None) if r['body']['organization']==body['organization'] and r['body']['id']==body['policy_id']]
            if not policies:raise InsightError('policy_missing',409)
            assessment_score(policies[0],body)
        if kind=='evaluation':
            # Link only existing, visible alerts in the same organization. Absence is a reported verdict, not an inferred scan.
            for case in body['cases']:
                for alert_id in case.get('alert_ids',[]):
                    detail=json.loads(operations_for(g.log_principal).detail([('id',alert_id)]))
                    if detail['alert']['organization']!=body['organization'] or detail['alert']['rule']!=body['rule_id'] or detail['rule_version']!=body['rule_version']:
                        raise InsightError('evaluation_alert_scope_mismatch',409)
        return jsonify(insights.put_record(kind,body,g.principal,validators[kind])),201

    @app.post('/api/dashboard-devices')
    def insight_register():
        if g.role!='admin' or request.args:abort(403)
        return jsonify(insights.register(request.get_json(),g.principal)),201

    @app.post('/api/dashboard-devices/<device>')
    def insight_device_change(device):
        if g.role!='admin' or request.args:abort(403)
        return jsonify(insights.change_device(device,request.get_json(),g.principal))

    @app.post('/api/dashboard-heartbeat')
    def insight_heartbeat():
        credential=request.headers.get('Authorization','')
        if not credential.startswith('Bearer '):raise InsightError('device_authentication_failed',401)
        return jsonify(insights.heartbeat(credential.removeprefix('Bearer '),request.get_json()))

    @app.get("/api/operations")
    def operations_summary():
        from cloud_soc.portal.operations import display_summary
        return log_response(operations_for(g.log_principal).summary, display_summary)

    @app.get("/api/operations/status")
    def operations_status():
        if request.args:
            return jsonify(error="분석 상태 조회에는 검색 조건을 사용할 수 없습니다."), 400
        result = operations_for(g.log_principal).pipeline()
        if settings.get('RUNTIME_CONTRACT_FILE') and g.role == 'admin':
            from cloud_soc.deployment.contract import WORKERS
            missing = [name for name in WORKERS if operations.worker_status(name)['state'] == 'not_started']
            result['runtime_missing_workers'] = missing
            if missing:
                result['realtime_coverage'] = {'state': 'blocked', 'reason': 'required_runtime_worker_missing'}
        return jsonify(result)

    @app.get('/api/runtime')
    def runtime_contract():
        from cloud_soc.deployment.contract import ALL_WORKERS, WORKERS
        path = settings.get('RUNTIME_CONTRACT_FILE')
        if not path:
            return jsonify(state='unmanaged', required_workers=list(ALL_WORKERS)), 200
        value = json.loads(Path(path).read_text())
        return jsonify(state='configured' if value.get('prepared') else 'migration_incomplete',
                       version=value['version'], policy_sha256=value['policy_sha256'],
                       required_workers=list(ALL_WORKERS), pipeline_workers=list(WORKERS), verified_rules=value['verified_rules'])

    @app.get("/api/alerts/detail")
    def alert_detail():
        return log_response(operations_for(g.log_principal).detail)

    @app.get('/api/alerts/site-context')
    def alert_site_context():
        from cloud_soc.portal.site_context import context
        return log_response(lambda pairs: context(operations_for(g.log_principal), pairs))

    @app.get('/api/alerts/notices')
    def notice_list():
        from cloud_soc.portal.notices import NoticeReader
        try:
            return jsonify(NoticeReader(operations_for(g.log_principal)).listing(request.args.items(multi=True)))
        except LogQueryError as error:
            return jsonify(code=error.code, error=str(error)), error.status

    @app.get('/api/alerts/notices/detail')
    def notice_detail():
        from cloud_soc.portal.notices import NoticeReader
        try:
            return jsonify(NoticeReader(operations_for(g.log_principal)).detail(request.args.items(multi=True)))
        except LogQueryError as error:
            return jsonify(code=error.code, error=str(error)), error.status

    @app.get('/api/detection/history')
    def detection_history():
        from cloud_soc.portal.detection_history import history
        return log_response(lambda pairs: history(operations, pairs))

    @app.post("/api/packages")
    def create_package():
        return jsonify(store.create(request.get_json())), 201

    @app.post("/api/packages/<identifier>/enrollment")
    def mint_enrollment(identifier):
        if not settings.get("ENROLLMENT_ENABLED"):
            raise EnrollmentError("enrollment_disabled", 503, "중앙 서버의 단일 설치 토큰 기능을 먼저 준비하세요.")
        if store.get(identifier).get('managed_device_id'):
            raise ValueError('장치 상세에서 설치 묶음을 준비하세요.')
        return jsonify(enrollments.mint(identifier, request.get_json())), 201

    @app.get("/api/enrollments")
    def enrollment_list():
        return jsonify(enrollments=enrollments.listing())

    @app.post("/api/enrollments/<identifier>/cancel")
    def cancel_enrollment(identifier):
        if request.get_json() != {}:
            raise ValueError("취소 요청에는 비밀이나 추가 설정을 넣지 마세요.")
        return jsonify(enrollment=enrollments.cancel(identifier))

    def installer_token():
        authorization = request.headers.get("Authorization", "")
        if not authorization.startswith("Bearer "):
            raise EnrollmentError("invalid_enrollment", 401, "설치 토큰 인증이 필요합니다.")
        return authorization[7:]

    @app.post("/api/installer/enroll")
    def enrollment_exchange():
        return jsonify(enrollments.exchange(installer_token(), request.get_json()))

    @app.post("/api/installer/receipt")
    def enrollment_receipt():
        return jsonify(enrollments.receipt(installer_token(), request.get_json()))

    @app.post("/api/installer/abort")
    def enrollment_abort():
        return jsonify(enrollment=enrollments.abort(installer_token(), request.get_json()))

    @app.delete("/api/packages/<identifier>")
    def delete_package(identifier):
        store.delete(identifier)
        return jsonify(deleted=True, agents_uninstalled=False, keys_revoked=False)

    @app.get("/api/packages/<identifier>/download")
    def download(identifier):
        metadata, archive = store.get(identifier, archive=True)
        return send_file(io.BytesIO(archive), as_attachment=True, download_name=metadata["filename"], mimetype="application/octet-stream")

    @app.post("/api/packages/<identifier>/keys")
    def issue_keys(identifier):
        package = store.get(identifier)
        if package.get('managed_device_id'):
            raise ValueError('장치 상세의 자동 등록을 사용하세요. 장치 키를 별도로 발급하지 않습니다.')
        data = request.get_json()
        if not isinstance(data, dict) or set(data) - {"days", "target_label"} or type(data.get("days")) is not int or data["days"] not in (1, 7, 30, 90):
            raise ValueError("키 만료일은 1·7·30·90일 중 선택하세요.")
        label = key_label(data.get("target_label", ""))
        issued = []
        try:
            for scope, role_file in [("host", "publisher-role.json")] + ([("network", "network-publisher-role.json")] if package["network"] else []):
                role = json.loads((Path(settings["AGENT_SOURCE"]) / role_file).read_text(encoding="utf-8"))
                key = issuer.security.create_api_key(
                    name=f"cloud-soc-{package['name']}-{scope}-{secrets.token_hex(4)}", expiration=f"{data['days']}d",
                    role_descriptors={f"cloud_soc_{scope}": role},
                    metadata={"package_id": identifier, "organization": package["organization"]},
                )
                issued.append({"id": key["id"], "key": key["id"] + ":" + key["api_key"], "scope": scope, "expiration": key.get("expiration")})
            store.record_keys(identifier, issued, package=package, target_label=label)
        except Exception:
            if issued:
                try:
                    issuer.security.invalidate_api_key(ids=[key["id"] for key in issued], owner=True)
                except Exception:
                    app.logger.error("Partial API key issue failed; administrator must audit keys for package %s", identifier)
            # Never include upstream request/response bodies or API secrets in errors.
            return jsonify(error="키 발급에 실패했습니다. 서버 연결·발급 권한을 확인하세요. 부분 발급 키는 관리자 감사가 필요할 수 있습니다."), 503
        return jsonify(keys=issued, warning="한 번만 표시됩니다. 서버마다 새로 발급하고 안전하게 보관하세요. 패키지에는 포함되지 않습니다.")

    @app.post("/api/keys/<identifier>/revoke")
    def revoke_key(identifier):
        found = known_key(identifier)
        if found["revoked_at"]:
            return jsonify(revoked=True, key=found)
        try:
            # manage_own_api_key requires an explicitly owner-scoped request.
            result = issuer.security.invalidate_api_key(ids=[identifier], owner=True)
            invalidated = result.get("invalidated_api_keys")
            previous = result.get("previously_invalidated_api_keys")
            if (not isinstance(invalidated, list) or not isinstance(previous, list)
                    or type(result.get("error_count")) is not int or result["error_count"] != 0):
                raise RuntimeError("Key revocation failed")
            if identifier not in invalidated + previous:
                # An owner-scoped retry can omit keys already invalidated remotely.
                if invalidated or previous:
                    raise RuntimeError("Unexpected key revocation response")
                keys = issuer.security.get_api_key(id=identifier, owner=True).get("api_keys")
                if (not isinstance(keys, list) or len(keys) != 1
                        or keys[0].get("id") != identifier or keys[0].get("invalidated") is not True):
                    raise RuntimeError("Key revocation not confirmed")
            store.mark_revoked(identifier)
        except Exception:
            return jsonify(error="키 폐기를 확인하지 못했습니다. 서버 연결·발급 계정 권한을 확인하고 다시 시도하세요. 이력은 삭제하지 않았습니다."), 503
        return jsonify(revoked=True, key=store.key(identifier))

    def known_key(identifier):
        found = store.key(identifier)
        if found is None:
            abort(404, description="발급 키 이력을 찾을 수 없습니다.")
        return found

    def key_label(value):
        if not isinstance(value, str) or len(value) > 100 or any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ValueError("대상 별칭은 줄바꿈 없이 100자 이내로 입력하세요. 키·비밀번호를 입력하지 마세요.")
        return value.strip()

    @app.patch("/api/keys/<identifier>")
    def label_key(identifier):
        known_key(identifier)
        data = request.get_json()
        if not isinstance(data, dict) or set(data) != {"target_label"}:
            raise ValueError("대상 별칭만 수정할 수 있습니다.")
        store.label_key(identifier, key_label(data["target_label"]))
        return jsonify(key=store.key(identifier))

    @app.post("/api/keys/<identifier>/check")
    def check_key(identifier):
        found = known_key(identifier)
        try:
            response = issuer.security.get_api_key(id=identifier, owner=True)
            keys = response["api_keys"]
            if not isinstance(keys, list):
                raise RuntimeError("Invalid key response")
            if not keys:
                store.check_key(identifier, None, "missing")
            else:
                if len(keys) != 1 or keys[0].get("id") != identifier or type(keys[0].get("invalidated")) is not bool:
                    raise RuntimeError("Invalid key response")
                key = keys[0]
                expiration = key.get("expiration")
                if expiration is not None and (type(expiration) is not int or not 0 <= expiration <= 253402300799000):
                    raise RuntimeError("Invalid expiration")
                scope = None
                if key.get("metadata", {}).get("package_id") == found["package_id"]:
                    roles = set(key.get("role_descriptors", {}))
                    if roles == {"cloud_soc_host"}:
                        scope = "host"
                    if roles == {"cloud_soc_network"}:
                        scope = "network"
                store.check_key(identifier, {"expiration": expiration, "invalidated": key["invalidated"], "scope": scope},
                                "revoked" if key["invalidated"] else "active")
        except Exception:
            store.check_key(identifier, None, "unavailable")
            return jsonify(error="서버에서 키 정보를 확인하지 못했습니다. 연결·발급 계정 권한을 확인하세요.", key=store.key(identifier)), 503
        return jsonify(key=store.key(identifier))

    @app.get("/api/keys")
    def key_ids():
        return jsonify(keys=store.keys())

    def device_admin(*, enabled=False):
        if g.role != 'admin':
            abort(403)
        if enabled and not settings.get('ENROLLMENT_ENABLED'):
            raise EnrollmentError('enrollment_disabled', 503, '서버의 HTTPS 장치 등록 설정을 준비하세요.')

    def page_args():
        if set(request.args) - {'view', 'q', 'page', 'size'} or any(len(request.args.getlist(k)) != 1 for k in request.args):
            raise ValueError('지원하지 않는 조회 조건입니다.')
        return {'view': request.args.get('view', 'active'), 'query': request.args.get('q', ''),
                'page': int(request.args.get('page', '1')), 'size': int(request.args.get('size', '25'))}

    @app.get('/api/managed-devices')
    def managed_device_list():
        device_admin()
        return jsonify(**devices.listing(**page_args()), enrollment_enabled=bool(settings.get('ENROLLMENT_ENABLED')))

    @app.post('/api/managed-devices')
    def managed_device_create():
        device_admin(enabled=True)
        if request.args:
            abort(400)
        return jsonify(device=devices.create(g.principal, request.headers.get('Idempotency-Key'), request.get_json())), 201

    @app.get('/api/managed-devices/<identifier>')
    def managed_device_get(identifier):
        device_admin()
        if request.args:
            abort(400)
        return jsonify(device=devices.detail(identifier))

    @app.post('/api/managed-devices/<identifier>/prepare')
    def managed_device_prepare(identifier):
        device_admin(enabled=True)
        if request.args:
            abort(400)
        return jsonify(device=devices.prepare(g.principal, identifier, request.headers.get('Idempotency-Key'), request.get_json()))

    @app.get('/api/managed-devices/<identifier>/activity')
    def managed_device_activity(identifier):
        device_admin()
        if request.args:
            abort(400)
        return jsonify(devices.activity(identifier))

    @app.get('/api/managed-devices/<identifier>/diagnostics')
    def managed_device_diagnostics(identifier):
        device_admin()
        if request.args:
            abort(400)
        device = devices.detail(identifier)
        public = {k: device[k] for k in ('id', 'label', 'organization', 'os', 'purpose', 'state', 'version',
            'created', 'updated', 'receipt_at', 'service_state', 'analysis_state', 'operations')}
        public['credentials'] = [{k: row.get(k) for k in ('id', 'scope', 'status', 'created_at', 'expiration', 'revoked_at', 'checked_at')}
                                 for row in device['keys']]
        content = json.dumps(public, ensure_ascii=False, indent=2).encode('utf-8')
        return send_file(io.BytesIO(content), as_attachment=True, download_name='device-' + identifier + '-diagnostics.json', mimetype='application/json')

    @app.get('/api/managed-devices/<identifier>/download')
    def managed_device_download(identifier):
        device_admin(enabled=True)
        if request.args:
            abort(400)
        content, filename = devices.download(identifier)
        return send_file(io.BytesIO(content), as_attachment=True, download_name=filename, mimetype='application/zip')

    @app.post('/api/managed-devices/<identifier>/end')
    def managed_device_end(identifier):
        device_admin()
        body = request.get_json()
        if request.args or not isinstance(body, dict) or set(body) != {'confirm'} or body['confirm'] is not True:
            raise ValueError('장치의 서버 접근 차단을 확인하세요.')
        return jsonify(device=devices.end(g.principal, identifier, request.headers.get('Idempotency-Key')))

    @app.post('/api/managed-devices/<identifier>/key-extension/preview')
    def managed_key_extension_preview(identifier):
        device_admin(enabled=True)
        if request.args:
            abort(400)
        result = devices.key_extensions.preview(g.principal, identifier,
            request.headers.get('Idempotency-Key'), request.get_json())
        return jsonify(extension=result)

    @app.post('/api/managed-devices/<identifier>/key-extension/<operation>')
    def managed_key_extension_apply(identifier, operation):
        device_admin(enabled=True)
        body = request.get_json()
        if request.args or not isinstance(body, dict) or set(body) != {'confirm'} or type(body['confirm']) is not bool:
            raise ValueError('유효기간 연장 또는 미제출 요청 취소를 확인하세요.')
        handler = devices.key_extensions.apply if body['confirm'] else devices.key_extensions.cancel
        result = handler(g.principal, identifier, operation)
        return jsonify(extension=result, device=devices.detail(identifier))

    @app.get('/api/key-history')
    def managed_key_history():
        device_admin()
        return jsonify(store.key_page(**page_args()))

    @app.get("/")
    def index():
        return send_from_directory(PROJECT / "prototype", "index.html")

    @app.get("/<path:filename>")
    def static_file(filename):
        # Never serve the repo, secrets, SQLite, source code, or arbitrary uploads.
        allowed = {"devices.html", "devices.js", "devices.css", "live-refresh.js", "live-refresh.css", "reprocessing-history.html", "reprocessing-history.js", "agents.html", "agents.js", "agents.css", "styles.css", "shell.js", "shell.css", "assets/mark.svg", "assets/world-countries-110m.json",
                   "settings-rules.html", "settings-rules.js", "rule-editor.js", "settings-rules.css",
                   "settings-slack.html", "settings-slack.js", "settings-slack.css",
                   "detection-history.html", "detection-history.js",
                   "agent-status.html", "agent-status.js", "agent-status.css",
                   "collection-health.html", "collection-health.js",
                   "index.html", "dashboard.html", "dashboard.js", "dashboard.css", "dashboard-builder.js", "dashboard-widgets.js", "dashboard-insights.js", "dashboard-insight-metrics.js", "dashboard-insights.css", "dashboard-builder.css", "alert-notices.js", "alert-notices.css", "operations.html", "operations.js", "operations.css", "cases.html", "cases.js", "cases.css", "investigation.js", "mall-alerts.js", "app.js", "demo-data.js", "workbench.html", "logs.html", "logs.js", "logs-data.js", "logs.css", "source-view.js"}
        if filename not in allowed:
            abort(404)
        return send_from_directory(PROJECT / "prototype", filename)

    return app


def main():
    parser = argparse.ArgumentParser(description="Local portal preview only; use Docker/Gunicorn for the central server")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    create_app().run(host="127.0.0.1", port=args.port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
