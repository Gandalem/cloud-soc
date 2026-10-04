"""Admin-only package API. Production entry point is Gunicorn behind TLS."""

import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import secrets
import sqlite3
import ssl
from urllib.parse import urlsplit

from elasticsearch import Elasticsearch
from flask import Flask, abort, g, jsonify, redirect, request, send_file, send_from_directory
from werkzeug.security import check_password_hash

from cloud_soc.portal.packages import PackageStore, validate_endpoint
from cloud_soc.portal.agent_status import decode_cursor, snapshot
from cloud_soc.portal.log_query import LogReader, LogQueryError
from cloud_soc.portal.collection_health import snapshot as health_snapshot
from cloud_soc.portal.operations import Operations
from cloud_soc.portal.cases import CaseStore, CaseError
from cloud_soc.portal.auth import COOKIE, PUBLIC, Sessions, load_users, permitted
from cloud_soc.privacy import redact_metadata
from cloud_soc.logging_config import configure_logging
from cloud_soc.portal.enrollment import Enrollments, EnrollmentError

PROJECT = Path(__file__).resolve().parents[3]


def settings_from_environment():
    def secret(name):
        value = Path(os.environ[name]).read_text(encoding="utf-8").strip()
        if not value:
            raise ValueError(f"Empty secret file: {name}")
        return value

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
        "CA_BYTES": ca,
        "PUBLIC_URL": public_url,
        "USERS_FILE": os.environ.get("SOC_USERS_FILE"),
        "ENROLLMENT_ENABLED": os.environ.get("SOC_ENROLLMENT_ENABLED") == "1",
        "ENDPOINT": validate_endpoint(os.environ.get("SOC_AGENT_ENDPOINT") or os.environ["SOC_ELASTIC_ENDPOINT"]),
        "ADMIN_USER": os.environ.get("SOC_ADMIN_USER", "admin"),
        "ADMIN_HASH": secret("SOC_ADMIN_HASH_FILE"),
        "ES_URL": os.environ["SOC_INTERNAL_ES_URL"],
        "ES_PASSWORD": secret("SOC_ISSUER_PASSWORD_FILE"),
        "CA_FILE": str(ca_path),
        "MONITOR_PASSWORD": secret("SOC_MONITOR_PASSWORD_FILE") if os.environ.get("SOC_MONITOR_PASSWORD_FILE") else None,
    }


def create_app(settings=None, *, issuer=None, monitor=None):
    configure_logging()
    settings = settings if settings is not None else settings_from_environment()
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=8192, TRUSTED_HOSTS=[urlsplit(settings["PUBLIC_URL"]).hostname])
    store = PackageStore(Path(settings["STATE_DIR"]), Path(settings["AGENT_SOURCE"]), settings["CA_BYTES"], settings["ENDPOINT"],
                         portal_url=settings["PUBLIC_URL"] if settings["PUBLIC_URL"].startswith("https://") else None)
    app.extensions["packages"] = store
    users = load_users(settings["USERS_FILE"]) if settings.get("USERS_FILE") else None
    sessions = Sessions(Path(settings["STATE_DIR"]) / "sessions.sqlite", users) if users else None
    app.extensions["sessions"] = sessions
    if issuer is None:
        issuer = Elasticsearch(settings["ES_URL"], basic_auth=("cloud_soc_issuer", settings["ES_PASSWORD"]),
                               ca_certs=settings["CA_FILE"], request_timeout=5, max_retries=0)
    app.extensions["issuer"] = issuer
    if monitor is None and settings.get("MONITOR_PASSWORD"):
        monitor = Elasticsearch(settings["ES_URL"], basic_auth=("cloud_soc_agent_monitor", settings["MONITOR_PASSWORD"]),
                                ca_certs=settings["CA_FILE"], request_timeout=5, max_retries=0)
    app.extensions["monitor"] = monitor
    enrollments = Enrollments(store, issuer, monitor)
    app.extensions["enrollments"] = enrollments
    log_reader = LogReader(monitor, secret=settings["ADMIN_HASH"],
                           principal=settings["PUBLIC_URL"] + "/" + settings["ADMIN_USER"])
    operations = Operations(monitor)
    cases = CaseStore(Path(settings["STATE_DIR"]) / "cases.sqlite", settings["ADMIN_USER"],
                      principals=set(users) if users else None,
                      owners={name for name, row in users.items() if row["role"] != "viewer"} if users else None)
    app.extensions["cases"] = cases

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
        return json.loads(operations.detail([("id", identifier)]))["alert"]

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
        if request.host.lower() != urlsplit(settings["PUBLIC_URL"]).netloc.lower():
            abort(400)
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
            if (credentials is None or credentials.type.lower() != "basic"
                    or not secrets.compare_digest((credentials.username or "").encode("utf-8"), settings["ADMIN_USER"].encode("utf-8"))
                    or not check_password_hash(settings["ADMIN_HASH"], credentials.password or "")):
                response = jsonify(error="관리자 로그인이 필요합니다.")
                response.status_code = 401
                response.headers["WWW-Authenticate"] = 'Basic realm="Cloud SOC Admin", charset="UTF-8"'
                return response
        if request.headers.get("Sec-Fetch-Site") == "cross-site":
            abort(403)
        origin = request.headers.get("Origin")
        if origin and origin != settings["PUBLIC_URL"]:
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
                    return redirect("/login")
                return jsonify(code="login_required", error="로그인이 필요합니다."), 401
            g.principal, g.role, g.csrf = identity["user"], identity["role"], identity["csrf"]
            if not permitted(request.endpoint, request.method, g.role, (request.view_args or {}).get("filename")):
                abort(403)
            if request.method not in ("GET", "HEAD", "OPTIONS"):
                if not secrets.compare_digest(request.headers.get("X-CSRF-Token", ""), g.csrf):
                    abort(403)
        else:
            g.principal, g.role, g.csrf = settings["ADMIN_USER"], "admin", None

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

    @app.get("/auth-client.js")
    @app.get("/login.js")
    def auth_asset():
        return send_from_directory(PROJECT / "prototype", request.path.lstrip("/"))

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
        return jsonify(user=g.principal, role=g.role, csrf=g.csrf, mode="session" if sessions else "basic")

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
            monitor.info()
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
                       packages=store.list(), max_packages=200)

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

    def log_response(operation):
        try:
            return app.response_class(json.dumps(redact_metadata(json.loads(operation(request.args.items(multi=True))))), mimetype="application/json")
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
        return log_response(log_reader.page)

    @app.get("/api/logs/detail")
    def log_detail():
        return log_response(log_reader.detail)

    @app.get("/api/operations")
    def operations_summary():
        return log_response(operations.summary)

    @app.get("/api/alerts/detail")
    def alert_detail():
        return log_response(operations.detail)

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

    @app.get("/")
    def index():
        return send_from_directory(PROJECT / "prototype", "index.html")

    @app.get("/<path:filename>")
    def static_file(filename):
        # Never serve the repo, secrets, SQLite, source code, or arbitrary uploads.
        allowed = {"agents.html", "agents.js", "agents.css", "styles.css", "shell.js", "shell.css", "assets/mark.svg",
                   "detection-history.html", "detection-history.js",
                   "agent-status.html", "agent-status.js", "agent-status.css",
                   "collection-health.html", "collection-health.js",
                   "index.html", "operations.js", "operations.css", "cases.html", "cases.js", "cases.css", "investigation.js", "app.js", "demo-data.js", "workbench.html", "logs.html", "logs.js", "logs-data.js", "logs.css"}
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
