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
from flask import Flask, abort, jsonify, request, send_file, send_from_directory
from werkzeug.security import check_password_hash

from cloud_soc.portal.packages import PackageStore, validate_endpoint
from cloud_soc.portal.agent_status import decode_cursor, snapshot

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
        "ENDPOINT": validate_endpoint(os.environ["SOC_ELASTIC_ENDPOINT"]),
        "ADMIN_USER": os.environ.get("SOC_ADMIN_USER", "admin"),
        "ADMIN_HASH": secret("SOC_ADMIN_HASH_FILE"),
        "ES_URL": os.environ["SOC_INTERNAL_ES_URL"],
        "ES_PASSWORD": secret("SOC_ISSUER_PASSWORD_FILE"),
        "CA_FILE": str(ca_path),
        "MONITOR_PASSWORD": secret("SOC_MONITOR_PASSWORD_FILE") if os.environ.get("SOC_MONITOR_PASSWORD_FILE") else None,
    }


def create_app(settings=None, *, issuer=None, monitor=None):
    settings = settings if settings is not None else settings_from_environment()
    app = Flask(__name__, static_folder=None)
    app.config.update(MAX_CONTENT_LENGTH=8192, TRUSTED_HOSTS=[urlsplit(settings["PUBLIC_URL"]).hostname])
    store = PackageStore(Path(settings["STATE_DIR"]), Path(settings["AGENT_SOURCE"]), settings["CA_BYTES"], settings["ENDPOINT"])
    app.extensions["packages"] = store
    if issuer is None:
        issuer = Elasticsearch(settings["ES_URL"], basic_auth=("cloud_soc_issuer", settings["ES_PASSWORD"]),
                               ca_certs=settings["CA_FILE"], request_timeout=5, max_retries=0)
    app.extensions["issuer"] = issuer
    if monitor is None and settings.get("MONITOR_PASSWORD"):
        monitor = Elasticsearch(settings["ES_URL"], basic_auth=("cloud_soc_agent_monitor", settings["MONITOR_PASSWORD"]),
                                ca_certs=settings["CA_FILE"], request_timeout=5, max_retries=0)
    app.extensions["monitor"] = monitor

    @app.before_request
    def protect():
        # Exact authority check also blocks DNS rebinding and unexpected ports.
        if request.host.lower() != urlsplit(settings["PUBLIC_URL"]).netloc.lower():
            abort(400)
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

    @app.after_request
    def headers(response):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        # Existing read-only demo charts use inline style attributes, not scripts.
        styles = "'self' 'unsafe-inline'" if request.path in ("/index.html", "/workbench.html", "/logs.html") else "'self'"
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

    @app.errorhandler(500)
    def failed(_error):
        return jsonify(error="서버 작업에 실패했습니다. 관리자 로그를 확인하세요."), 500

    @app.get("/api/portal")
    def portal():
        try:
            issuer.info()
            status = "connected"
        except Exception:
            status = "unavailable"
        return jsonify(endpoint=settings["ENDPOINT"], version="9.5.2", elasticsearch=status,
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

    @app.post("/api/packages")
    def create_package():
        return jsonify(store.create(request.get_json())), 201

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
        if not isinstance(data, dict) or set(data) != {"days"} or type(data["days"]) is not int or data["days"] not in (1, 7, 30, 90):
            raise ValueError("키 만료일은 1·7·30·90일 중 선택하세요.")
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
            store.record_keys(identifier, issued)
        except Exception:
            if issued:
                try:
                    issuer.security.invalidate_api_key(ids=[key["id"] for key in issued])
                except Exception:
                    app.logger.error("Partial API key issue failed; administrator must audit keys for package %s", identifier)
            # Never include upstream request/response bodies or API secrets in errors.
            return jsonify(error="키 발급에 실패했습니다. 서버 연결·발급 권한을 확인하세요. 부분 발급 키는 관리자 감사가 필요할 수 있습니다."), 503
        return jsonify(keys=issued, warning="한 번만 표시됩니다. 서버마다 새로 발급하고 안전하게 보관하세요. 패키지에는 포함되지 않습니다.")

    @app.post("/api/keys/<identifier>/revoke")
    def revoke_key(identifier):
        with store.connect() as db:
            found = db.execute("SELECT id FROM issued_keys WHERE id = ?", (identifier,)).fetchone()
        if found is None:
            abort(404)
        try:
            result = issuer.security.invalidate_api_key(ids=[identifier])
            if result.get("error_count", 0):
                raise RuntimeError("Key revocation failed")
        except Exception:
            return jsonify(error="키 폐기에 실패했습니다. 다시 확인하세요."), 503
        return jsonify(revoked=True)

    @app.get("/api/keys")
    def key_ids():
        with store.connect() as db:
            rows = [dict(row) for row in db.execute("SELECT id, package_id, created_at FROM issued_keys ORDER BY created_at DESC LIMIT 500")]
        return jsonify(keys=rows)

    @app.get("/")
    def index():
        return send_from_directory(PROJECT / "prototype", "agents.html")

    @app.get("/<path:filename>")
    def static_file(filename):
        # Never serve the repo, secrets, SQLite, source code, or arbitrary uploads.
        allowed = {"agents.html", "agents.js", "agents.css", "styles.css", "assets/mark.svg",
                   "agent-status.html", "agent-status.js", "agent-status.css",
                   "index.html", "app.js", "demo-data.js", "workbench.html", "logs.html", "logs.js", "logs-data.js", "logs.css"}
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
