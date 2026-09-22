"""Loopback synthetic UI with real temporary SQLite. Never deploy this helper."""
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import tempfile
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

import test_portal
from cloud_soc.portal.app import create_app


def alert_detail(_reader, pairs):
    values = dict(pairs)
    row = {"id": values["id"], "title": "합성 검증: SSH 로그인 실패", "rule": "SYNTHETIC-ONLY", "severity": "high", "organization": "fixture", "source_ip": "192.0.2.1", "timestamp": datetime.now(timezone.utc).isoformat()}
    data = {"alert": row, "evidence_count": 1, "evidence_limit": 1, "rule_version": "synthetic", "condition": {"event_count": 3, "threshold": 3, "time_window_seconds": 60}}
    if "evidence" in values:
        data["evidence"] = {"state": "exact_reference", "raw": {"index": "soc-host-raw-fixture", "id": "synthetic"}, "normalized": {"index": "soc-normalized-v1", "id": "synthetic"}, "metadata": {"source_ip": "192.0.2.1", "user": "fixture-user"}}
    return json.dumps(data, ensure_ascii=False).encode()


def summary(_reader, pairs):
    values = dict(pairs)
    row = json.loads(alert_detail(None, [("id", "synthetic")]))["alert"]
    part = {"state": "ok", "count": 0, "rows": [], "buckets": [], "statuses": []}
    return json.dumps({"start": values["start"], "end": values["end"], "sections": {
        "intake": part, "processing": part, "quality": part,
        "alerts": {**part, "count": 1, "rows": [row], "buckets": [{"time": row["timestamp"], "count": 1}]},
        "pipeline": {"state": "not_started"}}}).encode()


class Preview(BaseHTTPRequestHandler):
    def dispatch(self):
        with self.server.app.test_client() as client:
            headers = {"Authorization": test_portal.AUTH, "Content-Type": "application/json", "X-Cloud-SOC": "portal"}
            if self.headers.get("Idempotency-Key"): headers["Idempotency-Key"] = self.headers["Idempotency-Key"]
            length = int(self.headers.get("Content-Length", "0"))
            if length > 8192: self.send_error(413); return
            response = client.open(self.path, method=self.command, headers=headers, data=self.rfile.read(length) if length else None)
            data = response.get_data()
            if urlsplit(self.path).path in ("/index.html", "/workbench.html", "/"):
                data = data.replace("관리자 전용 · 실제".encode(), "합성 UI 검증 ·".encode())
            self.send_response(response.status_code)
            self.send_header("Content-Type", response.content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers(); self.wfile.write(data); response.close()
    do_GET = do_POST = do_PATCH = dispatch
    def log_message(self, *_): pass


if __name__ == "__main__":
    with tempfile.TemporaryDirectory(prefix="soc-p6-preview-") as directory:
        settings = {"STATE_DIR": Path(directory), "AGENT_SOURCE": test_portal.ROOT / "deploy/agents", "CA_BYTES": test_portal.CA,
                    "PUBLIC_URL": "http://localhost", "ENDPOINT": "https://example.test:9200", "ADMIN_USER": "admin", "ADMIN_HASH": test_portal.HASH}
        with patch("cloud_soc.portal.operations.Operations.detail", alert_detail), patch("cloud_soc.portal.operations.Operations.summary", summary):
            server = ThreadingHTTPServer(("127.0.0.1", 8769), Preview)
            server.app = create_app(settings, issuer=Mock())
            try: server.serve_forever()
            except KeyboardInterrupt: pass
            finally: server.server_close()
