"""Loopback-only UI fixtures. No ES credentials or real data, stop with Ctrl+C."""
from datetime import datetime, timedelta, timezone
import json
from http.server import ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit
from preview_logs import Preview, ROOT


class OperationsPreview(Preview):
    def do_GET(self):
        path = urlsplit(self.path)
        query = parse_qs(path.query)
        now = datetime.now(timezone.utc).isoformat()
        row = {"id": "synthetic-only", "timestamp": now, "title": "합성 검증: 로그인 실패 기록", "rule": "SYNTHETIC-ONLY", "severity": "high", "organization": "fixture"}
        if path.path == "/api/operations":
            start, end = query["start"][0], query["end"][0]
            duration = datetime.fromisoformat(end.replace("Z", "+00:00")) - datetime.fromisoformat(start.replace("Z", "+00:00"))
            if duration > timedelta(days=2):
                return self.reply(503, b'{"error":"synthetic failure"}', "application/json")
            empty = duration > timedelta(hours=2)
            def section(count):
                return {"state": "ok", "count": 0 if empty else count, "rows": [], "statuses": [],
                        "buckets": [{"time": start, "count": count // 2}, {"time": end, "count": count - count // 2}]}
            sections = {"intake": section(120), "processing": section(105), "quality": section(3), "alerts": section(1),
                        "pipeline": {"state": "success", "last_success": now, "checkpoint": start}}
            if not empty:
                sections["alerts"]["rows"] = [row]
                sections["processing"]["statuses"] = [{"key": "normalized", "doc_count": 100}, {"key": "unsupported", "doc_count": 5}]
            return self.reply(200, json.dumps({"start": start, "end": end, "sections": sections}).encode(), "application/json")
        if path.path == "/api/alerts/detail":
            data = {"alert": row, "evidence_count": 1, "evidence_limit": 1, "rule_version": "synthetic", "condition": {"event_count": 1}}
            if "evidence" in query:
                data["evidence"] = {"state": "exact_reference", "raw": {"index": "soc-host-raw-fixture", "id": "fixture"}, "metadata": {"source_ip": "192.0.2.1", "user": "synthetic-user"}}
            return self.reply(200, json.dumps(data).encode(), "application/json")
        assets = {"/index.html": "text/html", "/operations.js": "text/javascript", "/operations.css": "text/css"}
        if path.path in assets:
            data = (ROOT / "prototype" / path.path.lstrip("/")).read_bytes()
            if path.path == "/index.html":
                data = data.replace("관리자 전용 · 실제 데이터".encode(), "합성 UI 검증 · 운영 데이터 아님".encode())
            return self.reply(200, data, assets[path.path])
        super().do_GET()


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 8769), OperationsPreview).serve_forever()
