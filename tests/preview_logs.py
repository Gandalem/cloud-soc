"""Loopback-only synthetic UI fixture. Never connects to ES or reads credentials.

Run explicitly: python tests/preview_logs.py. Stop with Ctrl+C.
This is not a central-server deployment entry point.
"""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
from urllib.parse import parse_qs, urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cloud_soc.portal.log_contract import project_hit
from cloud_soc.portal.collection_health import project as project_health
from cloud_soc.portal.security_detail import security_detail
from cloud_soc.aws.cloudtrail import project_event, timestamp
from cloud_soc.oci.audit import project_event as project_oci

FIXTURES = json.loads((ROOT / "tests/fixtures/log_intake.json").read_text(encoding="utf-8"))["hits"]
FIXTURES[0]["_source"]["winlog"].update(provider_name="Microsoft-Windows-Security-Auditing")
FIXTURES[0]["_source"]["winlog"]["event_data"].update(LogonType="10", IpAddress="198.51.100.10", IpPort="55000")
for event in json.loads((ROOT / "tests/fixtures/cloudtrail_management.json").read_text(encoding="utf-8"))["events"]:
    index, identifier, document = project_event({"EventId": event["eventID"], "EventTime": timestamp(event["eventTime"]), "CloudTrailEvent": json.dumps(event)},
                                                 account="123456789012", region=event["awsRegion"], organization="synthetic")
    FIXTURES.append({"_index": index, "_id": identifier, "_source": document})


OCI_FIXTURE = json.loads((ROOT / "tests/fixtures/oci_audit.json").read_text(encoding="utf-8"))
for event in OCI_FIXTURE["events"]:
    index, identifier, document = project_oci(event, tenancy=OCI_FIXTURE["tenancy"], compartment=OCI_FIXTURE["compartment"], region=OCI_FIXTURE["region"], organization="synthetic")
    FIXTURES.append({"_index": index, "_id": identifier, "_source": document})


class Preview(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urlsplit(self.path)
        params = parse_qs(parsed.query)
        if parsed.path == "/api/agents/health":
            now = datetime.now(timezone.utc)
            source = {"host": {"name": "SYNTHETIC-WINDOWS"}, "event": {"ingested": now.isoformat()}, "cloud_soc": {"discovery": {
                "schema": 1, "generated_at": (now - timedelta(seconds=12)).isoformat(), "policy_version": 2,
                "selected": 28, "excluded": 4, "errors": 1, "total": 33,
                "sources": [{"id": "a" * 64, "status": "selected"}, {"id": "b" * 64, "status": "unreadable"}]}}}
            data = {"rows": [project_health(source, {"agent_id": "synthetic", "organization": "test"}, now)], "next_cursor": None}
            return self.reply(200, json.dumps(data).encode(), "application/json")
        if parsed.path == "/api/logs":
            host = params.get("host", [""])[0]
            if host == "unavailable":
                return self.reply(503, b'{"error":"synthetic failure"}', "application/json")
            now = datetime.now(timezone.utc)
            rows = [project_hit(hit) for hit in FIXTURES]
            for row in rows:
                row["received_at"] = now.isoformat()
            if host:
                rows = [row for row in rows if row["host_name"] == host]
            for name in ("collector", "os"):
                if params.get(name, [""])[0]:
                    rows = [row for row in rows if row[name] == params[name][0]]
            data = {"contract_version": 1, "rows": rows, "filters": {
                "start": (now - timedelta(hours=1)).isoformat(), "end": now.isoformat(), "time_basis": "ingested"},
                "raw_access": "restricted", "next_cursor": None, "total": None}
            return self.reply(200, json.dumps(data).encode(), "application/json")
        if parsed.path == "/api/logs/detail":
            matches = [hit for hit in FIXTURES if hit["_id"] == params.get("id", [None])[0] and hit["_index"] == params.get("index", [None])[0]]
            if not matches:
                return self.reply(404, b"{}", "application/json")
            data = {"contract_version": 1, "row": project_hit(matches[0]), "raw_access": "restricted",
                    "security": security_detail(matches[0]["_source"])}
            return self.reply(200, json.dumps(data).encode(), "application/json")
        assets = {"/logs.html": "text/html", "/logs.js": "text/javascript", "/logs.css": "text/css",
                  "/styles.css": "text/css", "/agents.css": "text/css", "/assets/mark.svg": "image/svg+xml",
                  "/collection-health.html": "text/html", "/collection-health.js": "text/javascript", "/agent-status.css": "text/css"}
        if parsed.path not in assets:
            return self.reply(404, b"Not found", "text/plain")
        data = (ROOT / "prototype" / parsed.path.lstrip("/")).read_bytes()
        if parsed.path == "/logs.html":
            data = data.replace("관리자 전용 · 읽기 전용".encode(), "합성 UI 검증 전용 · 운영 데이터 아님".encode())
        if parsed.path == "/collection-health.html":
            data = data.replace("관리자 전용 · 실제 보고 데이터".encode(), "합성 UI 검증 전용 · 운영 데이터 아님".encode())
        self.reply(200, data, assets[parsed.path])

    def reply(self, status, data, content_type):
        self.send_response(status)
        self.send_header("Content-Type", content_type + "; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, *_args):
        pass


if __name__ == "__main__":
    print("Synthetic UI only: http://127.0.0.1:8769/logs.html", flush=True)
    ThreadingHTTPServer(("127.0.0.1", 8769), Preview).serve_forever()
