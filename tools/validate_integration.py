"""Opt-in synthetic validation against a disposable TLS Elasticsearch cluster."""
import argparse
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import threading
import time

from elasticsearch import Elasticsearch, AuthorizationException
import requests
from werkzeug.security import generate_password_hash
from werkzeug.serving import make_server

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from cloud_soc.processing.setup import prepare as prepare_processing, ROLE as NORMALIZER_ROLE
from cloud_soc.processing.worker import run_once as normalize_once
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
from cloud_soc.detection.setup import prepare as prepare_detection, ROLE as DETECTOR_ROLE
from cloud_soc.detection.worker import run_once as detect_once
from cloud_soc.detection.incremental import run_incremental
from cloud_soc.detection.telemetry import RUNS, EXCLUSIONS
from cloud_soc.portal.app import create_app
from cloud_soc.portal.reprocessing_history import INDEX as HISTORY


def validate(args, report):
    password = Path(args.password_file).read_text(encoding="utf-8").strip()
    client = Elasticsearch(args.es_url, basic_auth=("elastic", password), ca_certs=args.ca_file,
                           request_timeout=30, max_retries=0)
    if client.info()["cluster_name"] != "cloud-soc-integration-20261008":
        raise ValueError("Only the disposable integration cluster is permitted")
    report["elasticsearch_version"] = client.info()["version"]["number"]
    if args.reset:
        for index in ("soc-host-raw-integration", NORMALIZED, RECORDS, STATUS, "security-alerts", RUNS, EXCLUSIONS, HISTORY):
            if client.indices.exists(index=index):
                client.indices.delete(index=index)
    checks = report["checks"]

    def check(name, condition, **details):
        checks.append({"name": name, "passed": bool(condition), **details})
        if not condition:
            raise AssertionError(name)

    state = Path(args.output).resolve().parent / (Path(args.output).stem + "-state")
    state.mkdir(exist_ok=True)
    now = datetime.now(timezone.utc) - timedelta(minutes=2)
    start = now - timedelta(minutes=3)
    stamp = lambda value: value.isoformat()
    raw_index = "soc-host-raw-integration"
    client.indices.create(index=raw_index, settings={"number_of_replicas": 0}, mappings={
        "dynamic": False, "properties": {"@timestamp": {"type": "date"},
            "event": {"properties": {"ingested": {"type": "date"}}},
            "organization": {"properties": {"id": {"type": "keyword"}}}}})
    prepare_processing(client)
    prepare_detection(client)
    sources = []
    for number in range(10):
        occurred = start + timedelta(seconds=number + 10)
        sources.append({"@timestamp": stamp(occurred), "event": {"ingested": stamp(occurred), "timezone": "UTC"},
            "organization": {"id": "team-a"}, "host": {"name": "integration-host", "os": {"type": "linux"}},
            "labels": {"log_source": "linux_file"}, "log": {"file": {"path": "/var/log/auth.log"}},
            "message": occurred.strftime("%b %d %H:%M:%S") +
                " integration-host sshd[100]: Failed password for fixture from 192.0.2.10 port 12345 ssh2"})
    for number, message, program in [(10, "Started fixture.service.", "systemd"),
                                    (11, "fixture : TTY=pts/0 ; PWD=/ ; USER=root ; COMMAND=/bin/true password=PRIVATE_CANARY", "sudo"),
                                    (12, '{"level":"error","msg":"PRIVATE_CANARY"}', "dockerd")]:
        source = deepcopy(sources[0])
        source["labels"]["log_source"] = "linux_journald"
        source["process"] = {"name": program}
        source["message"] = message
        source["log"]["file"]["path"] = "/var/log/syslog"
        if number == 10:
            source["labels"]["log_source"] = "linux_file"
            source["message"] = (start + timedelta(seconds=10)).strftime("%b %d %H:%M:%S") + " integration-host systemd[1]: " + message
        sources.append(source)
    invalid = deepcopy(sources[0])
    invalid["event"]["timezone"] = "invalid"
    sources.append(invalid)
    unsupported = deepcopy(sources[0])
    unsupported["message"] = "malformed\nPRIVATE_CANARY"
    sources.append(unsupported)
    foreign = deepcopy(sources[0])
    foreign["organization"]["id"] = "team-b"
    sources.append(foreign)
    for number, source in enumerate(sources):
        client.create(index=raw_index, id=str(number), document=source)
    client.indices.refresh(index=raw_index)
    normalizer_key = client.security.create_api_key(name="integration-normalizer", expiration="1h",
        role_descriptors={"normalizer": NORMALIZER_ROLE})
    detector_key = client.security.create_api_key(name="integration-detector", expiration="1h",
        role_descriptors={"detector": DETECTOR_ROLE})
    with Elasticsearch(args.es_url, api_key=normalizer_key["encoded"], ca_certs=args.ca_file) as normalizer:
        initial = normalize_once(normalizer, state / "normalizer.sqlite", stamp(start), now=now)
        client.indices.refresh(index=[NORMALIZED, RECORDS, STATUS])
        before = client.count(index=NORMALIZED)["count"]
        repeated = normalize_once(normalizer, state / "normalizer.sqlite", stamp(start), now=now + timedelta(seconds=5))
        client.indices.refresh(index=[NORMALIZED, RECORDS, STATUS])
        check("intake_normalization_storage_and_replay", before == 14 and client.count(index=NORMALIZED)["count"] == before,
              raw_documents=len(sources), normalized=before, first_counts=initial["counts"], replay_counts=repeated["counts"])
        records = client.search(index=RECORDS, size=100)["hits"]["hits"]
        quarantined = [row["_source"] for row in records if row["_source"]["status"] != "normalized"]
        check("invalid_and_unsupported_quarantine", len(quarantined) == 2 and
              "PRIVATE_CANARY" not in json.dumps(quarantined), reasons=[row["reason"] for row in quarantined])
        denied = 0
        for operation in (lambda: normalizer.create(index=raw_index, id="forbidden", document={}),
                          lambda: normalizer.create(index="security-alerts", id="forbidden", document={}),
                          lambda: normalizer.index(index=NORMALIZED, id="forbidden", document={})):
            try:
                operation()
            except AuthorizationException:
                denied += 1
        check("normalizer_least_privilege", denied == 3, denied_operations=denied)
    with Elasticsearch(args.es_url, api_key=detector_key["encoded"], ca_certs=args.ca_file) as detector:
        detected = detect_once(detector)
        client.indices.refresh(index="security-alerts")
        replay = detect_once(detector)
        client.indices.refresh(index="security-alerts")
        check("same_event_alert_deduplication", detected["created"] == 1 and replay["existing"] == 1 and
              client.count(index="security-alerts")["count"] == 1, first=detected, replay=replay)
        run_incremental(detector, state_path=state / "detector.sqlite", start=start,
                        now=now + timedelta(seconds=100), lateness_seconds=60)
        client.indices.refresh(index=["security-alerts", RUNS, EXCLUSIONS, STATUS])
        check("incremental_durable_history", client.count(index=RUNS)["count"] >= 2)
        denied = 0
        for operation in (lambda: detector.index(index="security-alerts", id="forbidden", document={}),
                          lambda: detector.create(index=raw_index, id="forbidden", document={})):
            try:
                operation()
            except AuthorizationException:
                denied += 1
        check("detector_least_privilege", denied == 2)
    alert = client.search(index="security-alerts", size=1)["hits"]["hits"][0]
    risk = alert["_source"]["cloud_soc"]
    check("explainable_risk", 0 < risk["risk_score"] <= 100 and
          risk["risk_score"] == sum(row["points"] for row in risk["risk_factors"]),
          risk_score=risk["risk_score"], risk_level=risk["risk_level"])
    normalized_rows = client.search(index=NORMALIZED, size=100)["hits"]["hits"]
    check("auth_syslog_operational_metadata", {"linux_ssh_v1", "linux_operational_v1"}.issubset(
        {row["_source"]["cloud_soc"]["detail"]["adapter"] for row in normalized_rows}) and
        "PRIVATE_CANARY" not in json.dumps(normalized_rows))
    mapping = deepcopy(client.indices.get_mapping(index=NORMALIZED)[NORMALIZED]["mappings"])
    mapping["_meta"]["contract"] = "ubuntu-linux-parser-757-v3"
    client.indices.create(index=HISTORY, mappings=mapping, settings={"number_of_replicas": 0})
    for number in range(57):
        source = deepcopy(normalized_rows[0]["_source"])
        source["cloud_soc"]["parse_status"] = "partial" if number < 53 else "recognized"
        source["cloud_soc"]["historical_replay"] = {"job": "ubuntu-linux-parser-757-v3", "history_only": True}
        source["host"] = {"name": "integration-host"}
        client.create(index=HISTORY, id=f"{number:064d}", document=source)
    client.indices.refresh(index=HISTORY)
    monitor_key = client.security.create_api_key(name="integration-reader", expiration="1h", role_descriptors={
        "reader": {"cluster": [], "indices": [{"names": [raw_index, NORMALIZED, RECORDS, STATUS,
            "security-alerts", RUNS, EXCLUSIONS, HISTORY], "privileges": ["read", "view_index_metadata"]}]}})
    monitor = Elasticsearch(args.es_url, api_key=monitor_key["encoded"], ca_certs=args.ca_file)
    hashed = generate_password_hash("synthetic-password", method="pbkdf2:sha256:1000")
    users = {name: {"role": role, "password_hash": hashed} for name, role in
             (("admin", "admin"), ("view", "viewer"), ("investigate", "analyst"), ("other", "analyst"))}
    users_file = state / "users.json"
    users_file.write_text(json.dumps(users), encoding="utf-8")
    users_file.chmod(0o600)
    policy = {"version": 1, "protected_source_enabled": True, "admin_source_organizations": ["team-a"],
              "users": [{"username": name, "password_hash": hashed, "role": role, "organizations": [organization]}
                        for name, role, organization in (("view", "viewer", "team-a"),
                            ("investigate", "investigator", "team-a"), ("other", "investigator", "team-b"))]}
    origin = "http://127.0.0.1:28865"
    settings = {"STATE_DIR": state, "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": Path(args.ca_file).read_bytes(),
                "PUBLIC_URL": origin, "ENDPOINT": args.es_url, "ADMIN_USER": "admin", "ADMIN_HASH": hashed,
                "LOG_ACCESS_POLICY": policy, "USERS_FILE": str(users_file)}
    app = create_app(settings, issuer=client, monitor=monitor)
    server = make_server("127.0.0.1", 28865, app, threaded=True)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    try:
        sessions = {}
        headers = {}
        for name in users:
            session = requests.Session()
            response = session.post(origin + "/api/auth/login", json={"username": name, "password": "synthetic-password"},
                                    headers={"X-Cloud-SOC": "portal"}, timeout=10)
            check("http_session_login_" + name, response.status_code == 200)
            identity = session.get(origin + "/api/auth/me", timeout=10).json()
            sessions[name] = session
            headers[name] = {"X-Cloud-SOC": "portal", "X-CSRF-Token": identity["csrf"]}
        check("unauthenticated_api", requests.get(origin + "/api/logs", timeout=10).status_code == 401)
        query = {"start": stamp(start - timedelta(minutes=1)), "end": stamp(now + timedelta(minutes=1))}
        own = sessions["view"].get(origin + "/api/logs", params=query, timeout=10)
        check("http_scoped_log_query", own.status_code == 200 and len(own.json()["rows"]) == 15,
              status=own.status_code, rows=len(own.json().get("rows", [])))
        reference = {"index": raw_index, "id": "0", "purpose": "investigation"}
        foreign_response = sessions["other"].post(origin + "/api/logs/source", json=reference, headers=headers["other"], timeout=10)
        view_response = sessions["view"].post(origin + "/api/logs/source", json=reference, headers=headers["view"], timeout=10)
        check("http_organization_and_role_isolation", foreign_response.status_code == 404 and view_response.status_code == 403)
        protected = sessions["investigate"].post(origin + "/api/logs/source", json={**reference, "id": "11"},
                                               headers=headers["investigate"], timeout=10)
        check("http_source_masking_and_audit", protected.status_code == 200 and "PRIVATE_CANARY" not in protected.text)
        with app.extensions["source_audit"].connect() as database:
            audit_count = database.execute("SELECT count(*) FROM source_access").fetchone()[0]
        check("durable_source_audit", audit_count == 3, audit_rows=audit_count)
        forbidden = sessions["investigate"].get(origin + "/api/detection/history", timeout=10)
        check("scoped_session_cannot_read_global_history", forbidden.status_code == 403)
        first = sessions["admin"].get(origin + "/api/detection/history", params={"rule": "AUTH-001", "limit": "1"}, timeout=10)
        check("http_detection_history_filter_page", first.status_code == 200 and len(first.json()["rows"]) == 1 and bool(first.json()["next"]))
        second = sessions["admin"].get(origin + "/api/detection/history", params={"rule": "AUTH-001", "limit": "1",
            "start": first.json()["start"], "end": first.json()["end"], "after": first.json()["next"]}, timeout=10)
        check("http_detection_history_seek", second.status_code == 200 and first.json()["rows"][0]["record_id"] != second.json()["rows"][0]["record_id"])
        identifiers = []
        for page in (1, 2):
            response = sessions["admin"].get(origin + "/api/reprocessing/history", params={"q": "integration-host", "status": "partial", "page": str(page)}, timeout=10)
            check("http_reprocessing_history_page_" + str(page), response.status_code == 200 and response.json()["filtered_total"] == 53)
            identifiers.extend(row["id"] for row in response.json()["rows"])
        check("http_reprocessing_no_missing_or_duplicate_rows", len(identifiers) == len(set(identifiers)) == 53)
        detail = sessions["admin"].get(origin + "/api/alerts/detail", params={"id": alert["_id"], "evidence": "0"}, timeout=10)
        check("http_alert_exact_evidence", detail.status_code == 200 and detail.json()["evidence"]["state"] == "exact_reference")
        check("http_csrf_source_guard", sessions["investigate"].post(origin + "/api/logs/source", json=reference,
            headers={"X-Cloud-SOC": "portal"}, timeout=10).status_code == 403)
        with app.extensions["source_audit"].connect() as database:
            database.execute("ALTER TABLE source_access RENAME TO temporarily_unavailable")
        response = sessions["investigate"].post(origin + "/api/logs/source", json=reference, headers=headers["investigate"], timeout=10)
        check("http_audit_failure_closes_source", response.status_code == 503 and "source" not in response.json())
        with app.extensions["source_audit"].connect() as database:
            database.execute("ALTER TABLE temporarily_unavailable RENAME TO source_access")
        report["passed"] = True
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print("Live TLS storage and HTTP API validation passed; browser preview ready", flush=True)
        deadline = time.monotonic() + args.serve_seconds
        while time.monotonic() < deadline and not (state.parent / "stop-validation.flag").exists():
            time.sleep(1)
    finally:
        server.shutdown()
        server_thread.join(timeout=5)
        monitor.close()
        client.security.invalidate_api_key(ids=[normalizer_key["id"], detector_key["id"], monitor_key["id"]])
        client.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--es-url", required=True)
    parser.add_argument("--ca-file", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--serve-seconds", type=int, default=0)
    parser.add_argument("--reset", action="store_true")
    args = parser.parse_args()
    report = {"passed": False, "checks": [], "scope": "disposable synthetic TLS ES and actual HTTP API"}
    try:
        validate(args, report)
    except Exception as error:
        report["error_type"] = type(error).__name__
        Path(args.output).write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
        print("Live validation failed; inspect structured evidence. Error type: " + type(error).__name__, flush=True)
        raise


if __name__ == "__main__":
    main()
