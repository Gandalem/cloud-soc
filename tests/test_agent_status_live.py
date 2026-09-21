"""Opt-in isolated ES 9.5.2 test. No production volume, agent or packet capture."""

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import unittest
import uuid

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from elasticsearch import Elasticsearch, AuthorizationException
from cloud_soc.portal.agent_status import decode_cursor, iso, snapshot
from cloud_soc.portal.status_setup import configure_reader, configure_template, inspect_existing, install_receipt_pipeline


@unittest.skipUnless(os.environ.get("SOC_TEST_AGENT_STATUS_ES") == "1", "Opt-in local Docker Elasticsearch test")
class LiveStatusTests(unittest.TestCase):
    def test_real_pipeline_pagination_and_least_privilege(self):
        docker = ["docker"] + (["--host", "npipe:////./pipe/docker_engine"] if os.name == "nt" else [])
        image = "docker.elastic.co/elasticsearch/elasticsearch:9.5.2"
        name = "soc-status-test-" + uuid.uuid4().hex[:12]
        password = secrets.token_urlsafe(36)

        def run(*args, check=True):
            result = subprocess.run([*docker, *args], capture_output=True, text=True, timeout=60)
            if check and result.returncode:
                self.fail(f"Isolated Docker command {args[0]} failed (details withheld)")
            return result

        run("image", "inspect", image)
        run("run", "--detach", "--rm", "--pull=never", "--name", name, "--memory=2g",
            "--publish", "127.0.0.1::9200", "--env", "discovery.type=single-node",
            "--env", "xpack.security.enabled=true", "--env", "xpack.security.http.ssl.enabled=false",
            "--env", "ES_JAVA_OPTS=-Xms512m -Xmx512m", "--env", "ELASTIC_PASSWORD=" + password, image)
        # This HTTP endpoint is loopback-only, temporary and uses synthetic credentials.
        try:
            port = run("port", name, "9200/tcp").stdout.strip().split(":")[-1]
            url = f"http://127.0.0.1:{int(port)}"
            with Elasticsearch(url, basic_auth=("elastic", password), request_timeout=5, max_retries=0) as admin:
                for _ in range(90):
                    try:
                        admin.info()
                        break
                    except Exception:
                        time.sleep(1)
                else:
                    self.fail("Isolated Elasticsearch did not become ready")
                configure_reader(admin, password)
                with Elasticsearch(url, basic_auth=("cloud_soc_agent_monitor", password), request_timeout=10) as monitor:
                    self.assertEqual(snapshot(monitor)["agents"], [])
                    # Create a legacy document with no receipt time, before migration.
                    for kind, filename in [("host", "index-template.json"), ("network", "network-index-template.json")]:
                        template = json.loads((ROOT / "deploy/agents" / filename).read_text(encoding="utf-8"))
                        template["template"]["settings"]["number_of_replicas"] = 0
                        admin.indices.put_index_template(name="test-" + kind, body=template)
                    legacy = {"@timestamp": iso(datetime.now(timezone.utc)), "agent": {"id": "legacy", "type": "filebeat"}}
                    admin.index(index="soc-host-raw-legacy", id="legacy", document=legacy, refresh=True)
                    existing = inspect_existing(admin)
                    self.assertEqual(existing, ["soc-host-raw-legacy"])
                    install_receipt_pipeline(admin, existing)
                    for kind, filename in [("host", "index-template.json"), ("network", "network-index-template.json")]:
                        template = json.loads((ROOT / "deploy/agents" / filename).read_text(encoding="utf-8"))
                        template["template"]["settings"]["number_of_replicas"] = 0
                        admin.indices.put_index_template(name="test-" + kind, body=configure_template(template))
                    original = admin.get(index="soc-host-raw-legacy", id="legacy")["_source"]
                    self.assertNotIn("event", original)
                    role = {"cluster": [], "indices": [{"names": ["soc-host-raw-*", "soc-network-*"], "privileges": ["auto_configure", "create_doc"]}]}
                    key = admin.security.create_api_key(name="synthetic-publisher", expiration="1h", role_descriptors={"publisher": role})
                    with Elasticsearch(url, api_key=key["encoded"], request_timeout=10) as publisher:
                        for i in range(51):
                            doc = {"@timestamp": "2020-01-01T00:00:00Z", "organization": {"id": "test"},
                                   "agent": {"id": f"host-{i:03}", "type": "filebeat", "version": "9.5.2"},
                                   "host": {"name": "SYNTHETIC-PC", "ip": ["192.0.2.1"]},
                                   "event": {"ingested": "2099-01-01T00:00:00Z"}}
                            publisher.index(index="soc-host-raw-legacy", id=f"new-{i}", op_type="create", pipeline="_none", document=doc)
                        publisher.index(index="soc-network-test", id="network", op_type="create", pipeline="_none", document={
                            "@timestamp": "2020-01-01T00:00:00Z", "agent": {"id": "packet", "type": "packetbeat"},
                            "host": {"name": "SYNTHETIC-PC"}, "event": {"ingested": "2099-01-01T00:00:00Z"},
                        })
                        with self.assertRaises(AuthorizationException):
                            publisher.search(index="soc-host-raw-*")
                    admin.indices.refresh(index="soc-host-raw-*,soc-network-*")
                    first = snapshot(monitor)
                    self.assertEqual(len(first["agents"]), 50)
                    second = snapshot(monitor, after=decode_cursor(first["next_cursor"]))
                    all_rows = first["agents"] + second["agents"]
                    self.assertEqual(len(all_rows), 53)
                    self.assertEqual(len({row["agent_id"] for row in all_rows}), 53)
                    self.assertEqual(next(row for row in all_rows if row["agent_id"] == "legacy")["status"], "unknown")
                    new_rows = [row for row in all_rows if row["agent_id"] != "legacy"]
                    self.assertTrue(all(row["status"] == "recent" for row in new_rows),
                                    {"now": iso(datetime.now(timezone.utc)), "sample": new_rows[:2]})
                    self.assertTrue(all(not row["last_received"].startswith("2099") for row in new_rows))
                    with self.assertRaises(AuthorizationException):
                        monitor.index(index="soc-host-raw-legacy", id="denied", document={})
                    with self.assertRaises(AuthorizationException):
                        monitor.security.create_api_key(name="denied")
        finally:
            cleanup = run("rm", "--force", "--volumes", name, check=False)
            self.assertEqual(cleanup.returncode, 0, "Clean up the named soc-status-test container manually")


if __name__ == "__main__":
    unittest.main()
