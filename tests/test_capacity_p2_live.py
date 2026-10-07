"""Opt-in disposable local ES test; never targets the existing central server."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import unittest
import uuid

from elasticsearch import AuthorizationException, Elasticsearch
from cloud_soc.capacity import collect
from cloud_soc.snapshot_checks import inspect_snapshot, verify_fixture_restore

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("SOC_TEST_P2_CAPACITY_ES") == "1", "Opt-in disposable local Docker ES test")
class LiveCapacityTests(unittest.TestCase):
    def test_receipts_least_privilege_ilm_snapshot_and_exact_restore(self):
        context = os.environ.get("SOC_TEST_P2_DOCKER_CONTEXT", "desktop-linux" if os.name == "nt" else "default")
        if context not in ("default", "desktop-linux"):
            self.fail("Only a local test Docker context is allowed")
        docker = ["docker", "--context", context]
        image = "docker.elastic.co/elasticsearch/elasticsearch:9.5.2"
        name = "soc-p2-capacity-test-" + uuid.uuid4().hex[:12]

        def run(*args, check=True):
            result = subprocess.run([*docker, *args], capture_output=True, text=True, timeout=60)
            if check and result.returncode:
                self.fail("Disposable Docker operation failed; details withheld")
            return result

        endpoint = json.loads(run("context", "inspect", context).stdout)[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith(("npipe://", "unix://")):
            self.fail("A local Docker socket is required")
        run("image", "inspect", image)
        password = secrets.token_urlsafe(36)
        run("run", "--detach", "--rm", "--pull=never", "--name", name, "--memory=2g",
            "--publish", "127.0.0.1::9200", "--env", "discovery.type=single-node",
            "--env", "xpack.security.enabled=true", "--env", "xpack.security.http.ssl.enabled=false",
            "--env", "path.repo=/tmp/p2-capacity-snapshots", "--env", "ES_JAVA_OPTS=-Xms512m -Xmx512m",
            "--env", "ELASTIC_PASSWORD=" + password, image)
        try:
            port = int(run("port", name, "9200/tcp").stdout.strip().split(":")[-1])
            url = f"http://127.0.0.1:{port}"
            with Elasticsearch(url, basic_auth=("elastic", password), request_timeout=5, max_retries=0) as admin:
                for _ in range(90):
                    try:
                        admin.info()
                        break
                    except Exception:
                        time.sleep(1)
                else:
                    self.fail("Disposable Elasticsearch did not become ready")
                now = datetime.now(timezone.utc)
                suffix = uuid.uuid4().hex[:12]
                old = "soc-host-raw-p2-expired-" + suffix
                keep = "soc-network-p2-keep-" + suffix
                restored = "soc-host-raw-p2-restore-" + suffix
                fixture = "p2-fixture-" + uuid.uuid4().hex
                policy = "p2-fixture-retention"
                admin.ilm.put_lifecycle(name=policy, policy={"phases": {"hot": {"actions": {}},
                    "delete": {"min_age": "30d", "actions": {"delete": {}}}}})
                admin.indices.create(index=old, settings={"number_of_replicas": 0, "index.lifecycle.name": policy,
                    "index.lifecycle.origination_date": int((now - timedelta(days=90)).timestamp() * 1000)})
                admin.index(index=old, id=fixture, document={"p2_fixture": fixture}, refresh=True)
                admin.indices.create(index=keep, settings={"number_of_replicas": 0})
                for identifier, document in (("received", {"event": {"ingested": (now - timedelta(minutes=1)).isoformat()}}),
                                             ("legacy", {"p2_fixture": "no-receipt"})):
                    admin.index(index=keep, id=identifier, document=document, refresh=True)
                role = json.loads((ROOT / "deploy/server/capacity-reader-role.json").read_text())
                key = admin.security.create_api_key(name="p2-capacity-fixture-reader", expiration="1h",
                                                    role_descriptors={"capacity": role})
                admin.snapshot.create_repository(name="p2-fixture-repo", repository={
                    "type": "fs", "settings": {"location": "/tmp/p2-capacity-snapshots"}})
                admin.snapshot.create(repository="p2-fixture-repo", snapshot="p2-fixture-backup",
                    indices=old, wait_for_completion=True, include_global_state=False, feature_states=["none"])
                with Elasticsearch(url, api_key=key["encoded"], request_timeout=10, max_retries=0) as reader:
                    sample = collect(reader)
                    self.assertEqual(sample["summary"]["received_documents"], 1)
                    self.assertEqual(sample["summary"]["missing_receipt_documents"], 2)
                    self.assertEqual(sample["summary"]["documents"], 3)
                    checked = inspect_snapshot(reader, repository="p2-fixture-repo", snapshot="p2-fixture-backup", expected_indices=[old])
                    self.assertEqual(checked["status"], "metadata_ok")
                    self.assertFalse(checked["restore_verified"])
                    with self.assertRaises(AuthorizationException):
                        reader.indices.delete(index=keep)
                    with self.assertRaises(AuthorizationException):
                        reader.snapshot.restore(repository="p2-fixture-repo", snapshot="p2-fixture-backup")
                admin.cluster.put_settings(persistent={"indices.lifecycle.poll_interval": "1s"})
                for _ in range(120):
                    if not admin.indices.exists(index=old):
                        break
                    time.sleep(1)
                else:
                    self.fail("Disposable ILM fixture did not expire")
                self.assertTrue(admin.indices.exists(index=keep))
                admin.snapshot.restore(repository="p2-fixture-repo", snapshot="p2-fixture-backup",
                    indices=old, wait_for_completion=True, include_global_state=False, include_aliases=False,
                    rename_pattern=old, rename_replacement=restored,
                    ignore_index_settings=["index.lifecycle.name", "index.lifecycle.origination_date"])
                admin.indices.refresh(index=restored)
                with Elasticsearch(url, api_key=key["encoded"], request_timeout=10, max_retries=0) as reader:
                    self.assertEqual(verify_fixture_restore(reader, restored_index=restored, fixture_id=fixture)["status"],
                                     "synthetic_restore_verified")
        finally:
            result = run("rm", "--force", "--volumes", name, check=False)
            self.assertEqual(result.returncode, 0, "Disposable named container cleanup needs attention")


if __name__ == "__main__":
    unittest.main()
