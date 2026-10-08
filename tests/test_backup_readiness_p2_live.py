"""Opt-in local disposable ES test. No production mounts, agents or cloud connections."""
import json
import os
from pathlib import Path
import secrets
import subprocess
import time
import unittest
import uuid

from elasticsearch import AuthorizationException, Elasticsearch
from cloud_soc.backup_readiness import backup_health, POLICY_ID, slm_candidate

ROOT = Path(__file__).resolve().parents[1]


@unittest.skipUnless(os.environ.get("SOC_TEST_P2_BACKUP_ES") == "1", "Opt-in disposable local Docker backup test")
class LiveBackupReadinessTests(unittest.TestCase):
    def test_real_slm_metadata_minimal_reader_and_isolated_restore(self):
        context = os.environ.get("SOC_TEST_P2_DOCKER_CONTEXT", "desktop-linux" if os.name == "nt" else "default")
        if context not in ("default", "desktop-linux"):
            self.fail("Only a local Docker context is permitted")
        docker = ["docker", "--context", context]

        def run(*args, check=True):
            result = subprocess.run([*docker, *args], capture_output=True, text=True, timeout=60)
            if check and result.returncode:
                self.fail("Disposable local Docker operation failed; details withheld")
            return result

        endpoint = json.loads(run("context", "inspect", context).stdout)[0]["Endpoints"]["docker"]["Host"]
        if not endpoint.startswith(("npipe://", "unix://")):
            self.fail("Local Docker socket required")
        image = "docker.elastic.co/elasticsearch/elasticsearch:9.5.2"
        run("image", "inspect", image)
        name = "soc-p2-backup-test-" + uuid.uuid4().hex[:12]
        password = secrets.token_urlsafe(36)
        run("run", "--detach", "--rm", "--pull=never", "--name", name, "--memory=2g",
            "--publish", "127.0.0.1::9200", "--env", "discovery.type=single-node",
            "--env", "xpack.security.enabled=true", "--env", "xpack.security.http.ssl.enabled=false",
            "--env", "path.repo=/tmp/p2-backup", "--env", "ES_JAVA_OPTS=-Xms512m -Xmx512m",
            "--env", "ELASTIC_PASSWORD=" + password, image)
        try:
            port = int(run("port", name, "9200/tcp").stdout.strip().split(":")[-1])
            with Elasticsearch(f"http://127.0.0.1:{port}", basic_auth=("elastic", password),
                               request_timeout=10, max_retries=0) as admin:
                for _ in range(90):
                    try:
                        admin.info()
                        break
                    except Exception:
                        time.sleep(1)
                else:
                    self.fail("Disposable ES did not become ready")
                indices = ["soc-host-raw-fixture", "soc-network-fixture", "soc-agent-health-fixture"]
                for index in indices:
                    admin.indices.create(index=index, settings={"number_of_replicas": 0})
                    admin.index(index=index, id="fixture", document={"p2_fixture": index}, refresh=True)
                repository = "cloud-soc-p2-test-repo"
                admin.snapshot.create_repository(name=repository, repository={"type": "fs", "settings": {"location": "/tmp/p2-backup"}})
                candidate = slm_candidate(repository)
                admin.slm.put_lifecycle(policy_id=POLICY_ID, **candidate)
                self.assertEqual(admin.slm.get_lifecycle(policy_id=POLICY_ID)[POLICY_ID]["policy"], candidate)
                snapshot = admin.slm.execute_lifecycle(policy_id=POLICY_ID)["snapshot_name"]
                for _ in range(90):
                    row = admin.snapshot.get(repository=repository, snapshot=snapshot)["snapshots"][0]
                    if row["state"] != "IN_PROGRESS":
                        break
                    time.sleep(1)
                self.assertEqual(row["state"], "SUCCESS")
                self.assertEqual(row["metadata"]["policy"], POLICY_ID)
                role = json.loads((ROOT / "deploy/server/backup-health-reader-role.json").read_text())
                key = admin.security.create_api_key(name="synthetic-backup-health", expiration="1h", role_descriptors={"health": role})
                with Elasticsearch(f"http://127.0.0.1:{port}", api_key=key["encoded"], request_timeout=10) as reader:
                    report = backup_health(reader, repository=repository, expected_indices=indices)
                    self.assertEqual(report["status"], "metadata_ok")
                    self.assertFalse(report["restore_verified"])
                    with self.assertRaises(AuthorizationException):
                        reader.search(index=indices[0])
                    with self.assertRaises(AuthorizationException):
                        reader.snapshot.delete(repository=repository, snapshot=snapshot)
                    with self.assertRaises(AuthorizationException):
                        reader.slm.put_lifecycle(policy_id=POLICY_ID, **candidate)
                admin.snapshot.restore(repository=repository, snapshot=snapshot, indices=indices[0],
                    rename_pattern="(.+)", rename_replacement="restored-$1", include_global_state=False, wait_for_completion=True)
                restored = "restored-" + indices[0]
                admin.indices.refresh(index=restored)
                self.assertEqual(admin.count(index=restored)["count"], 1)
                self.assertEqual(admin.get(index=restored, id="fixture")["_source"], {"p2_fixture": indices[0]})
        finally:
            result = run("rm", "--force", "--volumes", name, check=False)
            self.assertEqual(result.returncode, 0, "Remove the named soc-p2-backup-test container manually")


if __name__ == "__main__":
    unittest.main()
