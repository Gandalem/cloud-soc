"""Real isolated ES evidence -> authenticated Flask API -> durable case work."""
import json
from pathlib import Path
import tempfile
import uuid
from unittest.mock import Mock
from cloud_soc.portal.app import create_app
from cloud_soc.portal.operations import Operations
import test_portal


def check_p6(test, admin, monitor):
    source = admin.get(index="security-alerts", id="synthetic-p5-alert")["_source"]
    source["organization"] = {"id": "fixture"}
    admin.index(index="security-alerts", id="synthetic-p6-alert", document=source, refresh=True)
    with tempfile.TemporaryDirectory() as directory:
        settings = {"STATE_DIR": Path(directory), "AGENT_SOURCE": test_portal.ROOT / "deploy/agents", "CA_BYTES": test_portal.CA,
                    "PUBLIC_URL": "http://localhost", "ENDPOINT": "https://soc.example.test:9200", "ADMIN_USER": "admin", "ADMIN_HASH": test_portal.HASH}
        app = create_app(settings, issuer=Mock(), monitor=monitor)
        headers = {"Authorization": test_portal.AUTH, "X-Cloud-SOC": "portal", "Idempotency-Key": str(uuid.uuid4())}
        with app.test_client() as client:
            response = client.post("/api/cases", json={"alert_id": "synthetic-p6-alert", "title": "Synthetic ES incident", "priority": "high"}, headers=headers)
            test.assertEqual(response.status_code, 200, response.json)
            identifier = response.json["id"]
            updated = client.patch("/api/cases/"+identifier, json={"version": 1, "owner": "admin", "status": "investigating", "note": "Exact reference reviewed"}, headers={**headers, "Idempotency-Key": str(uuid.uuid4())})
            test.assertEqual(updated.status_code, 200, updated.json)
            detail = client.get("/api/alerts/detail?id=synthetic-p6-alert&evidence=0", headers=headers)
            test.assertEqual(detail.json["evidence"]["state"], "exact_reference")
            test.assertNotIn("PRIVATE_CANARY", detail.get_data(as_text=True))
        restarted = create_app(settings, issuer=Mock(), monitor=monitor)
        with restarted.test_client() as client:
            stored = client.get("/api/cases/"+identifier, headers=headers)
            test.assertEqual(stored.json["case"]["version"], 2)
            test.assertEqual(stored.json["history"][0]["note"], "Exact reference reviewed")
            queue = client.get("/api/cases?owner=me&status=investigating", headers=headers)
            test.assertEqual(queue.json["counts"]["total"], 1)
        # Deleting this named synthetic alert tests retention without deleting its case.
        admin.delete(index="security-alerts", id="synthetic-p6-alert", refresh=True)
        with restarted.test_client() as client:
            test.assertEqual(client.get("/api/alerts/detail?id=synthetic-p6-alert", headers=headers).status_code, 404)
            retained = client.get("/api/cases/"+identifier, headers=headers).json
            test.assertEqual(retained["alerts"][0]["snapshot"]["rule"], "SYNTHETIC-ONLY")
