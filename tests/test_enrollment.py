"""No network, services, real tokens or capture: protocol/security regression tests."""

import base64
from concurrent.futures import ThreadPoolExecutor
import io
import json
from pathlib import Path
import secrets
import tempfile
import threading
import unittest
from unittest.mock import Mock
import zipfile

from werkzeug.security import generate_password_hash

from cloud_soc.portal.app import create_app
from cloud_soc.portal.backup import backup, restore, verify
from cloud_soc.portal.enrollment import TOKEN_TTL, SESSION_TTL
from cloud_soc.portal.status_setup import PIPELINE, PIPELINE_ID

ROOT = Path(__file__).resolve().parents[1]
AGENTS = {"host": "00000000-0000-0000-0000-000000000001", "network": "00000000-0000-0000-0000-000000000002"}


class EnrollmentTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.issuer, self.monitor = Mock(), Mock()
        self.issuer.ingest.get_pipeline.return_value = {PIPELINE_ID: PIPELINE}
        self.issuer.security.create_api_key.side_effect = [
            {"id": "host-test-id", "api_key": "SENSITIVE_HOST_CANARY", "expiration": 2000000000000},
            {"id": "network-test-id", "api_key": "SENSITIVE_NETWORK_CANARY", "expiration": 2000000000000}]
        self.issuer.security.invalidate_api_key.return_value = {"error_count": 0, "invalidated_api_keys": [], "previously_invalidated_api_keys": []}
        self.issuer.security.get_api_key.return_value = {"api_keys": []}
        settings = {"STATE_DIR": self.root / "portal", "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": b"PUBLIC SYNTHETIC CA",
                    "PUBLIC_URL": "https://soc.example.test", "ENDPOINT": "https://receiver.example.test:9200",
                    "ENROLLMENT_ENABLED": True,
                    "ADMIN_USER": "admin", "ADMIN_HASH": generate_password_hash("synthetic-password", method="pbkdf2:sha256:1000")}
        self.app = create_app(settings, issuer=self.issuer, monitor=self.monitor)
        self.settings = settings
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()
        self.service = self.app.extensions["enrollments"]
        self.now = 1900000000
        self.service.clock = lambda: self.now
        self.auth = {"Authorization": "Basic " + base64.b64encode(b"admin:synthetic-password").decode(), "X-Cloud-SOC": "portal"}
        self.package = self.app.extensions["packages"].create({"name": "enrollment-test", "organization": "school", "os": "windows", "network": True})
        self.attempt = secrets.token_urlsafe(32)

    def admin(self, method, path, data=None):
        return self.client.open(path, method=method, json=data, base_url="https://soc.example.test", headers=self.auth)

    def mint(self):
        result = self.admin("POST", f"/api/packages/{self.package['id']}/enrollment", {"days": 1, "target_label": "test VM"})
        self.assertEqual(result.status_code, 201, result.json)
        self.token = result.json["token"]
        self.sid = result.json["id"]
        return result.json

    def machine(self, route, data, **headers):
        return self.client.post("/api/installer/" + route, json=data, base_url="https://soc.example.test",
                                headers={"Authorization": "Bearer " + self.token, "X-Cloud-SOC": "installer", **headers})

    def exchange(self):
        return self.machine("enroll", {"attempt": self.attempt, "package_id": self.package["id"], "package_sha256": self.package["sha256"]})

    def proof(self, host=1, network=1):
        def search(**kwargs):
            scope = "host" if kwargs["index"].startswith("soc-host") else "network"
            value = host if scope == "host" else network
            index = "soc-host-raw-windows-test" if scope == "host" else "soc-network-windows-test"
            return {"timed_out": False, "_shards": {"failed": 0}, "hits": {"total": {"value": value, "relation": "eq"}, "hits": [{"_index": index}] if value else []}}
        self.monitor.search.side_effect = search
        self.monitor.indices.get_settings.side_effect = lambda **k: {k["index"]: {"settings": {"index.final_pipeline": PIPELINE_ID}}}

    def test_single_token_scopes_binding_and_encrypted_retry(self):
        minted = self.mint()
        first, second = self.exchange(), self.exchange()
        self.assertEqual(first.status_code, 200, first.json)
        self.assertEqual(first.json, second.json)
        self.assertEqual(self.issuer.security.create_api_key.call_count, 2)
        self.assertFalse(first.json["receipt_verified"])
        for scope, call in zip(("host", "network"), self.issuer.security.create_api_key.call_args_list):
            role = call.kwargs["role_descriptors"][f"cloud_soc_{scope}"]
            self.assertEqual(role["indices"][0]["privileges"], ["auto_configure", "create_doc"])
            self.assertNotIn("read", role["indices"][0]["privileges"])
            self.assertNotIn("manage_own_api_key", role["cluster"])
            self.assertNotIn("soc-network-*", role["indices"][0]["names"])
            self.assertEqual(call.kwargs["metadata"], {"package_id": self.package["id"], "organization": "school", "enrollment_id": self.sid, "scope": scope})
        stored = (self.root / "portal/packages.sqlite3").read_bytes()
        for secret in (self.token, self.attempt, "SENSITIVE_HOST_CANARY", "SENSITIVE_NETWORK_CANARY"):
            self.assertNotIn(secret.encode(), stored)
        metadata = self.admin("GET", "/api/enrollments").data + self.admin("GET", "/api/keys").data
        self.assertNotIn(minted["token"].encode(), metadata)
        self.assertNotIn(b"SENSITIVE", metadata)
        _, archive = self.app.extensions["packages"].get(self.package["id"], archive=True)
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            for name in z.namelist():
                self.assertNotIn(self.token.encode(), z.read(name))
                self.assertNotIn(b"SENSITIVE_HOST_CANARY", z.read(name))

    def test_wrong_package_does_not_consume_and_wrong_attempt_cannot_retry(self):
        self.mint()
        result = self.machine("enroll", {"attempt": self.attempt, "package_id": "0" * 32, "package_sha256": self.package["sha256"]})
        self.assertEqual(result.status_code, 409)
        self.assertEqual(self.exchange().status_code, 200)
        self.attempt = secrets.token_urlsafe(32)
        self.assertEqual(self.exchange().status_code, 409)
        self.assertEqual(self.issuer.security.create_api_key.call_count, 2)

    def test_expiry_deleted_package_and_missing_pipeline(self):
        self.mint()
        self.now += TOKEN_TTL
        self.assertEqual(self.exchange().status_code, 410)
        self.issuer.security.create_api_key.assert_not_called()
        self.mint()
        self.issuer.ingest.get_pipeline.return_value = {PIPELINE_ID: {"processors": []}}
        self.assertEqual(self.exchange().status_code, 503)
        self.issuer.security.create_api_key.assert_not_called()
        self.issuer.ingest.get_pipeline.return_value = {PIPELINE_ID: PIPELINE}
        self.app.extensions["packages"].delete(self.package["id"])
        self.assertEqual(self.exchange().status_code, 404)

    def test_only_specific_machine_endpoints_bypass_admin_and_browser_is_rejected(self):
        self.mint()
        for headers in ({"Origin": "https://soc.example.test"}, {"Sec-Fetch-Site": "same-origin"}, {"X-Cloud-SOC": "portal"}):
            self.assertEqual(self.machine("enroll", {"attempt": self.attempt}, **headers).status_code, 403)
        for route in ("/api/keys", "/api/enrollments", "/api/portal", "/agents.html"):
            r = self.client.get(route, base_url="https://soc.example.test", headers={"Authorization": "Bearer " + self.token})
            self.assertEqual(r.status_code, 401)
        self.token = "invalid"
        self.assertEqual(self.exchange().status_code, 401)

    def test_partial_failure_cleans_both_names_and_never_returns_secret(self):
        self.mint()
        self.issuer.security.create_api_key.side_effect = [{"id": "host-test-id", "api_key": "SENSITIVE_HOST_CANARY"}, RuntimeError("SENSITIVE_UPSTREAM")]
        response = self.exchange()
        self.assertEqual(response.status_code, 503)
        self.assertNotIn(b"SENSITIVE", response.data)
        self.assertEqual(self.issuer.security.invalidate_api_key.call_count, 2)
        self.assertEqual(self.service.listing()[0]["state"], "cancelled")
        self.assertEqual(self.exchange().status_code, 409)

    def test_ambiguous_issue_and_cleanup_failure_remain_visible_and_retryable(self):
        self.mint()
        self.issuer.security.create_api_key.side_effect = RuntimeError("SENSITIVE lost response")
        self.issuer.security.invalidate_api_key.side_effect = RuntimeError("SENSITIVE failed cleanup")
        self.assertEqual(self.exchange().status_code, 503)
        self.assertEqual(self.service.listing()[0]["state"], "cleanup_pending")
        self.assertEqual(self.admin("POST", f"/api/enrollments/{self.sid}/cancel", {}).status_code, 503)
        self.issuer.security.invalidate_api_key.side_effect = None
        self.assertEqual(self.admin("POST", f"/api/enrollments/{self.sid}/cancel", {}).status_code, 200)

    def test_race_has_one_consumer_and_never_duplicates_keys(self):
        self.mint()
        entered, release = threading.Event(), threading.Event()
        calls = []
        def issue(**kwargs):
            calls.append(kwargs)
            entered.set()
            release.wait(3)
            scope = kwargs["metadata"]["scope"]
            return {"id": scope + "-id", "api_key": "SENSITIVE_" + scope}
        self.issuer.security.create_api_key.side_effect = issue
        payload = {"attempt": self.attempt, "package_id": self.package["id"], "package_sha256": self.package["sha256"]}
        with ThreadPoolExecutor(2) as pool:
            first = pool.submit(self.service.exchange, self.token, payload)
            self.assertTrue(entered.wait(3))
            second = pool.submit(self.service.exchange, self.token, payload)
            release.set()
            self.assertEqual(first.result(5), second.result(5))
        self.assertEqual(len(calls), 2)

    def test_partial_receipt_is_not_success_complete_is_bound_and_no_secrets(self):
        self.mint()
        self.assertEqual(self.exchange().status_code, 200)
        self.proof(network=0)
        r = self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS})
        self.assertFalse(r.json["verified"])
        self.assertEqual(r.json["received"], ["host"])
        self.proof()
        r = self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS})
        self.assertTrue(r.json["verified"])
        self.assertEqual(self.service.listing()[0]["state"], "complete")
        self.assertEqual(self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS}).status_code, 200)
        self.assertEqual(self.machine("receipt", {"attempt": self.attempt, "agents": {**AGENTS, "host": "00000000-0000-0000-0000-000000000003"}}).status_code, 409)
        self.assertEqual(self.exchange().status_code, 409)
        self.assertEqual(self.admin("POST", f"/api/enrollments/{self.sid}/cancel", {}).status_code, 409)
        for call in self.monitor.search.call_args_list:
            query = json.dumps(call.kwargs)
            self.assertIn("installation_probe", query)
            self.assertIn("cloud_soc_enrollment.key_id", query)
            self.assertIn(self.package["id"], query)
            self.assertFalse(call.kwargs["source"])

    def test_no_hits_timeout_partial_shards_and_untrusted_index_never_succeed(self):
        self.mint()
        self.exchange()
        self.proof(0, 0)
        self.assertFalse(self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS}).json["verified"])
        self.proof()
        self.monitor.indices.get_settings.side_effect = lambda **k: {k["index"]: {"settings": {}}}
        self.assertEqual(self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS}).status_code, 503)
        self.monitor.search.side_effect = None
        for result in ({"timed_out": True}, {"timed_out": False, "_shards": {"failed": 1}}):
            self.monitor.search.return_value = result
            self.assertEqual(self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS}).status_code, 503)

    def test_expired_receipt_aborts_keys_and_abort_is_idempotent(self):
        self.mint()
        self.exchange()
        self.now += SESSION_TTL
        self.assertEqual(self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS}).status_code, 410)
        self.assertEqual(self.service.listing()[0]["state"], "cancelled")
        self.assertEqual(self.machine("abort", {"attempt": self.attempt}).status_code, 200)

    def test_maintenance_revokes_only_abandoned_sessions_and_handles_cleanup_retry(self):
        self.mint()
        self.exchange()
        self.now += SESSION_TTL
        self.issuer.security.invalidate_api_key.side_effect = RuntimeError("SENSITIVE offline")
        self.assertEqual(self.service.sweep(), {"examined": 1, "cleanup_pending": 1})
        self.assertEqual(self.service.listing()[0]["state"], "cleanup_pending")
        self.issuer.security.invalidate_api_key.side_effect = None
        self.assertEqual(self.service.sweep(), {"examined": 1, "cleanup_pending": 0})
        self.assertEqual(self.service.sweep(), {"examined": 0, "cleanup_pending": 0})

    def test_restored_unused_session_cannot_duplicate_existing_remote_keys(self):
        self.mint()
        name = self.service.key_name(self.sid, "host")
        self.issuer.security.get_api_key.return_value = {"api_keys": [{"name": name, "id": "orphan-id", "invalidated": False}]}
        self.assertEqual(self.exchange().status_code, 503)
        self.issuer.security.create_api_key.assert_not_called()
        self.assertEqual(self.service.listing()[0]["state"], "cleanup_pending")

    def test_disabled_feature_and_supported_linux_bundle(self):
        package = self.app.extensions["packages"].create({"name": "linux", "os": "ubuntu", "organization": "school", "network": True})
        self.assertEqual(self.admin("POST", f"/api/packages/{package['id']}/enrollment", {"days": 1}).status_code, 201)
        self.assertEqual(self.admin("POST", f"/api/packages/{self.package['id']}/enrollment", {"days": True}).status_code, 400)
        _, archive = self.app.extensions["packages"].get(self.package["id"], archive=True)
        with zipfile.ZipFile(io.BytesIO(archive)) as z:
            spec = json.loads(z.read("package.json"))
            self.assertEqual(spec["package_id"], self.package["id"])
            self.assertEqual(spec["portal_url"], "https://soc.example.test")
            self.assertIn("enrollment-windows.ps1", z.namelist())
            self.assertIn("enrollment-http.cs", z.namelist())
        self.mint()
        self.settings["ENROLLMENT_ENABLED"] = False
        self.assertEqual(self.exchange().status_code, 503)
        self.assertEqual(self.admin("POST", f"/api/packages/{self.package['id']}/enrollment", {"days": 1}).status_code, 503)
        self.issuer.security.create_api_key.assert_not_called()

    def test_all_platform_scope_combinations_get_only_their_own_roles(self):
        for platform in ('windows', 'ubuntu'):
            for network in (False, True):
                with self.subTest(platform=platform, network=network):
                    self.package = self.app.extensions['packages'].create({'name': platform + str(network), 'os': platform,
                                                                         'organization': 'school', 'network': network})
                    self.issuer.security.create_api_key.reset_mock()
                    self.issuer.security.create_api_key.side_effect = [
                        {'id': secrets.token_hex(16), 'api_key': 'SYNTHETIC_KEY'} for _ in range(2 if network else 1)]
                    self.attempt = secrets.token_urlsafe(32)
                    self.mint()
                    result = self.exchange()
                    self.assertEqual(result.status_code, 200, result.json)
                    scopes = ['host', 'network'] if network else ['host']
                    self.assertEqual([key['scope'] for key in result.json['keys']], scopes)
                    os_index = 'linux' if platform == 'ubuntu' else 'windows'
                    for scope, call in zip(scopes, self.issuer.security.create_api_key.call_args_list):
                        role = call.kwargs['role_descriptors']['cloud_soc_' + scope]
                        expected = ['soc-host-raw-' + os_index + '-*', 'soc-agent-health-*'] if scope == 'host' else ['soc-network-' + os_index + '-*']
                        self.assertEqual(role['indices'][0]['names'], expected)
                        self.assertEqual(role['indices'][0]['privileges'], ['auto_configure', 'create_doc'])

    def failed_then_recovery(self):
        self.mint()
        first = self.exchange()
        self.assertEqual(first.status_code, 200)
        old = self.sid
        probe = first.json['probe']
        self.assertEqual(self.machine('abort', {'attempt': self.attempt}).status_code, 200)
        self.issuer.security.create_api_key.side_effect = [
            {'id': 'replacement-host', 'api_key': 'SYNTHETIC_KEY'}, {'id': 'replacement-network', 'api_key': 'SYNTHETIC_KEY'}]
        self.attempt = secrets.token_urlsafe(32)
        self.mint()
        body = {'attempt': self.attempt, 'package_id': self.package['id'], 'package_sha256': self.package['sha256'], 'recovery_probe': probe}
        return old, body

    def test_recovery_rechecks_remote_revocation_and_retry_binding(self):
        old, body = self.failed_then_recovery()
        before = self.issuer.security.invalidate_api_key.call_count
        result = self.machine('enroll', body)
        self.assertEqual(result.status_code, 200, result.json)
        self.assertEqual(result.json['recovery_probe'], body['recovery_probe'])
        self.assertEqual(self.issuer.security.invalidate_api_key.call_count, before + 2)
        self.assertEqual(self.machine('enroll', body).json, result.json)
        del body['recovery_probe']
        self.assertEqual(self.machine('enroll', body).status_code, 409)
        with self.service.store.connect() as db:
            self.assertEqual(db.execute('SELECT state FROM enrollments WHERE id=?', (old,)).fetchone()[0], 'cancelled')

    def test_recovery_expiry_completed_and_unconfirmed_cleanup_are_rejected(self):
        old, body = self.failed_then_recovery()
        self.now += TOKEN_TTL + 1
        before = self.issuer.security.invalidate_api_key.call_count
        self.assertEqual(self.machine('enroll', body).status_code, 410)
        self.assertEqual(self.issuer.security.invalidate_api_key.call_count, before)
        self.now -= TOKEN_TTL + 1
        with self.service.store.connect() as db:
            db.execute("UPDATE enrollments SET state='complete' WHERE id=?", (old,))
        self.assertEqual(self.machine('enroll', body).status_code, 409)
        with self.service.store.connect() as db:
            db.execute("UPDATE enrollments SET state='cancelled' WHERE id=?", (old,))
        self.issuer.security.invalidate_api_key.return_value = {'error_count': 1}
        self.assertEqual(self.machine('enroll', body).status_code, 503)
        self.assertEqual(self.issuer.security.create_api_key.call_count, 2)

    def test_request_validation_bounds_and_plain_http_are_rejected(self):
        self.mint()
        self.assertEqual(self.machine("enroll", {"attempt": "weak", "package_id": self.package["id"], "package_sha256": self.package["sha256"]}).status_code, 400)
        self.assertEqual(self.machine("receipt", {"attempt": self.attempt, "agents": AGENTS, "extra": True}).status_code, 400)
        r = self.client.post('/api/installer/enroll', base_url='http://soc.example.test', json={},
                             headers={"Authorization": "Bearer " + self.token, "X-Cloud-SOC": "installer"})
        self.assertEqual(r.status_code, 403)
        r = self.client.post('/api/installer/enroll', base_url='https://soc.example.test', data='x' * 9000,
                             content_type='application/json', headers={"Authorization": "Bearer " + self.token, "X-Cloud-SOC": "installer"})
        self.assertEqual(r.status_code, 413)
        self.issuer.security.create_api_key.assert_not_called()

    def test_backup_restore_preserves_encrypted_session_and_old_schema_compatibility(self):
        self.mint()
        self.exchange()
        report = backup(self.root / "portal", self.root / "backup")
        self.assertEqual(report["files"][0]["counts"]["enrollments"], 1)
        self.assertEqual(verify(self.root / "backup"), report)
        self.assertEqual(restore(self.root / "backup", self.root / "restored"), report)
        self.assertNotIn(self.token.encode(), (self.root / "restored/packages.sqlite3").read_bytes())


if __name__ == "__main__":
    unittest.main()
