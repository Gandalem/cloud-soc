"""Key history migration and lifecycle using isolated SQLite and a fake issuer."""
import json
import unittest
from unittest.mock import patch

import test_portal as fixtures
from cloud_soc.portal.app import create_app
from cloud_soc.portal.packages import PackageStore
from cloud_soc.portal import backup


class KeyManagementTests(unittest.TestCase):
    setUp = fixtures.PortalTests.setUp
    request = fixtures.PortalTests.request
    package = fixtures.PortalTests.package

    def issue(self):
        item = self.package()
        response = self.request("POST", f"/api/packages/{item['id']}/keys", {"days": 30, "target_label": "VMware lab 01"})
        self.assertEqual(response.status_code, 200)
        return item

    def history(self):
        return {key["id"]: key for key in self.request("GET", "/api/keys").json["keys"]}

    def confirm(self, identifier="host-id", previous=False):
        self.issuer.security.invalidate_api_key.return_value = {
            "error_count": 0, "invalidated_api_keys": [] if previous else [identifier],
            "previously_invalidated_api_keys": [identifier] if previous else [],
        }

    def test_identification_survives_package_deletion_and_restart(self):
        item = self.issue()
        before = self.history()
        self.assertEqual(before["host-id"]["scope"], "host")
        self.assertEqual(before["network-id"]["scope"], "network")
        self.assertEqual(before["host-id"]["target_label"], "VMware lab 01")
        self.assertEqual(before["host-id"]["package_name"], fixtures.SPEC["name"])
        self.assertEqual(before["host-id"]["organization"], "school")
        self.assertEqual(before["host-id"]["package_os"], "windows")
        self.assertEqual(before["host-id"]["status"], "unverified")
        self.assertEqual(self.request("DELETE", f"/api/packages/{item['id']}", {}).status_code, 200)
        self.issuer.security.invalidate_api_key.assert_not_called()
        self.client = create_app(self.settings, issuer=self.issuer).test_client()
        self.assertEqual(self.history(), before)
        self.confirm()
        self.assertEqual(self.request("POST", "/api/keys/host-id/revoke", {}).status_code, 200)
        self.client = create_app(self.settings, issuer=self.issuer).test_client()
        self.assertEqual(self.history()["host-id"]["status"], "revoked")
        self.assertEqual(self.request("POST", "/api/keys/host-id/revoke", {}).status_code, 200)
        self.issuer.security.invalidate_api_key.assert_called_once_with(ids=["host-id"], owner=True)

    def test_minimum_permission_issuer_requires_owner_scoped_revocation(self):
        self.issue()

        def invalidate(*, ids, owner=False):
            if owner is not True:
                raise PermissionError("manage_own_api_key requires owner=true")
            return {"error_count": 0, "invalidated_api_keys": ids, "previously_invalidated_api_keys": []}

        self.issuer.security.invalidate_api_key.side_effect = invalidate
        result = self.request("POST", "/api/keys/host-id/revoke", {})
        self.assertEqual(result.status_code, 200)
        self.assertTrue(result.json["revoked"])
        self.assertEqual(self.history()["host-id"]["status"], "revoked")
        self.issuer.security.invalidate_api_key.assert_called_once_with(ids=["host-id"], owner=True)

    def test_revocation_requires_exact_success_and_preserves_failed_history(self):
        self.issue()
        for result in ({}, {"error_count": 0}, {"error_count": 0, "invalidated_api_keys": ["other"]},
                       {"error_count": 1, "invalidated_api_keys": ["host-id"]},
                       {"error_count": 0, "invalidated_api_keys": "prefix-host-id-suffix", "previously_invalidated_api_keys": ""}):
            self.issuer.security.invalidate_api_key.return_value = result
            self.assertEqual(self.request("POST", "/api/keys/host-id/revoke", {}).status_code, 503)
            self.assertIsNone(self.history()["host-id"]["revoked_at"])
        self.confirm(previous=True)
        self.assertEqual(self.request("POST", "/api/keys/host-id/revoke", {}).status_code, 200)
        self.assertEqual(self.history()["host-id"]["status"], "revoked")

    def test_storage_failure_after_remote_revoke_can_be_retried(self):
        self.issue()
        self.confirm()
        store = self.app.extensions["packages"]
        with patch.object(store, "mark_revoked", side_effect=RuntimeError("SECRET")):
            result = self.request("POST", "/api/keys/host-id/revoke", {})
            self.assertEqual(result.status_code, 503)
            self.assertNotIn("SECRET", result.get_data(as_text=True))
        self.confirm(previous=True)
        self.assertEqual(self.request("POST", "/api/keys/host-id/revoke", {}).status_code, 200)

    def legacy(self):
        item = self.issue()
        store = self.app.extensions["packages"]
        with store.connect() as db:
            db.execute("ALTER TABLE issued_keys RENAME TO old_keys")
            db.execute("CREATE TABLE issued_keys (id TEXT PRIMARY KEY, package_id TEXT NOT NULL, created_at TEXT NOT NULL)")
            db.execute("INSERT INTO issued_keys SELECT id, package_id, created_at FROM old_keys")
            db.execute("DROP TABLE old_keys")
        return item

    def server_key(self, package_id, **changes):
        return {"id": "host-id", "metadata": {"package_id": package_id}, "role_descriptors": {"cloud_soc_host": {}},
                "expiration": 1900000000000, "invalidated": False, **changes}

    def test_legacy_migration_preserves_unknowns_and_exact_server_lookup_recovers_scope(self):
        item = self.legacy()
        self.client = create_app(self.settings, issuer=self.issuer).test_client()
        keys = self.history()
        self.assertIsNone(keys["host-id"]["scope"])
        self.assertIsNone(keys["host-id"]["expiration"])
        self.assertEqual(keys["host-id"]["package_name"], fixtures.SPEC["name"])
        self.issuer.security.get_api_key.return_value = {"api_keys": [self.server_key(item["id"])]}
        response = self.request("POST", "/api/keys/host-id/check", {})
        self.assertEqual(response.status_code, 200)
        self.issuer.security.get_api_key.assert_called_once_with(id="host-id", owner=True)
        self.assertEqual(response.json["key"]["scope"], "host")
        self.assertEqual(response.json["key"]["status"], "active")
        self.assertIsNone(self.history()["network-id"]["scope"])

    def test_legacy_missing_package_and_mismatched_metadata_are_not_guessed(self):
        self.legacy()
        store = self.app.extensions["packages"]
        with store.connect() as db:
            db.execute("DELETE FROM packages")
        self.client = create_app(self.settings, issuer=self.issuer).test_client()
        self.issuer.security.get_api_key.return_value = {"api_keys": [self.server_key("not-this-package")]}
        response = self.request("POST", "/api/keys/host-id/check", {})
        self.assertIsNone(response.json["key"]["scope"])
        self.assertIsNone(response.json["key"]["package_name"])

    def test_check_expired_revoked_missing_and_failure_are_distinct(self):
        item = self.issue()
        self.issuer.security.get_api_key.return_value = {"api_keys": []}
        self.assertEqual(self.request("POST", "/api/keys/host-id/check", {}).json["key"]["status"], "missing")
        self.issuer.security.get_api_key.return_value = {"api_keys": [self.server_key(item["id"], expiration=1)]}
        self.assertEqual(self.request("POST", "/api/keys/host-id/check", {}).json["key"]["status"], "expired")
        self.issuer.security.get_api_key.return_value = {"api_keys": [self.server_key(item["id"], invalidated=True)]}
        self.assertEqual(self.request("POST", "/api/keys/host-id/check", {}).json["key"]["status"], "revoked")
        self.issuer.security.get_api_key.return_value = {"api_keys": [self.server_key(item["id"])]}
        self.assertEqual(self.request("POST", "/api/keys/host-id/check", {}).json["key"]["status"], "revoked")
        self.issuer.security.get_api_key.side_effect = RuntimeError("SECRET upstream")
        result = self.request("POST", "/api/keys/network-id/check", {})
        self.assertEqual(result.status_code, 503)
        self.assertNotIn("SECRET", result.get_data(as_text=True))
        self.assertEqual(self.history()["network-id"]["status"], "unavailable")

    def test_invalid_server_response_never_marks_active(self):
        item = self.issue()
        for info in (self.server_key(item["id"], id="other"), self.server_key(item["id"], expiration=True),
                     self.server_key(item["id"], invalidated="false"), self.server_key(item["id"], expiration=10**30)):
            self.issuer.security.get_api_key.return_value = {"api_keys": [info]}
            self.assertEqual(self.request("POST", "/api/keys/host-id/check", {}).status_code, 503)
            self.assertEqual(self.history()["host-id"]["status"], "unavailable")

    def test_alias_validation_auth_csrf_and_unknown_key(self):
        self.issue()
        for value in (None, [], "x" * 101, "line\nbreak", "bad\x00"):
            self.assertEqual(self.request("PATCH", "/api/keys/host-id", {"target_label": value}).status_code, 400)
        result = self.request("PATCH", "/api/keys/host-id", {"target_label": "<img src=x>"})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(self.history()["host-id"]["target_label"], "<img src=x>")
        for suffix, method, body in (("", "PATCH", {"target_label": "lab"}), ("/check", "POST", {}), ("/revoke", "POST", {})):
            self.assertEqual(self.request(method, "/api/keys/not-issued" + suffix, body).status_code, 404)
            self.assertEqual(self.client.open("/api/keys/host-id" + suffix, method=method, json=body).status_code, 401)
            self.assertEqual(self.client.open("/api/keys/host-id" + suffix, method=method, json=body, headers={"Authorization": fixtures.AUTH}).status_code, 403)
        self.issuer.security.get_api_key.assert_not_called()
        self.issuer.security.invalidate_api_key.assert_not_called()
        self.assertNotIn("SENSITIVE", json.dumps(self.history()))

    def test_new_alias_rejected_before_issuing_and_request_keeps_backward_compatibility(self):
        item = self.package()
        self.assertEqual(self.request("POST", f"/api/packages/{item['id']}/keys", {"days": 30, "target_label": []}).status_code, 400)
        self.issuer.security.create_api_key.assert_not_called()
        self.assertEqual(self.request("POST", f"/api/packages/{item['id']}/keys", {"days": 30}).status_code, 200)

    def test_old_and_new_history_backup_restore_and_migrate(self):
        self.legacy()
        root = self.settings["STATE_DIR"]
        # Each destination is new and isolated; no installed state is involved.
        # The backup tool correctly forbids nesting; use separate sibling temp dirs.
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory(prefix="key-history-backup-") as temp:
            old = Path(temp) / "old"
            restored = Path(temp) / "restored"
            backup.backup(root, old)
            backup.restore(old, restored)
            store = PackageStore(restored, fixtures.ROOT / "deploy/agents", fixtures.CA, self.settings["ENDPOINT"])
            self.assertIsNone(store.key("host-id")["scope"])
            store.label_key("host-id", "restored lab")
            store.mark_revoked("host-id")
            newer = Path(temp) / "new"
            final = Path(temp) / "final"
            backup.backup(restored, newer)
            backup.restore(newer, final)
            result = PackageStore(final, fixtures.ROOT / "deploy/agents", fixtures.CA, self.settings["ENDPOINT"])
            self.assertEqual(result.key("host-id")["status"], "revoked")
            self.assertEqual(result.key("host-id")["target_label"], "restored lab")


if __name__ == "__main__":
    unittest.main()
