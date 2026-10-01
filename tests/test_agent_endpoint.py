"""Independent dashboard/receiver settings; no live installation or credentials."""

import base64
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
SPEC = importlib.util.spec_from_file_location("agent_endpoint", ROOT / "deploy/server/configure-agent-endpoint.py")
endpoint = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(endpoint)


class ReceiverTests(unittest.TestCase):
    def test_only_https_origins_with_valid_dns_ipv4_port(self):
        for value in ("https://192.168.32.60:9200", "https://receiver.example.test/", "https://a"):
            self.assertEqual(endpoint.validate_receiver(value), value.rstrip("/"))
        for value in ("http://host", "https://user:secret@host", "https://host/path", "https://host?q=1",
                      "https://host#f", "https://host:0", "https://host:65536", "https://host\n",
                      "https://[::1]", "https://0.0.0.0:9200", "https://224.0.0.1", "https://999.0.0.1",
                      "https://a..test", "https://bad-.test", "https://" + "a" * 64 + ".test"):
            with self.subTest(value=value), self.assertRaises(endpoint.EndpointError):
                endpoint.validate_receiver(value)

    def test_update_preserves_public_address_and_other_bytes(self):
        original = b"# keep me\r\nSOC_PUBLIC_HOST=dashboard.example.test\r\nSOC_BIND_IP=10.0.0.5\r\nSOC_STATE_DIR=/state\r\nOTHER=keep\r\n"
        updated = endpoint.updated_environment(original, "https://10.0.0.5:9200")
        self.assertEqual(updated, original + b"SOC_AGENT_ENDPOINT=https://10.0.0.5:9200\n")
        self.assertEqual(endpoint.updated_environment(updated, "https://10.0.0.5:9200"), updated)
        changed = endpoint.updated_environment(updated, "https://receiver.example.test:9200")
        self.assertEqual(changed, original + b"SOC_AGENT_ENDPOINT=https://receiver.example.test:9200\n")

    def test_ambiguous_or_incomplete_state_is_rejected(self):
        for value in (b"SOC_PUBLIC_HOST=a\n", b"export SOC_PUBLIC_HOST=a\n", b"SOC_PUBLIC_HOST=a\nSOC_PUBLIC_HOST=b\n", b"\xff", b"BAD=\0"):
            with self.subTest(value=value), self.assertRaises(endpoint.EndpointError):
                endpoint.updated_environment(value, "https://receiver:9200")

    def test_probe_no_credentials_redirects_or_proxy(self):
        response = Mock(status=401)
        response.read.return_value = b'{"error":{"type":"security_exception"}}'
        connection = Mock()
        connection.getresponse.return_value = response
        with patch.object(endpoint.ssl, "create_default_context") as context, \
                patch.object(endpoint.http.client, "HTTPSConnection", return_value=connection) as connect:
            endpoint.probe_receiver("https://receiver.example.test:9200", Path("ca.crt"))
        context.assert_called_once_with(cafile="ca.crt")
        connect.assert_called_once_with("receiver.example.test", 9200, timeout=10, context=context.return_value)
        connection.request.assert_called_once_with("GET", "/", headers={"Accept": "application/json"})
        response.read.assert_called_once_with(16385)
        connection.close.assert_called_once()

    def test_not_an_elasticsearch_auth_response_never_passes(self):
        for status, data in ((200, b'{}'), (301, b''), (401, b'[]'), (401, b'bad'),
                             (401, b'{"error":"SECRET_CANARY"}'), (401, b'x' * 16385)):
            response = Mock(status=status)
            response.read.return_value = data
            connection = Mock()
            connection.getresponse.return_value = response
            with self.subTest(status=status, size=len(data)), patch.object(endpoint.ssl, "create_default_context"), \
                    patch.object(endpoint.http.client, "HTTPSConnection", return_value=connection):
                with self.assertRaises(endpoint.EndpointError) as caught:
                    endpoint.probe_receiver("https://receiver:9200", Path("ca.crt"))
                self.assertNotIn("SECRET_CANARY", str(caught.exception))
                connection.close.assert_called_once()


@unittest.skipUnless(os.name == "posix" and os.geteuid() == 0, "actual private-state filesystem tests require isolated Linux root")
class ReceiverFilesystemTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="soc-endpoint-test-")
        self.addCleanup(self.temp.cleanup)
        self.state = Path(self.temp.name)
        self.state.chmod(0o700)
        self.env = self.state / "compose.env"
        self.original = b"SOC_PUBLIC_HOST=dashboard.example.test\nSOC_BIND_IP=10.0.0.5\nSOC_STATE_DIR=/state\n"
        self.env.write_bytes(self.original)
        self.env.chmod(0o600)
        (self.state / "tls").mkdir(mode=0o700)
        (self.state / "tls/ca.crt").write_bytes(b"SYNTHETIC_CA")
        self.probe = patch.object(endpoint, "probe_receiver")
        self.mock_probe = self.probe.start()
        self.addCleanup(self.probe.stop)

    def test_check_writes_nothing_apply_preserves_backup_and_mode(self):
        names = set(self.state.iterdir())
        endpoint.configure(self.state, "https://10.0.0.5:9200")
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertEqual(set(self.state.iterdir()), names)
        message = endpoint.configure(self.state, "https://10.0.0.5:9200", apply=True)
        self.assertIn("NEW bundle", message)
        self.assertEqual(self.env.read_bytes(), self.original + b"SOC_AGENT_ENDPOINT=https://10.0.0.5:9200\n")
        backups = list(self.state.glob("compose.env.before-agent-*"))
        self.assertEqual(len(backups), 1)
        self.assertEqual(backups[0].read_bytes(), self.original)
        for file in (self.env, backups[0]):
            self.assertEqual(file.stat().st_mode & 0o777, 0o600)
        endpoint.configure(self.state, "https://10.0.0.5:9200", apply=True)
        self.assertEqual(list(self.state.glob("compose.env.before-agent-*")), backups)

    def test_probe_failure_never_writes(self):
        self.mock_probe.side_effect = endpoint.ssl.SSLError("PRIVATE_CANARY")
        with self.assertRaises(endpoint.ssl.SSLError):
            endpoint.configure(self.state, "https://10.0.0.5:9200", apply=True)
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertFalse(list(self.state.glob("compose.env.before-agent-*")))

    def test_concurrent_edit_is_preserved(self):
        changed = self.original + b"OTHER=concurrent\n"
        self.mock_probe.side_effect = lambda *_args: self.env.write_bytes(changed)
        with self.assertRaisesRegex(endpoint.EndpointError, "changed during"):
            endpoint.configure(self.state, "https://10.0.0.5:9200", apply=True)
        self.assertEqual(self.env.read_bytes(), changed)

    def test_atomic_replace_failure_preserves_original_and_verified_backup(self):
        with patch.object(endpoint.os, "replace", side_effect=OSError("synthetic failure")):
            with self.assertRaises(OSError):
                endpoint.configure(self.state, "https://10.0.0.5:9200", apply=True)
        self.assertEqual(self.env.read_bytes(), self.original)
        self.assertEqual(list(self.state.glob("compose.env.before-agent-*"))[0].read_bytes(), self.original)
        self.assertFalse(list(self.state.glob(".compose.env.agent-*")))

    def test_link_or_weak_permissions_rejected_without_probe(self):
        self.env.chmod(0o644)
        with self.assertRaisesRegex(endpoint.EndpointError, "permissions"):
            endpoint.configure(self.state, "https://10.0.0.5:9200", apply=True)
        self.mock_probe.assert_not_called()
        self.env.chmod(0o600)
        alias = self.state / "alias"
        alias.symlink_to(self.env)
        self.env.rename(self.state / "saved")
        self.env.symlink_to(self.state / "saved")
        with self.assertRaisesRegex(endpoint.EndpointError, "Linked"):
            endpoint.configure(self.state, "https://10.0.0.5:9200", apply=True)
        self.mock_probe.assert_not_called()


class PortalReceiverTests(unittest.TestCase):
    def test_environment_explicit_receiver_and_legacy_fallback(self):
        from cloud_soc.portal.app import settings_from_environment

        with tempfile.TemporaryDirectory() as folder:
            ca = Path(folder) / "ca.crt"
            ca.write_bytes(b"SYNTHETIC_CA")
            secret = Path(folder) / "secret"
            secret.write_text("SYNTHETIC_SECRET", encoding="ascii")
            env = {"SOC_CA_FILE": str(ca), "SOC_ADMIN_HASH_FILE": str(secret),
                   "SOC_ISSUER_PASSWORD_FILE": str(secret), "SOC_PUBLIC_URL": "https://dashboard.example.test",
                   "SOC_ELASTIC_ENDPOINT": "https://dashboard.example.test:9200",
                   "SOC_INTERNAL_ES_URL": "https://elasticsearch:9200"}
            with patch.dict(os.environ, env, clear=True), patch("cloud_soc.portal.app.ssl.create_default_context"):
                for override, expected in ((None, env["SOC_ELASTIC_ENDPOINT"]), ("", env["SOC_ELASTIC_ENDPOINT"]),
                                           ("https://10.0.0.5:9200", "https://10.0.0.5:9200")):
                    if override is None:
                        os.environ.pop("SOC_AGENT_ENDPOINT", None)
                    else:
                        os.environ["SOC_AGENT_ENDPOINT"] = override
                    settings = settings_from_environment()
                    self.assertEqual(settings["PUBLIC_URL"], env["SOC_PUBLIC_URL"])
                    self.assertEqual(settings["ENDPOINT"], expected)
                    self.assertEqual(settings["ES_URL"], env["SOC_INTERNAL_ES_URL"])
                os.environ["SOC_AGENT_ENDPOINT"] = "http://10.0.0.5:9200"
                with self.assertRaises(ValueError):
                    settings_from_environment()

    def test_restart_changes_new_bundles_not_stored_zip_or_host_auth(self):
        from cloud_soc.portal.app import create_app
        from werkzeug.security import generate_password_hash

        with tempfile.TemporaryDirectory() as folder:
            settings = {"STATE_DIR": Path(folder), "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": b"SYNTHETIC_CA",
                        "PUBLIC_URL": "https://dashboard.example.test", "ENDPOINT": "https://old.example.test:9200",
                        "ADMIN_USER": "admin", "ADMIN_HASH": generate_password_hash("synthetic", method="pbkdf2:sha256:1000")}
            headers = {"Authorization": "Basic " + base64.b64encode(b"admin:synthetic").decode(), "X-Cloud-SOC": "portal"}
            origin = settings["PUBLIC_URL"]
            client = create_app(settings, issuer=Mock()).test_client()
            spec = {"name": "old", "os": "windows", "organization": "school", "network": True}
            old = client.post("/api/packages", base_url=origin, json=spec, headers=headers).json
            before = client.get(f"/api/packages/{old['id']}/download", base_url=origin, headers=headers).data
            settings = {**settings, "ENDPOINT": "https://10.0.0.5:9200"}
            client = create_app(settings, issuer=Mock()).test_client()
            after = client.get(f"/api/packages/{old['id']}/download", base_url=origin, headers=headers).data
            self.assertEqual(after, before)
            self.assertEqual(hashlib.sha256(after).hexdigest(), old["sha256"])
            self.assertEqual(client.get("/api/portal", base_url=origin, headers=headers).json["endpoint"], settings["ENDPOINT"])
            for os_name in ("windows", "ubuntu"):
                new = client.post("/api/packages", base_url=origin, json={**spec, "name": "new", "os": os_name}, headers=headers).json
                self.assertEqual(new["endpoint"], settings["ENDPOINT"])
            self.assertEqual(client.get("/api/portal", base_url="https://10.0.0.5", headers=headers).status_code, 400)


if __name__ == "__main__":
    unittest.main()
