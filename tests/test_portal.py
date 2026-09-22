"""Central portal tests use local temporary bundles and a fake Elasticsearch issuer."""

import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import Mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))
from werkzeug.security import generate_password_hash
from cloud_soc.portal.app import create_app
from cloud_soc.portal.packages import PackageStore, validate_endpoint

SPEC = {"name": "school-web", "os": "windows", "organization": "school", "network": True, "description": "<script>alert(1)</script>"}
CA = b"SYNTHETIC PUBLIC CA - never used to connect"
AUTH = "Basic " + base64.b64encode(b"admin:synthetic-test-password").decode()
HASH = generate_password_hash("synthetic-test-password", method="pbkdf2:sha256:1000")


class PortalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="cloud-soc-portal-test-")
        self.addCleanup(self.temp.cleanup)
        self.issuer = Mock()
        self.issuer.info.return_value = {"cluster_name": "synthetic"}
        self.issuer.security.create_api_key.side_effect = [
            {"id": "host-id", "api_key": "SENSITIVE_HOST_CANARY", "expiration": 1900000000000},
            {"id": "network-id", "api_key": "SENSITIVE_NETWORK_CANARY", "expiration": 1900000000000},
        ]
        self.settings = {"STATE_DIR": Path(self.temp.name), "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": CA,
                         "PUBLIC_URL": "http://localhost", "ENDPOINT": "https://soc.example.test:9200", "ADMIN_USER": "admin", "ADMIN_HASH": HASH}
        self.app = create_app(self.settings, issuer=self.issuer)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

    def request(self, method, path, data=None, headers=None):
        return self.client.open(path, method=method, json=data if method != "GET" else None,
                                headers={"Authorization": AUTH, "X-Cloud-SOC": "portal", **(headers or {})})

    def package(self, spec=None):
        result = self.request("POST", "/api/packages", spec or SPEC)
        self.assertEqual(result.status_code, 201, result.get_data(as_text=True))
        return result.json

    def test_every_page_and_api_require_authentication(self):
        for path in ("/", "/agents.js", "/api/portal", "/api/packages/a/download", "/api/keys", "/api/agents/health", "/collection-health.html", "/api/operations", "/api/alerts/detail", "/operations.js"):
            response = self.client.get(path)
            self.assertEqual(response.status_code, 401)
            self.assertIn("WWW-Authenticate", response.headers)

    def test_operations_routes_and_no_demo_root(self):
        response = self.request("GET", "/api/operations")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["sections"]["intake"]["state"], "unavailable")
        self.assertEqual(self.request("GET", "/api/operations?bad=1").status_code, 400)
        self.assertEqual(self.request("GET", "/api/alerts/detail?id=fixture").status_code, 503)
        root = self.request("GET", "/")
        self.assertIn(b"operations.js", root.data)
        self.assertNotIn(b"demo-data.js", root.data)
        root.close()

    def test_health_unconfigured_is_not_empty_success(self):
        response = self.request('GET', '/api/agents/health')
        self.assertEqual(response.status_code, 503)
        self.assertNotIn('rows', response.json)
        self.assertEqual(self.request('GET', '/api/agents/health?index=*').status_code, 400)
        self.assertEqual(self.request('GET', '/api/agents/health?cursor=a&cursor=b').status_code, 400)

    def test_host_origin_csrf_and_cross_site_protection(self):
        for headers in ({"Host": "attacker.test"}, {"Host": "localhost:8088"}, {"Origin": "https://attacker.test"}, {"Sec-Fetch-Site": "cross-site"}):
            self.assertIn(self.request("POST", "/api/packages", SPEC, headers).status_code, (400, 403))
        self.assertEqual(self.client.post("/api/packages", json=SPEC, headers={"Authorization": AUTH}).status_code, 403)
        self.assertEqual(self.client.post("/api/packages", data="{}", headers={"Authorization": AUTH, "X-Cloud-SOC": "portal"}).status_code, 403)

    def test_public_metadata_and_security_headers(self):
        response = self.request("GET", "/api/portal")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json["packages"], [])
        self.assertEqual(response.json["elasticsearch"], "connected")
        self.assertEqual(response.headers["Cache-Control"], "no-store")
        self.assertEqual(response.headers["X-Frame-Options"], "DENY")
        self.assertIn("connect-src 'self'", response.headers["Content-Security-Policy"])
        self.assertNotIn("Access-Control-Allow-Origin", response.headers)

    def test_elasticsearch_failure_is_not_reported_as_healthy(self):
        self.issuer.info.side_effect = RuntimeError("SENSITIVE_UPSTREAM_SECRET")
        response = self.request("GET", "/api/portal")
        self.assertEqual(response.json["elasticsearch"], "unavailable")
        self.assertNotIn("SENSITIVE", response.get_data(as_text=True))
        self.package()

    def test_windows_bundle_contains_real_installers_but_no_credentials(self):
        item = self.package()
        download = self.request("GET", f"/api/packages/{item['id']}/download")
        self.assertEqual(hashlib.sha256(download.data).hexdigest(), item["sha256"])
        with zipfile.ZipFile(io.BytesIO(download.data)) as archive:
            self.assertIn("discover-windows.ps1", archive.namelist())
            self.assertIn("download-windows.ps1", archive.namelist())
            self.assertIn("install-network-windows.ps1", archive.namelist())
            self.assertEqual(archive.read("ca.crt"), CA)
            self.assertNotIn(".env", archive.namelist())
            self.assertTrue(all("/" not in name and "\\" not in name for name in archive.namelist()))
            launcher = archive.read("install.ps1").decode()
            self.assertIn("https://soc.example.test:9200", launcher)
            self.assertIn("-InterfaceGuid", launcher)
            self.assertIn("$LASTEXITCODE", launcher)
            for line in archive.read("SHA256SUMS").decode().splitlines():
                digest, name = line.split("  ")
                self.assertEqual(hashlib.sha256(archive.read(name)).hexdigest(), digest)

    def test_linux_log_only_bundle_is_executable_and_has_no_network_installer(self):
        item = self.package({**SPEC, "os": "ubuntu", "network": False})
        self.assertTrue(item["filename"].endswith(".tar.gz"))
        response = self.request("GET", f"/api/packages/{item['id']}/download")
        with tarfile.open(fileobj=io.BytesIO(response.data), mode="r:gz") as archive:
            self.assertEqual(archive.getmember("install.sh").mode, 0o755)
            self.assertNotIn("install-network-ubuntu.sh", archive.getnames())
            self.assertIn("discover-linux.sh", archive.getnames())
            self.assertNotIn(b"\r", archive.extractfile("install.sh").read())

    def test_invalid_spec_duplicate_and_delete(self):
        for change in ({"name": "../bad"}, {"name": "a\n"}, {"organization": "${SECRET}"}, {"os": "other"}, {"os": []}, {"os": {}}, {"network": "false"}, {"endpoint": "https://attacker.test"}, {"description": "x" * 501}):
            self.assertEqual(self.request("POST", "/api/packages", {**SPEC, **change}).status_code, 400)
        item = self.package()
        self.assertEqual(self.request("POST", "/api/packages", SPEC).status_code, 409)
        self.assertEqual(self.request("DELETE", f"/api/packages/{item['id']}", {}).status_code, 200)
        self.assertEqual(self.request("GET", f"/api/packages/{item['id']}/download").status_code, 404)
        self.issuer.security.invalidate_api_key.assert_not_called()

    def test_api_keys_have_separate_scopes_and_never_enter_bundle_or_database(self):
        item = self.package()
        response = self.request("POST", f"/api/packages/{item['id']}/keys", {"days": 30})
        self.assertEqual(response.status_code, 200, response.json)
        self.assertEqual(response.json["keys"][0]["key"], "host-id:SENSITIVE_HOST_CANARY")
        calls = self.issuer.security.create_api_key.call_args_list
        self.assertEqual(calls[0].kwargs["role_descriptors"]["cloud_soc_host"]["indices"][0]["names"], ["soc-host-raw-*", "soc-agent-health-*"])
        self.assertEqual(calls[1].kwargs["role_descriptors"]["cloud_soc_network"]["indices"][0]["names"], ["soc-network-*"])
        self.assertEqual(calls[0].kwargs["expiration"], "30d")
        self.assertNotIn(b"SENSITIVE", (Path(self.temp.name) / "packages.sqlite3").read_bytes())
        history = self.request("GET", "/api/keys").json
        self.assertEqual(len(history["keys"]), 2)
        self.assertNotIn("api_key", json.dumps(history))
        self.assertNotIn("SENSITIVE", json.dumps(history))

    def test_partial_key_issue_revokes_the_first_key_and_redacts_error(self):
        item = self.package()
        self.issuer.security.create_api_key.side_effect = [{"id": "first", "api_key": "SECRET"}, RuntimeError("SECRET")]
        response = self.request("POST", f"/api/packages/{item['id']}/keys", {"days": 7})
        self.assertEqual(response.status_code, 503)
        self.assertNotIn("SECRET", response.get_data(as_text=True))
        self.issuer.security.invalidate_api_key.assert_called_once_with(ids=["first"])

    def test_key_lifetime_validation_and_revocation_scope(self):
        item = self.package()
        for value in (True, -1, 3650, "30"):
            self.assertEqual(self.request("POST", f"/api/packages/{item['id']}/keys", {"days": value}).status_code, 400)
        self.assertEqual(self.request("POST", "/api/keys/arbitrary-key/revoke", {}).status_code, 404)
        self.request("POST", f"/api/packages/{item['id']}/keys", {"days": 1})
        self.issuer.security.invalidate_api_key.return_value = {"error_count": 0}
        self.assertEqual(self.request("POST", "/api/keys/host-id/revoke", {}).status_code, 200)

    def test_repo_secrets_and_arbitrary_paths_are_not_served(self):
        for path in ("/.env", "/state/portal/packages.sqlite3", "/src/cloud_soc/main.py", "/../.env", "/api/packages/not-a-uuid/download"):
            self.assertEqual(self.request("GET", path).status_code, 404)
        with self.request("GET", "/") as response:
            self.assertEqual(response.status_code, 200)

    def test_generated_bundle_launchers_dry_run_without_installation(self):
        bash = os.environ.get("BASH_EXE") or ("C:/Program Files/Git/bin/bash.exe" if os.name == "nt" else shutil.which("bash"))
        pwsh = shutil.which("pwsh")
        for platform, shell in (("ubuntu", bash), ("windows", pwsh)):
            if not shell or not Path(shell).exists():
                self.skipTest(f"Shell for {platform} is not installed")
            for network in (False, True):
                with self.subTest(platform=platform, network=network):
                    item = self.package({**SPEC, "name": f"dry-{platform}-{network}", "os": platform, "network": network})
                    _, data = self.app.extensions["packages"].get(item["id"], archive=True)
                    folder = Path(self.temp.name) / item["id"]
                    folder.mkdir()
                    if platform == "windows":
                        with zipfile.ZipFile(io.BytesIO(data)) as archive:
                            archive.extractall(folder)
                        args = [shell, "-NoProfile", "-NonInteractive", "-File", str(folder / "install.ps1"), "-DryRun"]
                        nic = ["-InterfaceGuid", "12345678-1234-1234-1234-123456789abc"]
                    else:
                        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as archive:
                            # Members come from the validated, local builder, not uploads.
                            for member in archive.getmembers():
                                self.assertEqual(Path(member.name).name, member.name)
                                (folder / member.name).write_bytes(archive.extractfile(member).read())
                        args = [shell, str(folder / "install.sh"), "--dry-run"]
                        nic = ["--interface", "eth0"]
                    if network:
                        missing = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=20)
                        self.assertNotEqual(missing.returncode, 0)
                        self.assertNotIn("soc-host-raw-", missing.stdout)
                        args += nic
                    result = subprocess.run(args, capture_output=True, text=True, encoding="utf-8", timeout=20)
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertIn("soc-host-raw-", result.stdout)
                    self.assertEqual("soc-network-" in result.stdout, network)
                    self.assertIn("DRY RUN", result.stderr)

    def test_persistence_and_size_limit(self):
        item = self.package()
        again = PackageStore(Path(self.temp.name), ROOT / "deploy/agents", CA, self.settings["ENDPOINT"])
        self.assertEqual(again.get(item["id"])["sha256"], item["sha256"])
        self.assertEqual(self.client.post("/api/packages", data="x" * 9000, content_type="application/json", headers={"Authorization": AUTH, "X-Cloud-SOC": "portal"}).status_code, 413)


class DeploymentTests(unittest.TestCase):
    def test_public_endpoint_validation(self):
        for bad in ("http://host", "https://host/path", "https://a@b", "https://host:0", "https://host:99999", "https://${SECRET}", "https://host\n"):
            with self.assertRaises(ValueError):
                validate_endpoint(bad)
        self.assertEqual(validate_endpoint("https://soc.example.test:9200/"), "https://soc.example.test:9200")

    def test_prepare_hostname_and_password_hash(self):
        spec = importlib.util.spec_from_file_location("server_prepare", ROOT / "deploy/server/prepare.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        self.assertEqual(module.validate_host("192.0.2.10"), "IP:192.0.2.10")
        self.assertEqual(module.validate_host("soc.example.test"), "DNS:soc.example.test")
        for bad in ("host\n", "host/path", "https://host", "1.2.3.999", "bad..host", "-bad.example"):
            with self.assertRaises(ValueError): module.validate_host(bad)
        from werkzeug.security import check_password_hash
        self.assertTrue(check_password_hash(module.password_hash("long-synthetic-password"), "long-synthetic-password"))

    def test_compose_isolated_security_and_secrets(self):
        import yaml
        compose = yaml.safe_load((ROOT / "deploy/server/compose.yaml").read_text())
        services = compose["services"]
        self.assertEqual(services["elasticsearch"]["environment"]["xpack.security.http.ssl.enabled"], "true")
        self.assertNotIn("ports", services["portal"])
        self.assertNotIn("ports", services["kibana"])
        self.assertNotIn("elastic_password", services["portal"]["secrets"])
        self.assertIn("127.0.0.1", services["elasticsearch"]["ports"][0])
        self.assertEqual(services["bootstrap"]["restart"], "no")
        self.assertEqual(compose["name"], "cloud-soc-central")

    def test_elastic_password_owner_matches_bootstrap_and_is_not_exposed_to_portal(self):
        import yaml

        services = yaml.safe_load((ROOT / "deploy/server/compose.yaml").read_text())["services"]
        self.assertIn("elastic_password", services["elasticsearch"]["secrets"])
        self.assertIn("elastic_password", services["bootstrap"]["secrets"])
        self.assertNotIn("elastic_password", services["portal"]["secrets"])
        self.assertEqual(services["elasticsearch"].get("user", "1000:0").split(":")[0], "1000")
        dockerfile = (ROOT / "deploy/server/Dockerfile").read_text()
        image_user = [line.split()[1] for line in dockerfile.splitlines() if line.startswith("USER ")][-1]
        self.assertEqual(services["bootstrap"].get("user", image_user).split(":")[0], "1000")


if __name__ == "__main__":
    unittest.main()
