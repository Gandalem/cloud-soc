"""Loopback-only synthetic UI fixture. Never connects to Elasticsearch."""
import base64
from pathlib import Path
import sys
import tempfile
from unittest.mock import Mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.portal.app import create_app
from werkzeug.security import generate_password_hash


def main():
    port = 8779
    root = Path(__file__).resolve().parents[1]
    with tempfile.TemporaryDirectory(prefix="soc-key-ui-") as directory:
        issuer = Mock()
        app = create_app({"STATE_DIR": Path(directory), "AGENT_SOURCE": root / "deploy/agents",
                          "CA_BYTES": b"SYNTHETIC PUBLIC CA", "PUBLIC_URL": f"http://127.0.0.1:{port}",
                          "ENDPOINT": "https://soc.example.test:9200", "ADMIN_USER": "fixture",
                          "ADMIN_HASH": generate_password_hash("synthetic-only")}, issuer=issuer)
        store = app.extensions["packages"]
        package = store.create({"name": "vmware-lab", "os": "windows", "organization": "school",
                                "network": True, "description": "Synthetic UI fixture"})
        store.record_keys(package["id"], [{"id": "synthetic-host", "scope": "host", "expiration": 1900000000000},
                                          {"id": "synthetic-network", "scope": "network", "expiration": 1900000000000}],
                          target_label="VMware lab 01")
        store.record_keys(package["id"], [{"id": "synthetic-legacy"}, {"id": "synthetic-revoked", "scope": "host"}])
        store.mark_revoked("synthetic-revoked")

        def revoke(*, ids, owner=False):
            if owner is not True:
                raise PermissionError("Synthetic owner-scoping failure")
            if ids == ["synthetic-network"]:
                raise RuntimeError("Synthetic connection failure")
            return {"error_count": 0, "invalidated_api_keys": ids, "previously_invalidated_api_keys": []}

        issuer.security.invalidate_api_key.side_effect = revoke
        issuer.security.get_api_key.side_effect = lambda *, id, owner: {"api_keys": [{
            "id": id, "metadata": {"package_id": package["id"]}, "expiration": 1900000000000,
            "invalidated": id == "synthetic-revoked", "role_descriptors": {"cloud_soc_host": {}}}]}
        # Only this disposable loopback fixture injects synthetic authentication.
        original = app.wsgi_app

        def authenticated(environ, start_response):
            environ["HTTP_AUTHORIZATION"] = "Basic " + base64.b64encode(b"fixture:synthetic-only").decode()
            return original(environ, start_response)

        app.wsgi_app = authenticated
        app.run(host="127.0.0.1", port=port, debug=False, use_reloader=False)


if __name__ == "__main__":
    main()
