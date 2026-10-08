from copy import deepcopy
import json
from pathlib import Path
from unittest.mock import Mock

import pytest

from cloud_soc.portal.app import create_app
from cloud_soc.portal.auth import COOKIE
from test_log_query import FIXTURE, client
from test_source_access import HASH, POLICY


@pytest.fixture
def session_portal(tmp_path):
    users = {"admin": {"role": "admin", "password_hash": HASH}}
    users.update({row["username"]: {"role": "analyst" if row["role"] == "investigator" else "viewer",
                                  "password_hash": HASH} for row in POLICY["users"]})
    filename = tmp_path / "users.json"
    filename.write_text(json.dumps(users), encoding="utf-8")
    filename.chmod(0o600)
    settings = {"STATE_DIR": tmp_path, "AGENT_SOURCE": Path(__file__).resolve().parents[1] / "deploy/agents",
                "CA_BYTES": b"SYNTHETIC CA", "PUBLIC_URL": "http://localhost",
                "ENDPOINT": "https://example.test:9200", "ADMIN_USER": "admin", "ADMIN_HASH": HASH,
                "USERS_FILE": str(filename), "LOG_ACCESS_POLICY": deepcopy(POLICY)}
    monitor = client()
    app = create_app(settings, issuer=Mock(), monitor=monitor)
    return app, monitor, settings, users


def login(app, username):
    http = app.test_client()
    response = http.post("/api/auth/login", json={"username": username, "password": "synthetic-password"},
                         headers={"X-Cloud-SOC": "portal"})
    assert response.status_code == 200
    identity = http.get("/api/auth/me").json
    return http, {"X-Cloud-SOC": "portal", "X-CSRF-Token": identity["csrf"]}


def test_session_preserves_organization_scope_and_blocks_global_history(session_portal):
    app, monitor, _, _ = session_portal
    http, headers = login(app, "investigate")
    assert http.get("/api/logs").status_code == 200
    assert {"terms": {"organization.id": ["synthetic"]}} in monitor.search.call_args.kwargs["body"]["query"]["bool"]["filter"]
    for path in ("/api/detection/history", "/api/reprocessing/history", "/api/operations", "/api/cases", "/api/keys"):
        assert http.get(path, headers={"X-Role": "admin", "X-Organization": "foreign"}).status_code == 403
    foreign = deepcopy(FIXTURE)
    foreign["_source"]["organization"]["id"] = "foreign"
    monitor.get.return_value = foreign
    reference = {"index": FIXTURE["_index"], "id": FIXTURE["_id"], "purpose": "investigation"}
    assert http.post("/api/logs/source", json=reference, headers=headers).status_code == 404


def test_session_source_requires_csrf_masks_and_audits_before_release(session_portal):
    app, monitor, _, _ = session_portal
    http, headers = login(app, "investigate")
    reference = {"index": FIXTURE["_index"], "id": FIXTURE["_id"], "purpose": "investigation"}
    assert http.post("/api/logs/source", json=reference, headers={"X-Cloud-SOC": "portal"}).status_code == 403
    source = deepcopy(FIXTURE)
    source["_source"]["message"] = "PRIVATE_CANARY"
    monitor.get.return_value = source
    response = http.post("/api/logs/source", json=reference, headers=headers)
    assert response.status_code == 200
    assert "PRIVATE_CANARY" not in response.get_data(as_text=True)
    with app.extensions["source_audit"].connect() as database:
        assert database.execute("SELECT actor,outcome FROM source_access").fetchall() == [("investigate", "granted")]
        database.execute("DROP TABLE source_access")
    failed = http.post("/api/logs/source", json=reference, headers=headers)
    assert failed.status_code == 503
    assert "source" not in failed.json


def test_viewer_session_cannot_acquire_investigator_source_authority(session_portal):
    app, _, _, _ = session_portal
    http, headers = login(app, "view")
    assert http.get("/api/logs/access").json["protected_source"] is False
    reference = {"index": FIXTURE["_index"], "id": FIXTURE["_id"], "purpose": "support"}
    assert http.post("/api/logs/source", json=reference, headers=headers).status_code == 403
    assert http.get_cookie(COOKIE) is not None


def test_conflicting_session_role_is_rejected_at_startup(session_portal, tmp_path):
    _, monitor, settings, users = session_portal
    users["view"]["role"] = "admin"
    filename = tmp_path / "users.json"
    filename.write_text(json.dumps(users), encoding="utf-8")
    with pytest.raises(ValueError, match="roles must agree"):
        create_app(settings, issuer=Mock(), monitor=monitor)
