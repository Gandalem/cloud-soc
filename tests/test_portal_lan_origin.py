"""Direct LAN authorities must retain authentication and same-origin boundaries."""
from unittest.mock import Mock

import pytest

from cloud_soc.portal.app import create_app
from test_portal import ROOT, CA, AUTH, HASH
from test_integration_security import make_session_portal

LAN = "https://192.168.32.60"
PUBLIC = "https://soc.example.test"


def settings(tmp_path, **extra):
    return {"STATE_DIR": tmp_path, "AGENT_SOURCE": ROOT / "deploy/agents", "CA_BYTES": CA,
            "PUBLIC_URL": PUBLIC, "ENDPOINT": "https://soc.example.test:9200",
            "ADMIN_USER": "admin", "ADMIN_HASH": HASH, **extra}


def test_alias_is_opt_in_and_requires_normal_authentication(tmp_path):
    app = create_app(settings(tmp_path), issuer=Mock())
    assert app.test_client().get("/", base_url=LAN).status_code == 400
    app = create_app(settings(tmp_path, LAN_URL=LAN), issuer=Mock())
    http = app.test_client()
    assert http.get("/", base_url=LAN).status_code == 401
    for origin in (LAN, PUBLIC):
        response = http.get("/", base_url=origin, headers={"Authorization": AUTH})
        assert response.status_code == 200 and b"Cloud SOC" in response.data


def test_lan_save_and_other_allowed_origin_cannot_cross_authorities(tmp_path):
    app = create_app(settings(tmp_path, LAN_URL=LAN), issuer=Mock())
    http = app.test_client()
    headers = {"Authorization": AUTH, "X-Cloud-SOC": "portal", "Origin": LAN}
    data = {"action": "create", "revision": 0, "template": "empty", "name": "LAN"}
    assert http.post("/api/dashboards", base_url=LAN, json=data, headers=headers).status_code == 200
    for host, origin in ((LAN, PUBLIC), (PUBLIC, LAN), (LAN, "https://attacker.test")):
        assert http.post("/api/dashboards", base_url=host, json=data,
                         headers={**headers, "Origin": origin}).status_code == 403
    for host in ("https://192.168.32.61", LAN + ":8443", "https://attacker.test"):
        assert http.get("/", base_url=host, headers=headers).status_code == 400
    assert http.post("/api/dashboards", base_url=LAN, json=data,
                     headers={**headers, "Sec-Fetch-Site": "cross-site"}).status_code == 403
    assert http.post("/api/dashboards", base_url=LAN, json=data,
                     headers={"Authorization": AUTH, "Origin": LAN}).status_code == 403


@pytest.mark.parametrize("origin", ["http://192.168.32.60", "https://attacker.test", "https://8.8.8.8",
    "https://192.168.32.60/path", LAN + "?q=1", LAN + "#part", "https://user@192.168.32.60",
    LAN + ":8443", "https://0.0.0.0", "https://239.1.1.1", "https://*.test", "https://"])
def test_unsafe_lan_origin_fails_before_opening_state(tmp_path, origin):
    with pytest.raises(ValueError):
        create_app(settings(tmp_path / "absent", LAN_URL=origin), issuer=Mock())
    assert not (tmp_path / "absent").exists()


def test_lan_session_login_still_requires_csrf_for_save(tmp_path):
    _, monitor, configuration, _ = make_session_portal(tmp_path)
    app = create_app({**configuration, "PUBLIC_URL": PUBLIC, "LAN_URL": LAN}, issuer=Mock(), monitor=monitor)
    http = app.test_client()
    headers = {"X-Cloud-SOC": "portal", "Origin": LAN}
    response = http.post("/api/auth/login", base_url=LAN, json={"username": "admin", "password": "synthetic-password"}, headers=headers)
    assert response.status_code == 200
    identity = http.get("/api/auth/me", base_url=LAN).json
    data = {"action": "create", "revision": 0, "template": "empty", "name": "LAN session"}
    assert http.post("/api/dashboards", base_url=LAN, json=data, headers=headers).status_code == 403
    assert http.post("/api/dashboards", base_url=LAN, json=data,
                     headers={**headers, "X-CSRF-Token": identity["csrf"]}).status_code == 200
