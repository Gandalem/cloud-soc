"""Security boundaries and scoring behavior for the approved 1–12 improvements."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from werkzeug.security import generate_password_hash

from cloud_soc.detection.engine import detect_rule
from cloud_soc.detection.risk import calculate_risk
from cloud_soc.elastic.client import create_elasticsearch_client
from cloud_soc.portal.app import create_app
from cloud_soc.portal.auth import COOKIE, Sessions, load_users
from cloud_soc.privacy import REDACTED, redact_metadata, sensitive
from test_sequence_detection import ssh
from cloud_soc.detection.worker import approved_rules

ROOT = Path(__file__).resolve().parents[1]
PASSWORD = "synthetic-password"
HASH = generate_password_hash(PASSWORD, method="pbkdf2:sha256:1000")


class ImprovementsTests(unittest.TestCase):
    def test_risk_is_explainable_bounded_and_has_no_unknown_context(self):
        row = {"severity":"high", "event_count":10, "threshold":5, "rule_snapshot":{"type":"threshold"}}
        risk = calculate_risk(row)
        self.assertEqual(risk["risk_score"], 75)
        self.assertEqual(risk["risk_score"], sum(item["points"] for item in risk["risk_factors"]))
        self.assertEqual(risk["risk_level"], "high")
        row.update(severity="critical", rule_snapshot={"type":"sequence"})
        self.assertEqual(calculate_risk(row)["risk_score"],100)
        row["event_count"] = True
        with self.assertRaises(ValueError): calculate_risk(row)

    def test_unknown_detector_fails_closed(self):
        with self.assertRaises(ValueError): detect_rule([], {"type":"untrusted_python"})

    def test_correlation_does_not_count_repeated_evidence(self):
        rule = next(row for row in approved_rules(include_sequence=True) if row.get("type") == "sequence")
        failure = ssh(0)
        self.assertEqual(detect_rule([failure]*5+[ssh(5,outcome="success")],rule),[])
        runtime = {}
        detect_rule([failure], rule, runtime=runtime)
        detect_rule([failure], rule, runtime=runtime)
        self.assertEqual(sum(len(group["failures"]) for group in runtime.values()),1)
        rows = [ssh(i) for i in range(5)]+[ssh(5,outcome="success")]
        detection = detect_rule(rows+rows,rule)[0]
        self.assertEqual(len(detection["evidence"]),6)

    def test_structured_redaction_preserves_original(self):
        source = {"items":[{"x-api-key":"canary", "access_key_id":"canary", "safe":"hello"}],
                  "private_key":"canary", "note":"set-cookie=canary"}
        output = redact_metadata(source)
        self.assertEqual(output["private_key"],REDACTED)
        self.assertEqual(output["items"][0]["x-api-key"],REDACTED)
        self.assertEqual(output["items"][0]["access_key_id"],REDACTED)
        self.assertEqual(output["items"][0]["safe"],"hello")
        self.assertEqual(output["note"],REDACTED)
        self.assertEqual(source["private_key"],"canary")
        for key in ("private_key", "client_secret", "refresh_token", "secret_access_key", "session_token"):
            self.assertTrue(sensitive(key+"=canary"))

    def test_elasticsearch_credentials_never_travel_over_http(self):
        for url in ("http://192.0.2.1:9200", "http://localhost:9200", "https://user:pass@host:9200"):
            with patch.dict(os.environ,{"ELASTICSEARCH_URL":url,"ELASTICSEARCH_API_KEY":"canary"},clear=True):
                with self.assertRaises(ValueError): create_elasticsearch_client()
        with patch.dict(os.environ,{"ELASTICSEARCH_URL":"https://es.invalid:9200","ELASTICSEARCH_API_KEY":"canary","ELASTICSEARCH_CA_FILE":"fixture-ca"},clear=True):
            with patch("cloud_soc.elastic.client.Elasticsearch") as client:
                create_elasticsearch_client()
                self.assertEqual(client.call_args.kwargs["ca_certs"],"fixture-ca")
                self.assertEqual(client.call_args.kwargs["api_key"],"canary")


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name)
        self.users = {name:{"role":name,"password_hash":HASH} for name in ("admin","analyst","viewer")}
        filename = self.path/"users.json"
        filename.write_text(json.dumps(self.users)); filename.chmod(0o600)
        settings = {"STATE_DIR":self.path,"AGENT_SOURCE":ROOT/"deploy/agents","CA_BYTES":b"synthetic",
                    "PUBLIC_URL":"https://soc.invalid","ENDPOINT":"https://es.invalid:9200",
                    "ADMIN_USER":"admin","ADMIN_HASH":HASH,"USERS_FILE":str(filename)}
        self.app = create_app(settings,issuer=Mock(),monitor=Mock())
        self.app.config["TESTING"] = True

    def request(self, client, method, url, **kwargs):
        return client.open(url,method=method,base_url="https://soc.invalid",**kwargs)

    def login(self, role):
        client = self.app.test_client()
        response = self.request(client,"POST","/api/auth/login",json={"username":role,"password":PASSWORD},headers={"X-Cloud-SOC":"portal"})
        self.assertEqual(response.status_code,200)
        self.assertIn("HttpOnly",response.headers["Set-Cookie"])
        self.assertIn("Secure",response.headers["Set-Cookie"])
        self.assertIn("SameSite=Strict",response.headers["Set-Cookie"])
        identity = self.request(client,"GET","/api/auth/me").json
        return client,identity

    def test_server_enforces_roles_even_with_forged_ui(self):
        for role in self.users:
            client,identity = self.login(role)
            self.assertEqual(self.request(client,"GET","/api/cases").json["actor"],role)
            self.assertEqual(self.request(client,"GET","/api/keys").status_code,200 if role=="admin" else 403)
            response = self.request(client,"POST","/api/cases",json={},headers={"X-Cloud-SOC":"portal","X-CSRF-Token":identity["csrf"]})
            self.assertEqual(response.status_code,403 if role=="viewer" else 400)
            if role != "admin":
                self.assertEqual(self.request(client,"GET","/agents.html").status_code,403)

    def test_cross_origin_login_and_csrf_mutations_are_rejected(self):
        client,identity = self.login("admin")
        for extra in ({},{"X-CSRF-Token":"forged"},{"X-CSRF-Token":identity["csrf"],"Origin":"https://evil.invalid"}):
            response = self.request(client,"POST","/api/auth/logout",json={},headers={"X-Cloud-SOC":"portal",**extra})
            self.assertEqual(response.status_code,403)
        self.assertEqual(self.request(client,"POST","/api/auth/login",json={"username":"admin","password":PASSWORD},headers={"X-Cloud-SOC":"portal","Origin":"https://evil.invalid"}).status_code,403)

    def test_logout_revokes_copied_cookie_and_sessions_expire(self):
        client,identity = self.login("analyst")
        token = client.get_cookie(COOKIE,domain="soc.invalid").value
        self.assertNotIn(token,(self.path/"sessions.sqlite").read_bytes().decode("latin-1"))
        self.assertEqual(self.request(client,"POST","/api/auth/logout",json={},headers={"X-Cloud-SOC":"portal","X-CSRF-Token":identity["csrf"]}).status_code,200)
        client.set_cookie(COOKIE,token,domain="soc.invalid")
        self.assertEqual(self.request(client,"GET","/api/auth/me").status_code,401)
        client,_ = self.login("viewer")
        with patch("cloud_soc.portal.auth.time.time",return_value=10**12):
            self.assertEqual(self.request(client,"GET","/api/auth/me").status_code,401)

    def test_password_or_role_change_invalidates_session(self):
        sessions = self.app.extensions["sessions"]
        token = sessions.login("analyst",PASSWORD)
        sessions.users["analyst"]["role"] = "viewer"
        self.assertIsNone(sessions.get(token))

    def test_repeated_login_failures_are_throttled_across_instances(self):
        sessions = self.app.extensions["sessions"]
        for _ in range(5): self.assertIsNone(sessions.login("viewer","bad"))
        other = Sessions(self.path/"sessions.sqlite",self.users)
        self.assertIsNone(other.login("viewer",PASSWORD))
        with patch("cloud_soc.portal.auth.time.time",return_value=10**12):
            self.assertIsNotNone(other.login("viewer",PASSWORD))

    def test_missing_session_cannot_use_basic_to_bypass_roles(self):
        client=self.app.test_client()
        response=self.request(client,"GET","/api/keys",headers={"Authorization":"Basic YWRtaW46c3ludGhldGljLXBhc3N3b3Jk"})
        self.assertEqual(response.status_code,401)
        self.assertEqual(self.request(client,"GET","/").status_code,302)

    @unittest.skipIf(os.name=="nt","POSIX permission validation")
    def test_user_hash_config_must_not_be_world_readable(self):
        filename=self.path/"users.json";filename.chmod(0o644)
        with self.assertRaises(ValueError): load_users(filename)
