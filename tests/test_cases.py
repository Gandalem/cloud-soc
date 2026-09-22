"""Case work uses synthetic alert metadata and isolated temporary SQLite files."""
from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import sys
import tempfile
import unittest
import uuid
from unittest.mock import Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from cloud_soc.portal.cases import CaseStore, CaseError
import test_portal
AUTH = test_portal.AUTH


def alert(identifier="fixture", organization="school"):
    return {"id": identifier, "organization": organization, "title": "Synthetic alert", "timestamp": "2026-09-22T01:00:00Z",
            "severity": "high", "rule": "SYNTHETIC-ONLY", "source_ip": "192.0.2.1"}


class CasesTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "cases.sqlite"
        self.store = CaseStore(self.path, "admin")
        self.fetch = Mock(side_effect=lambda identifier: alert(identifier))

    def create(self, identifier="fixture", title="Test investigation"):
        return self.store.create({"title": title, "alert_id": identifier, "priority": "high"}, "admin", str(uuid.uuid4()), self.fetch)

    def update(self, row, **changes):
        return self.store.update(row["id"], {"version": row["version"], **changes}, "admin", str(uuid.uuid4()), self.fetch)

    def test_create_restart_and_explicit_assignment(self):
        row = self.create(); self.assertIsNone(row["owner"])
        row = self.update(row, owner="admin", status="investigating", note="Reviewing exact evidence")
        other = CaseStore(self.path, "admin")
        result = other.detail(row["id"], "admin")
        self.assertEqual(result["case"]["version"], 2)
        self.assertEqual(result["history"][0]["actor"], "admin")
        self.assertEqual(result["history"][0]["note"], "Reviewing exact evidence")
        self.assertEqual(result["alerts"][0]["id"], "fixture")

    def test_retries_are_idempotent_even_after_alert_unavailable(self):
        key = str(uuid.uuid4()); body = {"title": "Test", "alert_id": "fixture", "priority": "high"}
        row = self.store.create(body, "admin", key, self.fetch)
        self.fetch.side_effect = RuntimeError("PRIVATE_CANARY")
        self.assertEqual(self.store.create(body, "admin", key, self.fetch), row)
        with self.assertRaises(CaseError) as caught:
            self.store.create({**body, "title": "Changed"}, "admin", key, self.fetch)
        self.assertEqual(caught.exception.status, 409)
        self.assertEqual(len(self.store.detail(row["id"], "admin")["history"]), 1)

    def test_duplicate_alert_and_cross_organization_rejected(self):
        row = self.create()
        with self.assertRaises(CaseError): self.create()
        self.fetch.side_effect = lambda identifier: alert(identifier, "other")
        with self.assertRaises(CaseError) as caught: self.update(row, alert_id="different")
        self.assertEqual(caught.exception.code, "organization_mismatch")
        self.assertEqual(self.store.detail(row["id"], "admin")["case"]["version"], 1)

    def test_same_org_link_and_lookup(self):
        row = self.create(); row = self.update(row, alert_id="second")
        self.assertEqual(self.store.lookup("second", "admin")["case_id"], row["id"])
        self.assertEqual(len(self.store.detail(row["id"], "admin")["alerts"]), 2)

    def test_state_transition_closure_and_reopen_need_reasons(self):
        row = self.create()
        for data in ({"status": "escalated"}, {"status": "closed"}, {"verdict": "malicious"}, {"status": "closed", "note": "reason"}):
            with self.assertRaises(CaseError): self.update(row, **data)
        closed = self.update(row, status="closed", verdict="inconclusive", note="Insufficient evidence")
        with self.assertRaises(CaseError): self.update(closed, note="Edit while closed")
        reopened = self.update(closed, status="investigating", note="New evidence")
        self.assertEqual(reopened["verdict"], "unreviewed")

    def test_two_concurrent_writers_only_one_succeeds(self):
        row = self.create()
        def attempt(note):
            try: return self.update(row, note=note)["version"]
            except CaseError as error: return error.code
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(attempt, ["writer A", "writer B"]))
        self.assertCountEqual(results, [2, "case_version_conflict"])
        self.assertEqual(len(self.store.detail(row["id"], "admin")["history"]), 2)

    def test_failed_es_lookup_rolls_back_case_and_request(self):
        self.fetch.side_effect = RuntimeError("PRIVATE_CANARY")
        with self.assertRaises(RuntimeError): self.create()
        self.assertEqual(self.store.listing([], "admin")["counts"]["total"], 0)
        with self.store.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM case_requests").fetchone()[0], 0)

    def test_privacy_permissions_and_untrusted_owner(self):
        row = self.create(title="<img src=x onerror=alert(1)>")
        self.assertEqual(row["title"], "<img src=x onerror=alert(1)>")
        for data in ({"owner": "invented-user"}, {"note": "password=PRIVATE_CANARY"}, {"note": "x"*2001}, {"version": True}, {"actor": "forged"}):
            with self.assertRaises(CaseError): self.update(row, **data)
        with self.assertRaises(CaseError) as caught: self.store.detail(row["id"], "not-admin")
        self.assertEqual(caught.exception.status, 403)

    def test_queue_paging_sort_and_counts_use_same_filter(self):
        for i in range(27):
            row = self.create(str(i))
            if i%2==0: self.update(row, owner="admin", status="investigating")
        first = self.store.listing([("sort", "oldest")], "admin")
        second = self.store.listing([("sort", "oldest"), ("page", "2")], "admin")
        self.assertEqual([len(first["rows"]),len(second["rows"])], [25,2])
        self.assertFalse(set(r["id"] for r in first["rows"]) & set(r["id"] for r in second["rows"]))
        filtered = self.store.listing([("owner", "me"), ("status", "investigating")], "admin")
        self.assertEqual(filtered["counts"], {"total":14,"open":14,"unassigned":0,"investigating":14})
        for pairs in ([("sort", "DROP TABLE cases")], [("status", "new"),("status", "closed")], [("page", "0")]):
            with self.assertRaises(CaseError): self.store.listing(pairs,"admin")

    def test_history_keyset_pagination_and_update_retry(self):
        row=self.create()
        for i in range(53): row=self.update(row,note="note "+str(i))
        key=str(uuid.uuid4()); body={"version":row["version"],"note":"last"}
        changed=self.store.update(row["id"],body,"admin",key,self.fetch)
        self.assertEqual(self.store.update(row["id"],body,"admin",key,self.fetch),changed)
        first=self.store.detail(row["id"],"admin"); second=self.store.detail(row["id"],"admin",first["history_next"])
        self.assertEqual(len(first["history"])+len(second["history"]),55)
        self.assertGreater(first["history"][-1]["seq"],second["history"][0]["seq"])


class CaseApiTests(unittest.TestCase):
    def setUp(self):
        self.base=test_portal.PortalTests(); self.base.setUp(); self.addCleanup(self.base.doCleanups)
        self.client=self.base.client

    def test_auth_csrf_input_and_live_static(self):
        for path in ("/api/cases", "/api/cases/"+"a"*32,"/api/case-link?alert_id=x","/investigation.js"):
            self.assertEqual(self.client.get(path).status_code,401)
        self.assertEqual(self.client.post("/api/cases",json={},headers={"Authorization":AUTH}).status_code,403)
        self.assertEqual(self.base.request("POST","/api/cases",{}).status_code,400)
        result=self.base.request("GET","/workbench.html")
        self.assertIn(b"investigation.js",result.data);self.assertNotIn(b"demo-data.js",result.data);result.close()

    def test_persisted_api_writes_and_conflict(self):
        body={"title":"API case","alert_id":"fixture","priority":"high"}
        headers={"Idempotency-Key":str(uuid.uuid4())}
        with patch("cloud_soc.portal.operations.Operations.detail",return_value=json.dumps({"alert":alert()}).encode()):
            response=self.base.request("POST","/api/cases",body,headers=headers)
        self.assertEqual(response.status_code,200,response.json)
        identifier=response.json["id"]
        update={"version":1,"status":"investigating","owner":"admin","note":"Review"}
        result=self.base.request("PATCH","/api/cases/"+identifier,update,headers={"Idempotency-Key":str(uuid.uuid4())})
        self.assertEqual(result.status_code,200)
        self.assertEqual(self.base.request("PATCH","/api/cases/"+identifier,update,headers={"Idempotency-Key":str(uuid.uuid4())}).status_code,409)
        self.assertEqual(self.base.request("GET","/api/cases/"+identifier).json["history"][0]["note"],"Review")
        self.assertEqual(self.base.request("GET","/api/case-link?alert_id=fixture").json["case_id"],identifier)


if __name__ == "__main__": unittest.main()
