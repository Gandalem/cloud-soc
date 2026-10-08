"""Session case workflow and tenant boundaries using isolated synthetic data."""
from copy import deepcopy
from datetime import datetime, timezone
from fnmatch import fnmatchcase
import json
import uuid
from unittest.mock import Mock

import pytest

from cloud_soc.portal.app import create_app
from cloud_soc.portal.cases import CaseError, CaseStore
from cloud_soc.portal.operations import ALERT
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS
from test_cases import alert
from test_integration_security import login, make_session_portal
from test_source_access import auth


@pytest.fixture
def workflow(tmp_path):
    app, monitor, settings, _ = make_session_portal(tmp_path)
    stamp = datetime.now(timezone.utc).replace(second=0, microsecond=0).isoformat()
    raw = {"index": "soc-host-raw-test", "id": "raw"}
    norm = {"index": NORMALIZED, "id": "norm"}
    docs = {
        (ALERT, "local"): {"@timestamp": stamp, "organization": {"id": "synthetic"},
            "rule": {"id": "SYNTHETIC"}, "cloud_soc": {"alert_title": "Synthetic alert", "severity": "high",
                "provenance": {"evidence": [{"normalized": norm, "raw": raw}]}}},
        (ALERT, "foreign"): {"@timestamp": stamp, "organization": {"id": "foreign"},
            "cloud_soc": {"alert_title": "FOREIGN_CANARY"}},
        (NORMALIZED, "norm"): {"@timestamp": stamp, "organization": {"id": "synthetic"},
            "event": {"action": "service_started", "outcome": "unknown"},
            "cloud_soc": {"provenance": {"raw": raw}}},
        (raw["index"], raw["id"]): {"@timestamp": stamp, "event": {"ingested": stamp},
            "organization": {"id": "synthetic"}, "host": {"name": "fixture"}, "message": "PRIVATE_CANARY"},
    }
    monitor.indices.resolve_index.side_effect = lambda **kw: {"indices": [{"name": name} for name in sorted(
        {index for index, _ in docs if any(fnmatchcase(index, pattern) for pattern in kw["name"].split(","))})]}
    monitor.get.side_effect = lambda **kw: {"_source": deepcopy(docs[(kw["index"], kw["id"])])}
    monitor.field_caps.side_effect = lambda **kw: {"fields": {kw["fields"][0]: {"date": {}}}}

    def search(**kw):
        scope = kw["query"].get("bool", {}).get("filter", [])
        allowed = next((clause["terms"]["organization.id"] for clause in scope if "terms" in clause), None)
        hits = [{"_index": index, "_id": identifier, "_source": deepcopy(source)}
                for (index, identifier), source in docs.items() if index in kw["index"]
                and (allowed is None or source.get("organization", {}).get("id") in allowed)]
        count = len(hits)
        return {"hits": {"total": {"value": count, "relation": "eq"}, "hits": hits if kw["size"] else []},
                "aggregations": {"trend": {"buckets": [{"key_as_string": stamp, "doc_count": count}] if count else []}}}
    monitor.search.side_effect = search
    return app, monitor, settings, docs


def mutate(http, method, path, headers, body, token=None):
    return http.open(path, method=method, json=body,
                     headers={**headers, "Idempotency-Key": token or str(uuid.uuid4())})


def test_scoped_analyst_can_investigate_create_note_link_and_replay(workflow):
    app, monitor, _, docs = workflow
    http, headers = login(app, "investigate")
    for path in ("/", "/index.html", "/cases.html", "/workbench.html", "/investigation.js", "/operations.js"):
        with http.get(path) as response:
            assert response.status_code == 200, path
    summary = http.get("/api/operations").json
    assert summary["sections"]["alerts"]["count"] == 1
    assert summary["sections"]["alerts"]["rows"][0]["id"] == "local"
    assert summary["sections"]["processing"]["state"] == "unavailable"
    assert summary["sections"]["pipeline"]["state"] == "unavailable"
    assert all({"terms": {"organization.id": ["synthetic"]}} in call.kwargs["query"]["bool"]["filter"]
               for call in monitor.search.call_args_list)
    assert all(RECORDS not in call.kwargs["name"] for call in monitor.indices.resolve_index.call_args_list)
    assert all(call.kwargs["index"] != STATUS for call in monitor.get.call_args_list)
    detail = http.get("/api/alerts/detail?id=local&evidence=0")
    assert detail.status_code == 200
    assert detail.json["evidence"]["state"] == "exact_reference"
    assert "PRIVATE_CANARY" not in detail.get_data(as_text=True)
    body = {"title": "Review", "alert_id": "local", "priority": "high"}
    token = str(uuid.uuid4())
    created = mutate(http, "POST", "/api/cases", headers, body, token)
    assert created.status_code == 200, created.json
    case = created.json
    assert http.get("/api/case-link?alert_id=local").json == {"case_id": case["id"]}
    assert http.get("/api/cases").json["counts"]["total"] == 1
    own = mutate(http, "PATCH", "/api/cases/" + case["id"], headers,
                 {"version": 1, "owner": "investigate", "status": "investigating"})
    assert own.status_code == 200
    saved = mutate(http, "PATCH", "/api/cases/" + case["id"], headers, {"version": 2, "note": "Evidence reviewed"})
    assert saved.json["owner"] == "investigate"
    docs[(ALERT, "second")] = deepcopy(docs[(ALERT, "local")])
    linked = mutate(http, "PATCH", "/api/cases/" + case["id"], headers, {"version": 3, "alert_id": "second"})
    assert linked.status_code == 200
    case_detail = http.get("/api/cases/" + case["id"]).json
    assert len(case_detail["alerts"]) == 2
    assert case_detail["history"][1]["note"] == "Evidence reviewed"
    admin, admin_headers = login(app, "admin")
    admin_note = mutate(admin, "PATCH", "/api/cases/" + case["id"], admin_headers,
                        {"version": 4, "note": "Another analyst remains assigned"})
    assert admin_note.json["owner"] == "investigate"
    monitor.get.side_effect = RuntimeError("Unavailable")
    assert mutate(http, "POST", "/api/cases", headers, body, token).json == case


def test_unexpected_foreign_search_response_is_withheld(workflow):
    app, monitor, _, docs = workflow
    original = monitor.search.side_effect
    def unexpected(**kw):
        result = original(**kw)
        if kw["size"]:
            result["hits"]["hits"] = [{"_id": "foreign", "_source": docs[(ALERT, "foreign")]}]
        return result
    monitor.search.side_effect = unexpected
    http, _ = login(app, "investigate")
    response = http.get("/api/operations")
    assert response.json["sections"]["alerts"] == {"state": "unavailable"}
    assert "FOREIGN_CANARY" not in response.get_data(as_text=True)


def test_foreign_cases_alerts_evidence_and_owner_assignment_are_blocked(workflow):
    app, _, _, _ = workflow
    local, headers = login(app, "investigate")
    other, other_headers = login(app, "other")
    foreign = mutate(other, "POST", "/api/cases", other_headers,
                     {"title": "FOREIGN_CANARY", "alert_id": "foreign", "priority": "high"}).json
    assert local.get("/api/cases", headers={"X-Organization": "foreign", "X-Role": "admin"}).json["counts"]["total"] == 0
    assert local.get("/api/cases/" + foreign["id"]).status_code == 404
    assert local.get("/api/cases/" + foreign["id"] + "?before=100").status_code == 404
    assert local.get("/api/case-link?alert_id=foreign").json == {"case_id": None}
    for path in ("/api/alerts/detail?id=foreign", "/api/alerts/detail?id=foreign&evidence=0"):
        response = local.get(path)
        assert response.status_code == 404
        assert "FOREIGN_CANARY" not in response.get_data(as_text=True)
    assert mutate(local, "POST", "/api/cases", headers,
                  {"title": "Forbidden", "alert_id": "foreign", "priority": "high"}).status_code == 404
    assert mutate(local, "PATCH", "/api/cases/" + foreign["id"], headers,
                  {"version": 1, "note": "Forbidden"}).status_code == 404
    created = mutate(local, "POST", "/api/cases", headers,
                     {"title": "Allowed", "alert_id": "local", "priority": "high"}).json
    path = "/api/cases/" + created["id"]
    assert mutate(local, "PATCH", path, headers, {"version": 1, "alert_id": "foreign"}).status_code == 404
    assert mutate(local, "PATCH", path, headers, {"version": 1, "owner": "other"}).status_code == 400
    assert local.get(path).json["case"]["version"] == 1


@pytest.mark.parametrize("index,id", [(NORMALIZED, "norm"), ("soc-host-raw-test", "raw")])
@pytest.mark.parametrize("organization", ["foreign", None, ["synthetic"]])
def test_malformed_or_cross_tenant_evidence_never_returns_document_metadata(workflow, index, id, organization):
    app, _, _, docs = workflow
    docs[(index, id)]["organization"]["id"] = organization
    docs[(index, id)]["host"] = {"name": "FOREIGN_CANARY"}
    http, _ = login(app, "investigate")
    response = http.get("/api/alerts/detail?id=local&evidence=0")
    assert response.status_code == 200
    assert "FOREIGN_CANARY" not in response.get_data(as_text=True)
    assert response.json["evidence"]["state"] != "exact_reference"
    assert "metadata" not in response.json["evidence"]


def test_scoped_viewer_reads_cases_but_cannot_modify_or_acquire_source(workflow):
    app, _, _, _ = workflow
    analyst, headers = login(app, "investigate")
    row = mutate(analyst, "POST", "/api/cases", headers, {"title": "Read only", "alert_id": "local", "priority": "high"}).json
    viewer, viewer_headers = login(app, "view")
    assert viewer.get("/api/cases").json["counts"]["total"] == 1
    assert viewer.get("/api/cases/" + row["id"]).status_code == 200
    assert viewer.get("/api/alerts/detail?id=local&evidence=0").status_code == 200
    assert mutate(viewer, "PATCH", "/api/cases/" + row["id"], viewer_headers, {"version": 1, "note": "No"}).status_code == 403
    assert mutate(viewer, "POST", "/api/cases", viewer_headers, {"title": "No", "alert_id": "local", "priority": "high"}).status_code == 403
    assert viewer.post("/api/logs/source", json={"index": "soc-host-raw-test", "id": "raw", "purpose": "investigation"},
                       headers=viewer_headers).status_code == 403
    for path in ("/api/keys", "/api/portal", "/api/agents/status", "/api/agents/health", "/api/detection/history", "/api/reprocessing/history", "/api/healthz"):
        assert viewer.get(path).status_code == 403
        assert analyst.get(path).status_code == 403
    assert analyst.patch("/api/cases/" + row["id"], json={"version": 1, "note": "No CSRF"},
                         headers={"X-Cloud-SOC": "portal"}).status_code == 403


def test_basic_log_identities_remain_log_only(workflow):
    _, monitor, settings, _ = workflow
    app = create_app({**settings, "USERS_FILE": None}, issuer=Mock(), monitor=monitor)
    http = app.test_client()
    for path in ("/api/cases", "/api/operations", "/api/alerts/detail?id=local", "/cases.html", "/workbench.html"):
        assert http.get(path, headers=auth("investigate")).status_code == 403


def test_unscoped_session_cannot_see_existing_cases_or_write(workflow, tmp_path):
    _, monitor, settings, _ = workflow
    users = {"admin": {"role": "admin", "password_hash": settings["ADMIN_HASH"]},
             "unscoped": {"role": "analyst", "password_hash": settings["ADMIN_HASH"]}}
    filename = tmp_path / "unscoped.json"
    filename.write_text(json.dumps(users), encoding="utf-8"); filename.chmod(0o600)
    app = create_app({**settings, "USERS_FILE": str(filename)}, issuer=Mock(), monitor=monitor)
    admin, headers = login(app, "admin")
    case = mutate(admin, "POST", "/api/cases", headers, {"title": "Admin case", "alert_id": "local", "priority": "high"}).json
    user, user_headers = login(app, "unscoped")
    assert user.get("/api/cases").json["counts"]["total"] == 0
    assert user.get("/api/cases/" + case["id"]).status_code == 404
    assert user.get("/api/operations").status_code == 403
    assert user.get("/api/alerts/detail?id=local").status_code == 403
    assert mutate(user, "POST", "/api/cases", user_headers,
                  {"title": "No", "alert_id": "local", "priority": "high"}).status_code == 403


def test_case_scope_covers_counts_pagination_and_replays_after_scope_change(tmp_path):
    store = CaseStore(tmp_path / "cases.sqlite", "admin", principals={"admin", "analyst"},
                      organizations={"admin": None, "analyst": ("school",)})
    for i in range(27):
        store.create({"title": "Foreign", "priority": "high", "alert_id": "foreign-" + str(i)},
                     "admin", str(uuid.uuid4()), lambda id: alert(id, "foreign"))
    token = str(uuid.uuid4()); body = {"title": "Local", "priority": "high", "alert_id": "local"}
    case = store.create(body, "analyst", token, alert)
    first = store.listing([], "analyst")
    assert first["counts"] == {"total": 1, "open": 1, "unassigned": 1, "investigating": 0}
    assert first["rows"] == [case]
    assert store.listing([("page", "2")], "analyst")["rows"] == []
    update_token = str(uuid.uuid4()); update_body = {"version": 1, "note": "Reviewed"}
    store.update(case["id"], update_body, "analyst", update_token, alert)
    restricted = CaseStore(store.path, "admin", principals={"admin", "analyst"},
                           organizations={"admin": None, "analyst": ("foreign",)})
    for operation in (lambda: restricted.create(body, "analyst", token, alert),
                      lambda: restricted.update(case["id"], update_body, "analyst", update_token, alert)):
        with pytest.raises(CaseError) as caught:
            operation()
        assert caught.value.status == 404
