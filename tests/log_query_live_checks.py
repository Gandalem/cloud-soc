"""Additional checks called only inside the disposable ES integration fixture."""

from copy import deepcopy
import json
from pathlib import Path

from cloud_soc.portal.log_query import LogReader, LogQueryError


def check_log_queries(test, admin, monitor):
    root = Path(__file__).resolve().parents[1]
    fixtures = json.loads((root / "tests/fixtures/log_intake.json").read_text(encoding="utf-8"))["hits"]
    reader = LogReader(monitor, secret="synthetic-cursor-secret", principal="synthetic-admin")
    period = [("start", "2026-09-22T00:00:00Z"), ("end", "2026-09-23T00:00:00Z"), ("time_basis", "event")]
    for hit in fixtures:
        admin.index(index=hit["_index"], id=hit["_id"], document=hit["_source"])
    admin.indices.refresh(index="soc-host-raw-*,soc-network-*")

    def search(*extra):
        return json.loads(reader.page(period + list(extra)))

    test.assertEqual(len(search()["rows"]), 7)
    for os_name, count in [("windows", 3), ("linux", 4), ("unknown", 0)]:
        result = search(("os", os_name))
        test.assertEqual(len(result["rows"]), count)
        test.assertTrue(all(row["os"] == os_name for row in result["rows"]))
    test.assertEqual(len(search(("collector", "packetbeat"))["rows"]), 3)
    test.assertEqual(len(search(("host", "win.example.test"))["rows"]), 3)
    test.assertEqual(len(search(("ip", "198.51.100.20"))["rows"]), 2)
    test.assertEqual(len(search(("ip", "2001:0db8::1"))["rows"]), 1)
    test.assertEqual(len(search(("ip", "192.0.2.10"), ("os", "windows"))["rows"]), 2)
    test.assertEqual(search(("host", "win.*"))["rows"], [])
    original = fixtures[0]
    detail = json.loads(reader.detail([("index", original["_index"]), ("id", original["_id"])]))
    test.assertEqual(detail["row"]["reference"]["id"], original["_id"])
    test.assertNotIn('"message"', json.dumps(detail))
    test.assertNotIn('"event_data"', json.dumps(detail))

    # The real ES source filter permits selected audit fields, never whole event_data.
    audit_source = deepcopy(original["_source"])
    audit_source["winlog"].update(provider_name="Microsoft-Windows-Security-Auditing",
                                 event_data={"TargetUserName": "audit-fixture", "LogonType": "10",
                                             "CommandLine": "PRIVATE_CANARY", "TaskContent": "PRIVATE_CANARY"})
    audit_source["message"] = "PRIVATE_CANARY"
    admin.index(index=original["_index"], id="security-detail-fixture", document=audit_source, refresh=True)
    audited = json.loads(reader.detail([("index", original["_index"]), ("id", "security-detail-fixture")]))
    test.assertEqual(audited["security"]["fields"]["target_user"], "audit-fixture")
    test.assertEqual(audited["security"]["fields"]["outcome"], "failure")
    test.assertEqual(audited["security"]["audit_configuration"], "not_checked")
    test.assertNotIn("PRIVATE_CANARY", json.dumps(audited))
    admin.delete(index=original["_index"], id="security-detail-fixture", refresh=True)
    flow = next(hit for hit in fixtures if hit["_id"] == "flow")
    network = json.loads(reader.detail([("index", flow["_index"]), ("id", flow["_id"])]))
    test.assertEqual(network["security"]["fields"]["bytes"], 2048)
    test.assertEqual(network["security"]["process_link"], "not_established")

    # Equal timestamps across page boundaries, and a new arrival during pagination.
    source = deepcopy(original["_source"])
    source["host"]["name"] = "pagination.example.test"
    index = original["_index"]
    for number in range(61):
        admin.index(index=index, id=f"page-{number}", document=source)
    admin.indices.refresh(index=index)
    first = search(("host", "pagination.example.test"))
    admin.index(index=index, id="new-after-snapshot", document=source, refresh=True)
    seen = [row["reference"]["id"] for row in first["rows"]]
    result = first
    while result["next_cursor"]:
        result = json.loads(reader.page([("cursor", result["next_cursor"])]))
        seen.extend(row["reference"]["id"] for row in result["rows"])
    test.assertEqual(len(seen), 61)
    test.assertEqual(len(set(seen)), 61)
    test.assertNotIn("new-after-snapshot", seen)
    # Closing a PIT causes a safe 410, not a misleading empty page.
    first = search(("host", "pagination.example.test"))
    state, _ = reader.decode(first["next_cursor"])
    monitor.close_point_in_time(id=state["pit"])
    with test.assertRaises(LogQueryError) as error:
        reader.page([("cursor", first["next_cursor"])])
    test.assertEqual(error.exception.status, 410)

    admin.indices.put_alias(index=index, name="soc-host-raw-forbidden-alias")
    with test.assertRaises(LogQueryError):
        reader.detail([("index", "soc-host-raw-forbidden-alias"), ("id", original["_id"])])
    admin.indices.delete_alias(index=index, name="soc-host-raw-forbidden-alias")

    admin.indices.create(index="soc-host-raw-incompatible", mappings={"properties": {
        "@timestamp": {"type": "keyword"},
    }})
    with test.assertRaises(LogQueryError) as error:
        search()
    test.assertEqual(error.exception.status, 503)
