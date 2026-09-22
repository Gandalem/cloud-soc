"""Synthetic OCI events against the existing disposable ES test container."""

import json
from pathlib import Path

from elasticsearch import Elasticsearch, AuthorizationException
from cloud_soc.oci.audit import project_event
from cloud_soc.oci.collector import ElasticsearchSink
from cloud_soc.portal.log_query import LogReader
from cloud_soc.portal.status_setup import configure_template


def check_oci(test, admin, monitor, url):
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "deploy/oci/index-template.json").read_text(encoding="utf-8"))
    template["template"]["settings"]["number_of_replicas"] = 0
    admin.indices.put_index_template(name="test-oci-audit", body=configure_template(template))
    role = json.loads((root / "deploy/oci/publisher-role.json").read_text(encoding="utf-8"))
    key = admin.security.create_api_key(name="synthetic-oci", expiration="1h", role_descriptors={"oci": role})
    fixture = json.loads((root / "tests/fixtures/oci_audit.json").read_text(encoding="utf-8"))
    references = []
    with Elasticsearch(url, api_key=key["encoded"], request_timeout=10) as publisher:
        sink = ElasticsearchSink(publisher)
        for event in fixture["events"]:
            index, identifier, doc = project_event(event, tenancy=fixture["tenancy"], compartment=fixture["compartment"], region=fixture["region"], organization="fixture")
            doc["event"]["ingested"] = "2099-01-01T00:00:00Z"
            test.assertTrue(sink.create(index, identifier, doc))
            test.assertFalse(sink.create(index, identifier, doc))
            references.append({"index": index, "id": identifier})
        for operation in (lambda: publisher.search(index="soc-cloud-oci-*"),
                          lambda: publisher.create(index="soc-cloud-aws-denied", id="denied", document={}),
                          lambda: publisher.create(index="soc-host-raw-denied", id="denied", document={}),
                          lambda: publisher.index(index=references[0]["index"], id=references[0]["id"], document={})):
            with test.assertRaises(AuthorizationException):
                operation()
    admin.indices.refresh(index="soc-cloud-oci-*")
    reader = LogReader(monitor, secret="synthetic", principal="fixture")
    result = json.loads(reader.page([("collector", "oci-audit"), ("os", "cloud")]))
    test.assertEqual(len(result["rows"]), 3)
    test.assertTrue(all(row["cloud_provider"] == "oci" and row["host_name"] is None for row in result["rows"]))
    test.assertTrue(all(not row["received_at"].startswith("2099") for row in result["rows"]))
    test.assertEqual(len(json.loads(reader.page([("os", "cloud")]))["rows"]), 6)
    test.assertEqual(len(json.loads(reader.page([("collector", "oci-audit"), ("ip", "2001:db8::31")]))["rows"]), 1)
    for event, reference in zip(fixture["events"], references):
        detail = json.loads(reader.detail(list(reference.items())))
        test.assertEqual(detail["security"]["adapter"], "oci_audit_metadata_v1")
        test.assertEqual(detail["security"]["fields"]["compartment_id"], fixture["compartment"])
        test.assertEqual(detail["security"]["fields"]["resource_id"], event["data"]["resource_id"])
        test.assertEqual(detail["security"]["fields"]["http_status"], int(event["data"]["response"]["status"]))
        test.assertEqual(detail["row"]["reference"], reference)
        test.assertNotIn("PRIVATE_CANARY", json.dumps(detail))
        test.assertNotIn("PRIVATE_CANARY", json.dumps(admin.get(**reference)["_source"]))
