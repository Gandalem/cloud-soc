"""Synthetic AWS SDK envelopes -> real disposable ES -> read-only portal query."""

import json
from pathlib import Path

from elasticsearch import Elasticsearch, AuthorizationException

from cloud_soc.aws.collector import ElasticsearchSink
from cloud_soc.aws.cloudtrail import project_event, timestamp
from cloud_soc.portal.log_query import LogReader
from cloud_soc.portal.status_setup import configure_template


def check_p4(test, admin, monitor, url):
    root = Path(__file__).resolve().parents[1]
    template = json.loads((root / "deploy/aws/index-template.json").read_text(encoding="utf-8"))
    template["template"]["settings"]["number_of_replicas"] = 0
    admin.indices.put_index_template(name="test-cloudtrail", body=configure_template(template))
    role = json.loads((root / "deploy/aws/publisher-role.json").read_text(encoding="utf-8"))
    key = admin.security.create_api_key(name="synthetic-cloudtrail", expiration="1h", role_descriptors={"cloudtrail": role})
    events = json.loads((root / "tests/fixtures/cloudtrail_management.json").read_text(encoding="utf-8"))["events"]
    references = []
    with Elasticsearch(url, api_key=key["encoded"], request_timeout=10) as publisher:
        sink = ElasticsearchSink(publisher)
        for event in events:
            envelope = {"CloudTrailEvent": json.dumps(event), "EventId": event["eventID"], "EventTime": timestamp(event["eventTime"])}
            index, identifier, document = project_event(envelope, account="123456789012", region=event["awsRegion"], organization="fixture")
            document["event"]["ingested"] = "2099-01-01T00:00:00Z"
            test.assertTrue(sink.create(index, identifier, document))
            test.assertFalse(sink.create(index, identifier, document))
            references.append({"index": index, "id": identifier})
        for operation in (lambda: publisher.search(index="soc-cloud-aws-*"),
                          lambda: publisher.create(index="soc-host-raw-denied", id="denied", document={}),
                          lambda: publisher.index(index=references[0]["index"], id=references[0]["id"], document={})):
            with test.assertRaises(AuthorizationException):
                operation()
    admin.indices.refresh(index="soc-cloud-aws-*")
    reader = LogReader(monitor, secret="synthetic", principal="fixture")
    result = json.loads(reader.page([("collector", "cloudtrail"), ("os", "cloud")]))
    test.assertEqual(len(result["rows"]), 3)
    test.assertTrue(all(row["host_name"] is None and row["cloud_account"] == "123456789012" for row in result["rows"]))
    test.assertTrue(all(not row["received_at"].startswith("2099") for row in result["rows"]))
    test.assertEqual(len(json.loads(reader.page([("collector", "cloudtrail"), ("ip", "198.51.100.10")]))["rows"]), 1)
    test.assertEqual(json.loads(reader.page([("collector", "cloudtrail"), ("host", "123456789012")]))["rows"], [])
    for reference in references:
        detail = json.loads(reader.detail(list(reference.items())))
        test.assertEqual(detail["row"]["reference"], reference)
        test.assertEqual(detail["security"]["adapter"], "aws_cloudtrail_metadata_v1")
        test.assertNotIn("PRIVATE_CANARY", json.dumps(detail))
        test.assertNotIn("CloudTrailEvent", json.dumps(detail))
        test.assertIn("management_events_not_object_access", detail["security"]["limitations"])
        stored = admin.get(**reference)["_source"]
        test.assertNotIn("PRIVATE_CANARY", json.dumps(stored))
    iam = json.loads(reader.detail(list(references[1].items())))["security"]["fields"]
    test.assertEqual(iam["target_user"], "target-fixture")
    test.assertEqual(iam["resource_arns"], ["arn:aws:iam::123456789012:user/target-fixture"])
