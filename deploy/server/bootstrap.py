"""Idempotent, explicit central initialization; never processes collected events."""

import json
import os
from pathlib import Path

from elasticsearch import Elasticsearch
from cloud_soc.portal.status_setup import SetupConflict, inspect_existing, install_receipt_pipeline, configure_template, configure_reader
from cloud_soc.processing.setup import prepare as prepare_processing


def main():
    def secret(name):
        return (Path("/run/secrets") / name).read_text(encoding="utf-8").strip()

    with Elasticsearch(os.environ["SOC_INTERNAL_ES_URL"], ca_certs=os.environ["SOC_CA_FILE"],
                       basic_auth=("elastic", secret("elastic_password")), request_timeout=30) as client:
        client.info()
        existing = inspect_existing(client)
        monitor_password = secret("monitor_password")
        install_receipt_pipeline(client, existing)
        client.security.change_password(username="kibana_system", password=secret("kibana_password"))
        client.security.put_role(name="cloud_soc_issuer", cluster=["monitor", "manage_own_api_key"],
                                 indices=[{"names": ["soc-host-raw-*", "soc-network-*", "soc-agent-health-*"], "privileges": ["auto_configure", "create_doc"]}])
        client.security.put_user(username="cloud_soc_issuer", password=secret("issuer_password"), roles=["cloud_soc_issuer"])
        client.security.put_role(name="cloud_soc_reader", cluster=["monitor"], indices=[{
            "names": ["soc-host-raw-*", "soc-network-*", "soc-cloud-aws-*", "soc-cloud-oci-*", "raw-logs-*", "normalized-events", "security-alerts"],
            "privileges": ["read", "view_index_metadata"],
        }])
        client.security.put_user(username="cloud_soc_analyst", password=secret("analyst_password"), roles=["cloud_soc_reader", "kibana_admin"])
        for name, filename in [("cloud-soc-host", "index-template.json"), ("cloud-soc-network", "network-index-template.json"), ("cloud-soc-health", "health-index-template.json")]:
            template = json.loads((Path("/app/deploy/agents") / filename).read_text(encoding="utf-8"))
            template["template"]["settings"]["number_of_replicas"] = 0
            client.indices.put_index_template(name=name, body=configure_template(template))
        configure_reader(client, monitor_password)
        prepare_processing(client)
        cloud_template = json.loads(Path("/app/deploy/aws/index-template.json").read_text(encoding="utf-8"))
        cloud_template["template"]["settings"]["number_of_replicas"] = 0
        client.indices.put_index_template(name="cloud-soc-aws", body=configure_template(cloud_template))
        cloud_role = json.loads(Path("/app/deploy/aws/publisher-role.json").read_text(encoding="utf-8"))
        client.security.put_role(name="cloud_soc_cloudtrail_writer", **cloud_role)
        oci_template = json.loads(Path("/app/deploy/oci/index-template.json").read_text(encoding="utf-8"))
        oci_template["template"]["settings"]["number_of_replicas"] = 0
        client.indices.put_index_template(name="cloud-soc-oci", body=configure_template(oci_template))
        oci_role = json.loads(Path("/app/deploy/oci/publisher-role.json").read_text(encoding="utf-8"))
        client.security.put_role(name="cloud_soc_oci_audit_writer", **oci_role)
        print("Central users, intake templates, receipt pipeline and normalization indices/role prepared. Existing documents were not rewritten; no rules, retention or agent services changed. Normalizer not started.")


if __name__ == "__main__":
    try:
        main()
    except SetupConflict as error:
        raise SystemExit(f"Central initialization blocked: {error}.") from None
    except Exception as error:
        # Do not print upstream request bodies containing credentials.
        raise SystemExit(f"Central initialization failed ({type(error).__name__}); inspect connectivity and protected settings.") from None
