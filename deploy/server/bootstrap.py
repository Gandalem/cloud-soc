"""Idempotent, explicit central initialization; never processes collected events."""

import json
import os
from pathlib import Path

from elasticsearch import Elasticsearch


def main():
    def secret(name):
        return (Path("/run/secrets") / name).read_text(encoding="utf-8").strip()

    with Elasticsearch(os.environ["SOC_INTERNAL_ES_URL"], ca_certs=os.environ["SOC_CA_FILE"],
                       basic_auth=("elastic", secret("elastic_password")), request_timeout=30) as client:
        client.info()
        client.security.change_password(username="kibana_system", password=secret("kibana_password"))
        client.security.put_role(name="cloud_soc_issuer", cluster=["monitor", "manage_own_api_key"],
                                 indices=[{"names": ["soc-host-raw-*", "soc-network-*"], "privileges": ["auto_configure", "create_doc"]}])
        client.security.put_user(username="cloud_soc_issuer", password=secret("issuer_password"), roles=["cloud_soc_issuer"])
        client.security.put_role(name="cloud_soc_reader", cluster=["monitor"], indices=[{
            "names": ["soc-host-raw-*", "soc-network-*", "raw-logs-*", "normalized-events", "security-alerts"],
            "privileges": ["read", "view_index_metadata"],
        }])
        client.security.put_user(username="cloud_soc_analyst", password=secret("analyst_password"), roles=["cloud_soc_reader", "kibana_admin"])
        for name, filename in [("cloud-soc-host", "index-template.json"), ("cloud-soc-network", "network-index-template.json")]:
            template = json.loads((Path("/app/deploy/agents") / filename).read_text(encoding="utf-8"))
            template["template"]["settings"]["number_of_replicas"] = 0
            client.indices.put_index_template(name=name, body=template)
        print("Central users and isolated intake templates prepared. No rules, live events, retention policy or agent services were changed.")


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # Do not print upstream request bodies containing credentials.
        raise SystemExit(f"Central initialization failed ({type(error).__name__}); inspect connectivity and protected settings.") from None
