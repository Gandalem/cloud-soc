"""Explicit server-side setup for activity timestamps and a separate reader role."""

from cloud_soc.portal.agent_status import INDICES

SETUP_INDICES = INDICES + ",soc-agent-health-*,soc-cloud-aws-*,soc-cloud-oci-*"

PIPELINE_ID = "cloud-soc-received-at-v1"
PIPELINE = {"description": "Server receipt time for collector activity; not a heartbeat",
            "processors": [{"set": {"field": "event.ingested", "value": "{{{_ingest.timestamp}}}", "override": True}}]}
RECEIPT_MAPPING = {"event": {"properties": {"ingested": {"type": "date"}}}}


class SetupConflict(RuntimeError):
    """Static diagnostics that are safe to display without upstream error bodies."""


def inspect_existing(client):
    # Filtering by final_pipeline omits indices that have never set it. Those
    # legacy indices are precisely the ones that need the receipt-time migration.
    settings = client.indices.get_settings(index=SETUP_INDICES, flat_settings=True,
                                          ignore_unavailable=True, allow_no_indices=True, expand_wildcards="open")
    mappings = client.indices.get_mapping(index=SETUP_INDICES, ignore_unavailable=True,
                                         allow_no_indices=True, expand_wildcards="open") if settings else {}
    for name, entry in settings.items():
        if not name.startswith(("soc-host-raw-", "soc-network-", "soc-agent-health-", "soc-cloud-aws-", "soc-cloud-oci-")):
            raise SetupConflict("Unexpected intake index; no automatic migration")
        if entry.get("settings", {}).get("index.final_pipeline", "_none") not in ("_none", PIPELINE_ID):
            raise SetupConflict("Existing final pipeline requires manual review; not overwritten")
        field = mappings.get(name, {}).get("mappings", {}).get("properties", {}).get("event", {}).get("properties", {}).get("ingested")
        if field and field.get("type") != "date":
            raise SetupConflict("Existing event.ingested mapping requires manual review")
    return sorted(settings)


def install_receipt_pipeline(client, indices):
    client.ingest.put_pipeline(id=PIPELINE_ID, body=PIPELINE)
    for name in indices:
        client.indices.put_mapping(index=name, properties=RECEIPT_MAPPING)
        client.indices.put_settings(index=name, settings={"index.final_pipeline": PIPELINE_ID})


def configure_template(template):
    template["template"]["settings"]["index.final_pipeline"] = PIPELINE_ID
    properties = template["template"]["mappings"]["properties"]
    properties.setdefault("event", {}).setdefault("properties", {})["ingested"] = {"type": "date"}
    return template


def configure_reader(client, password):
    client.security.put_role(name="cloud_soc_agent_monitor", cluster=[], indices=[{
        "names": INDICES.split(",") + ["soc-agent-health-*", "soc-cloud-aws-*", "soc-cloud-oci-*",
                  "soc-normalized-v1", "soc-processing-v1", "soc-pipeline-status", "security-alerts", "normalized-events", "raw-logs-*"],
        "privileges": ["read", "view_index_metadata"],
    }])
    client.security.put_user(username="cloud_soc_agent_monitor", password=password, roles=["cloud_soc_agent_monitor"])
