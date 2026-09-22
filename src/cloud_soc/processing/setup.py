"""Explicit administrative preparation; the worker cannot create indices or keys."""

from cloud_soc.portal.log_contract import INDICES
from cloud_soc.processing.contract import NORMALIZED, RECORDS, STATUS

ROLE = {"cluster": [], "indices": [
    {"names": list(INDICES), "privileges": ["read", "view_index_metadata"]},
    {"names": [NORMALIZED, RECORDS], "privileges": ["create_doc"]},
    {"names": [STATUS], "privileges": ["index"]},
]}
DATE = {"type": "date"}
KEYWORD = {"type": "keyword", "ignore_above": 1024}


def prepare(client):
    mappings = {
        NORMALIZED: {"@timestamp": DATE, "organization": {"properties": {"id": KEYWORD}},
                     "event": {"properties": {"ingested": DATE, **{k: KEYWORD for k in ("kind", "category", "action", "outcome", "code", "dataset", "provider")}}},
                     **{name: {"properties": {"ip": {"type": "ip"}, "port": {"type": "long"}}} for name in ("source", "destination")},
                     **{name: {"properties": {"id": KEYWORD, "name": KEYWORD}} for name in ("host", "user")},
                     "cloud": {"properties": {"provider": KEYWORD, "region": KEYWORD, "account": {"properties": {"id": KEYWORD}}}},
                     "network": {"properties": {"protocol": KEYWORD, "transport": KEYWORD}},
                     "process": {"properties": {"pid": {"type": "long"}, "executable": KEYWORD}},
                     "cloud_soc": {"properties": {"normalizer_version": KEYWORD, "parse_status": KEYWORD,
                                                    "detail": {"type": "object", "enabled": False},
                                                    "provenance": {"type": "object", "enabled": False}}}},
        RECORDS: {"@timestamp": DATE, "event": {"properties": {"ingested": DATE}},
                  **{k: KEYWORD for k in ("version", "status", "reason", "adapter")},
                  "raw": {"type": "object", "enabled": False}, "normalized": {"type": "object", "enabled": False}},
        STATUS: {"@timestamp": DATE, "last_success": DATE, "checkpoint": DATE,
                 "state": KEYWORD, "error": KEYWORD, "detection": KEYWORD},
    }
    for name, properties in mappings.items():
        if not client.indices.exists(index=name):
            client.indices.create(index=name, settings={"number_of_shards": 1, "number_of_replicas": 0},
                                  mappings={"dynamic": False, "_meta": {"contract": name}, "properties": properties})
        else:
            found = client.indices.get_mapping(index=name)
            if set(found) != {name} or found[name]["mappings"].get("_meta", {}).get("contract") != name:
                raise ValueError("Processing mapping conflict; manual review required")
    client.security.put_role(name="cloud_soc_normalizer", **ROLE)
