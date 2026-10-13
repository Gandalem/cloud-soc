"""Plan a narrowly scoped reader repair without replacing existing privileges."""
from copy import deepcopy
import fnmatch
import hashlib
import json

ROLE = "cloud_soc_agent_monitor"
HISTORY = ("soc-normalized-history-v1", "soc-processing-history-v1")
FIELDS = {"cluster", "indices", "applications", "run_as", "metadata", "description", "global",
          "remote_indices", "remote_cluster", "restriction", "transient_metadata"}


def digest(role):
    return hashlib.sha256(json.dumps(role, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def history_plan(role):
    if not isinstance(role, dict) or set(role) - FIELDS or not isinstance(role.get("indices"), list):
        raise ValueError("Unsupported reader role; no automatic replacement")
    for entry in role["indices"]:
        if (not isinstance(entry, dict) or not isinstance(entry.get("names"), list)
                or not isinstance(entry.get("privileges"), list)
                or not all(isinstance(value, str) for value in entry["names"] + entry["privileges"])):
            raise ValueError("Unsupported reader index grant; no automatic replacement")
        if (any(fnmatch.fnmatchcase(name, pattern) for name in HISTORY for pattern in entry["names"])
                and ("query" in entry or "field_security" in entry)):
            raise ValueError("History restrictions require manual review; no unrestricted grant appended")
    missing = [name for name in HISTORY if not all(any(
        privilege in entry["privileges"] and any(fnmatch.fnmatchcase(name, pattern) for pattern in entry["names"])
        for entry in role["indices"]) for privilege in ("read", "view_index_metadata"))]
    updated = {key: deepcopy(value) for key, value in role.items() if key != "transient_metadata"}
    if missing:
        updated["indices"].append({"names": missing, "privileges": ["read", "view_index_metadata"]})
    return {"role_name": ROLE, "before_sha256": digest(role), "added_indices": missing,
            "requires_change": bool(missing), "role": updated}


def restore_history_reader(client, expected_before):
    role = client.security.get_role(name=ROLE)[ROLE]
    plan = history_plan(role)
    if plan["before_sha256"] != expected_before:
        raise ValueError("Reader role changed after review; no write performed")
    if plan["requires_change"]:
        client.security.put_role(name=ROLE, body=plan["role"])
    return {key: value for key, value in plan.items() if key != "role"}
