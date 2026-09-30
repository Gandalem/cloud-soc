"""Internal read-only receipt/reference audit; never a loss counter or replayer."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import time
from urllib.parse import urlsplit
import uuid


INDICES = "soc-host-raw-windows-*"
MAX_REFERENCES = 200
REFERENCE_FIELDS = {
    "channel": ("winlog", "channel"), "provider": ("winlog", "provider_name"),
    "record_id": ("winlog", "record_id"), "event_code": ("event", "code"),
}
# Fixed source-based keyword fields cover text/keyword and ignored-field drift.
REFERENCE_RUNTIME = {
    "soc_loss_" + name: {"type": "keyword", "script": {"source": (
        "def parent=params._source.get('" + parent + "'); "
        "if (!(parent instanceof Map)) return; def v=parent.get('" + field + "'); "
        "if (v instanceof String && v.length()<=256) emit(v); "
        "else if (v instanceof Number) emit(v.toString());"
    )}} for name, (parent, field) in REFERENCE_FIELDS.items()
}


class AuditError(Exception):
    """Static, credential- and event-free diagnostic messages."""


def instant(value):
    if not isinstance(value, str) or not re.fullmatch(
            r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})", value):
        raise AuditError("Use explicit ISO-8601 timestamps with timezone.")
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00")).astimezone(timezone.utc)
    except ValueError:
        raise AuditError("Invalid timestamp.") from None


def iso(value):
    return value.isoformat().replace("+00:00", "Z")


def references(values):
    if not isinstance(values, list) or len(values) > MAX_REFERENCES:
        raise AuditError("At most 200 metadata references are allowed.")
    seen = set()
    result = []
    for item in values:
        if not isinstance(item, dict) or set(item) != {"channel", "record_id", "provider", "event_code", "occurred_at"}:
            raise AuditError("Only reference metadata is allowed; event bodies are forbidden.")
        for name in ("channel", "provider", "event_code"):
            value = item[name]
            if not isinstance(value, str) or not 1 <= len(value) <= 256 or any(ord(c) < 32 for c in value):
                raise AuditError("Invalid reference metadata.")
        if (type(item["record_id"]) is not int or not 0 < item["record_id"] <= 9223372036854775807
                or not re.fullmatch(r"\d{1,10}", item["event_code"])):
            raise AuditError("Invalid event/record number.")
        clean = {**item, "occurred_at": iso(instant(item["occurred_at"]))}
        key = json.dumps(clean, sort_keys=True, separators=(",", ":"))
        if key not in seen:
            seen.add(key)
            result.append(clean)
    return result


def count(client, filters, deadline, *, runtime=None):
    if time.monotonic() >= deadline:
        raise AuditError("Audit time limit exceeded; no complete result.")
    response = client.search(
        index=INDICES, query={"bool": {"filter": filters}}, size=0, source=False,
        track_total_hits=True, timeout="5s", allow_partial_search_results=False,
        ignore_unavailable=True, allow_no_indices=True,
        **({"runtime_mappings": runtime} if runtime is not None else {}),
    )
    if time.monotonic() >= deadline:
        raise AuditError("Audit time limit exceeded; no complete result.")
    try:
        shards = response["_shards"]
        total = response["hits"]["total"]
        if (response["timed_out"] is not False or type(shards["failed"]) is not int or shards["failed"] != 0
                or type(shards["total"]) is not int or shards["total"] < 0
                or type(shards["successful"]) is not int or shards["successful"] != shards["total"]
                or total["relation"] != "eq" or type(total["value"]) is not int or total["value"] < 0):
            raise ValueError
        return total["value"], shards["total"] > 0
    except (KeyError, TypeError, ValueError):
        raise AuditError("Incomplete search response; do not infer missing events.") from None


def inspect_window(client, agent_id, since, until, candidates=None):
    try:
        if not isinstance(agent_id, str) or str(uuid.UUID(agent_id)) != agent_id:
            raise ValueError
    except (ValueError, AttributeError):
        raise AuditError("Use the exact collector UUID.") from None
    start, end = instant(since), instant(until)
    if not 0 < (end - start).total_seconds() <= 31 * 86400:
        raise AuditError("Invalid receipt window (maximum 31 days).")
    refs = references(candidates if candidates is not None else [])
    deadline = time.monotonic() + 60
    agent = {"term": {"agent.id": agent_id}}
    received, indices_present = count(client, [agent, {"range": {"event.ingested": {"gte": iso(start), "lt": iso(end)}}}], deadline)
    report = {
        "schema": 1, "checked_at": iso(datetime.now(timezone.utc)), "mode": "read_only",
        "scope": INDICES, "agent_ref": hashlib.sha256(agent_id.encode()).hexdigest()[:12],
        "receipt_since": iso(start), "receipt_until": iso(end), "stored_documents_in_receipt_window": received,
        "indices_present": indices_present, "reference_count": len(refs), "reference_matches": 0,
        "reference_not_found": 0, "multiple_reference_matches": 0,
        "identity_verified": False, "complete_loss_count": False, "historical_loss_count": None,
        "recovery_ready": False, "replay_performed": False,
    }
    for reference in refs:
        filters = [agent, {"term": {"@timestamp": reference["occurred_at"]}},
                   *({"term": {"soc_loss_" + key: str(reference[key])}} for key in REFERENCE_FIELDS)]
        found, _ = count(client, filters, deadline, runtime=REFERENCE_RUNTIME)
        report["reference_matches" if found else "reference_not_found"] += 1
        if found > 1:
            report["multiple_reference_matches"] += 1
    report["interpretation"] = "Reference matches do not prove identical content; no match does not prove loss."
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description="Internal read-only receipt audit; no event export or replay")
    parser.add_argument("--agent-id", required=True)
    parser.add_argument("--since", required=True)
    parser.add_argument("--until", required=True)
    parser.add_argument("--references-stdin", action="store_true", help="Read at most 200 metadata-only references from stdin")
    args = parser.parse_args(argv)
    client = None
    try:
        candidates = []
        if args.references_stdin:
            raw = sys.stdin.buffer.read(131073)
            if len(raw) > 131072:
                raise AuditError("Reference input exceeded the limit.")
            candidates = json.loads(raw)
        # Validate all input before opening the client or reading credentials.
        class NoNetwork:
            def search(self, **kwargs):
                return {"timed_out": False, "_shards": {"failed": 0, "total": 0, "successful": 0},
                        "hits": {"total": {"relation": "eq", "value": 0}}}
        inspect_window(NoNetwork(), args.agent_id, args.since, args.until, candidates)
        endpoint = os.environ["SOC_INTERNAL_ES_URL"]
        url = urlsplit(endpoint)
        if (url.scheme != "https" or not url.hostname or url.username or url.password
                or url.path not in ("", "/") or url.query or url.fragment):
            raise AuditError("A credential-free HTTPS Elasticsearch origin is required.")
        with Path(os.environ["SOC_MONITOR_PASSWORD_FILE"]).open("rb") as stream:
            password = stream.read(4097)
        if not 1 <= len(password) <= 4096 or not password.strip():
            raise AuditError("Invalid monitor credential file.")
        from elasticsearch import Elasticsearch
        client = Elasticsearch(endpoint, basic_auth=("cloud_soc_agent_monitor", password.decode().strip()),
                               ca_certs=os.environ["SOC_CA_FILE"], request_timeout=10, max_retries=0)
        del password
        print(json.dumps(inspect_window(client, args.agent_id, args.since, args.until, candidates)))
        return 0
    except Exception:
        print("Read-only audit failed. Check input, TLS, monitor access and search completeness; no replay occurred.", file=sys.stderr)
        return 1
    finally:
        if client is not None:
            client.close()


if __name__ == "__main__":
    raise SystemExit(main())
