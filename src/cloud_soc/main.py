import argparse
from dataclasses import dataclass
import hashlib
import json
import logging
import time
from typing import Any

from elasticsearch import ApiError, ConnectionError, ConnectionTimeout, Elasticsearch

from cloud_soc.detection.engine import run_detection_from_elasticsearch
from cloud_soc.elastic.client import create_elasticsearch_client
from cloud_soc.elastic.pagination import IncompleteSearchError
from cloud_soc.elastic.repository import (
    ProvenanceMappingError,
    ensure_normalized_index,
    ensure_provenance_mapping,
    ensure_security_alerts_index,
    fetch_raw_events,
    save_normalized_event,
    save_security_alert,
)
from cloud_soc.normalizers.ecs import normalize_linux_auth_event
from cloud_soc.normalizers.time_context import parse_utc_offset, raw_time_context
from cloud_soc.parsers.linux_auth import parse_linux_auth_line

RAW_INDEX_PATTERN = "raw-logs-*"
NORMALIZED_INDEX = "normalized-events"
ALERT_INDEX = "security-alerts"
LOGGER = logging.getLogger(__name__)


@dataclass
class ProcessingStats:
    created: int = 0
    existing: int = 0
    unsupported: int = 0
    invalid: int = 0


@dataclass
class PipelineStats:
    raw: ProcessingStats
    alerts_created: int = 0
    normalized_invalid: int = 0

    @property
    def has_errors(self) -> bool:
        return bool(self.raw.invalid or self.normalized_invalid)


def make_stable_id(*values: str) -> str:
    # Preserve existing normalized document IDs; do not reindex old data implicitly.
    return hashlib.sha256("|".join(values).encode("utf-8")).hexdigest()


def make_alert_id(detection: dict[str, Any]) -> str:
    identity = {
        "rule_id": detection["rule_id"],
        "rule_version": detection["rule_version"],
        "group": detection["group"],
        "window_start": detection["window_start"],
        "window_end": detection["window_end"],
        "evidence": detection["evidence"],
    }
    return hashlib.sha256(json.dumps(
        identity, sort_keys=True, ensure_ascii=True, separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def build_security_alert(detection: dict[str, Any]) -> dict[str, Any]:
    alert = detection.get("alert", {})
    organization_id = detection["organization_id"]
    if (not isinstance(organization_id, str) or not organization_id.strip()
            or detection["group"].get("organization.id") != organization_id):
        raise ValueError("Detection organization scope is missing or inconsistent")
    document = {
        "@timestamp": detection["window_end"],
        "event": {"kind": "alert", "category": [alert.get("category", "authentication")]},
        "rule": {"id": detection["rule_id"], "name": detection["rule_name"]},
        "organization": {"id": organization_id},
        "cloud_soc": {
            "alert_title": alert.get("title", detection["rule_name"]),
            "severity": detection["severity"],
            "event_count": detection["event_count"],
            "threshold": detection["threshold"],
            "time_window_seconds": detection["time_window_seconds"],
            "window_start": detection["window_start"],
            "window_end": detection["window_end"],
            # Stored in _source only: do not dynamically map arbitrary rule values.
            "provenance": {
                "schema_version": 1,
                "engine_version": detection["engine_version"],
                "rule_version": detection["rule_version"],
                "rule_snapshot": detection["rule_snapshot"],
                "evidence": detection["evidence"],
                "evidence_status": detection["evidence_status"],
            },
        },
        "message": alert.get("message", detection["rule_name"]),
        "tags": alert.get("tags", []),
        "mitre": detection.get("mitre", {}),
    }
    if source_ip := detection["group"].get("source.ip"):
        document["source"] = {"ip": source_ip}
    return document


def refresh_complete(client: Elasticsearch, index: str) -> None:
    response = client.indices.refresh(index=index)
    if response.get("_shards", {}).get("failed", 0):
        raise IncompleteSearchError(f"Index refresh was incomplete: {index}")


def process_raw_logs(client: Elasticsearch, *, source_timezone: str = "UTC") -> ProcessingStats:
    # Complete the read before writes, so a partial search cannot look successful.
    raw_events = fetch_raw_events(client=client, index_pattern=RAW_INDEX_PATTERN)
    stats = ProcessingStats()
    for hit in raw_events:
        try:
            source = hit["_source"]
            if not isinstance(source, dict):
                raise ValueError("Raw _source must be an object")
            labels = source.get("labels", {})
            if not isinstance(labels, dict) or labels.get("log_source") != "linux_auth":
                stats.unsupported += 1
                continue
            message = source.get("message")
            if not isinstance(message, str):
                raise ValueError("linux_auth message must be a string")
            parsed = parse_linux_auth_line(message)
            if parsed is None:
                stats.unsupported += 1
                continue
            organization = source.get("organization")
            if not isinstance(organization, dict):
                raise ValueError("Missing organization object")
            organization_id = organization.get("id")
            reference, zone, time_metadata = raw_time_context(
                source, default_timezone=source_timezone,
            )
            normalized = normalize_linux_auth_event(
                parsed, organization_id=organization_id,
                reference_time=reference, source_timezone=zone,
            )
            normalized.setdefault("cloud_soc", {})["provenance"] = {
                "schema_version": 1,
                "raw": {"index": hit["_index"], "id": hit["_id"]},
                "time": time_metadata,
            }
            normalized_id = make_stable_id(hit["_index"], hit["_id"])
        except (KeyError, TypeError, ValueError) as error:
            stats.invalid += 1
            # References are sufficient to investigate; avoid echoing raw log content.
            LOGGER.error("Invalid raw document index=%r id=%r (%s)",
                         hit.get("_index"), hit.get("_id"), type(error).__name__)
            continue

        # Infrastructure failures must propagate, not masquerade as malformed input.
        response = save_normalized_event(
            client=client, index_name=NORMALIZED_INDEX, event=normalized,
            document_id=normalized_id, refresh=False, index_prepared=True,
        )
        if response["result"] == "created":
            stats.created += 1
        else:
            stats.existing += 1
    if stats.created or stats.existing:
        refresh_complete(client, NORMALIZED_INDEX)
    return stats


def process_detections(client: Elasticsearch, *, rejected: list[dict[str, Any]]) -> int:
    detections = run_detection_from_elasticsearch(
        client=client, index_name=NORMALIZED_INDEX, rejected=rejected,
    )
    created = 0
    for detection in detections:
        response = save_security_alert(
            client=client, index_name=ALERT_INDEX, alert=build_security_alert(detection),
            document_id=make_alert_id(detection), refresh=False, index_prepared=True,
        )
        if response["result"] == "created":
            created += 1
    if detections:
        refresh_complete(client, ALERT_INDEX)
    for reference in rejected:
        LOGGER.error("Invalid normalized document index=%r id=%r",
                     reference.get("index"), reference.get("document_id"))
    return created


def prepare_indices(client: Elasticsearch, *, apply_mappings: bool = False) -> None:
    ensure_normalized_index(client=client, index_name=NORMALIZED_INDEX)
    ensure_security_alerts_index(client=client, index_name=ALERT_INDEX)
    for index in (NORMALIZED_INDEX, ALERT_INDEX):
        ensure_provenance_mapping(client, index, apply=apply_mappings)


def run_pipeline_once(client: Elasticsearch, *, source_timezone: str = "UTC") -> PipelineStats:
    prepare_indices(client)
    raw = process_raw_logs(client, source_timezone=source_timezone)
    rejected: list[dict[str, Any]] = []
    alerts_created = process_detections(client, rejected=rejected)
    stats = PipelineStats(raw, alerts_created, len(rejected))
    print(
        f"Pipeline {'DEGRADED' if stats.has_errors else 'OK'}: "
        f"normalized_created={raw.created} existing={raw.existing} "
        f"unsupported={raw.unsupported} raw_invalid={raw.invalid} "
        f"normalized_invalid={len(rejected)} alerts_created={alerts_created}"
    )
    return stats


def is_transient_error(error: Exception) -> bool:
    return isinstance(error, (ConnectionError, ConnectionTimeout)) or (
        isinstance(error, ApiError) and error.status_code in (429, 502, 503, 504)
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--watch", action="store_true", help="Repeat pipeline batches")
    parser.add_argument("--interval", type=int, default=5, help="Seconds between batches")
    parser.add_argument("--source-timezone", default="UTC", help="Fallback syslog timezone: UTC or +09:00")
    parser.add_argument("--prepare-lineage-mappings", action="store_true",
                        help="Explicitly add provenance mappings, then exit without processing logs")
    args = parser.parse_args()
    if args.interval < 1:
        parser.error("--interval must be positive")
    if args.watch and args.prepare_lineage_mappings:
        parser.error("--prepare-lineage-mappings cannot be combined with --watch")
    try:
        parse_utc_offset(args.source_timezone)
    except ValueError as error:
        parser.error(str(error))

    client = None
    exit_code = 0
    try:
        client = create_elasticsearch_client()
        if args.prepare_lineage_mappings:
            prepare_indices(client, apply_mappings=True)
            print("Provenance mappings prepared; no log documents were processed.")
        else:
            consecutive_failures = 0
            while True:
                try:
                    stats = run_pipeline_once(client, source_timezone=args.source_timezone)
                except Exception as error:
                    consecutive_failures += 1
                    if (not args.watch or not is_transient_error(error)
                            or consecutive_failures >= 3):
                        raise
                    delay = min(args.interval * (2 ** (consecutive_failures - 1)), 60)
                    LOGGER.warning("Transient %s; retry %d/2 in %ds",
                                   type(error).__name__, consecutive_failures, delay)
                    time.sleep(delay)
                    continue
                consecutive_failures = 0
                if not args.watch:
                    exit_code = 2 if stats.has_errors else 0
                    break
                if stats.has_errors:
                    LOGGER.error("Batch degraded; rejected documents remain in raw/normalized indices")
                time.sleep(args.interval)
    except KeyboardInterrupt:
        exit_code = 130
    except Exception as error:
        if isinstance(error, ProvenanceMappingError):
            LOGGER.error("%s", error)
        # Avoid dumping ES request bodies, which may contain sensitive source logs.
        LOGGER.error("Pipeline failed (%s). Check connectivity, index permissions, rules, "
                     "and docs/pipeline_reliability.md before retrying.", type(error).__name__)
        exit_code = 1
    finally:
        if client is not None:
            try:
                client.close()
            except Exception:
                LOGGER.error("Elasticsearch client cleanup failed")
                exit_code = 1
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
