import time as time
import logging
from typing import Any

from elasticsearch import ApiError, ConnectionError, ConnectionTimeout, Elasticsearch

from cloud_soc.pipeline.stats import ProcessingStats, PipelineStats
from cloud_soc.pipeline.alerts import make_stable_id, make_alert_id, build_security_alert
from cloud_soc.detection.engine import run_detection_from_elasticsearch
from cloud_soc.elastic.client import create_elasticsearch_client as create_elasticsearch_client
from cloud_soc.elastic.pagination import IncompleteSearchError
from cloud_soc.elastic.repository import (
    ProvenanceMappingError as ProvenanceMappingError,
    ensure_normalized_index,
    ensure_provenance_mapping,
    ensure_security_alerts_index,
    fetch_raw_events,
    save_normalized_event,
    save_security_alert,
)
from cloud_soc.normalizers.ecs import normalize_linux_auth_event
from cloud_soc.normalizers.time_context import raw_time_context, parse_utc_offset as parse_utc_offset
from cloud_soc.parsers.linux_auth import parse_linux_auth_line

RAW_INDEX_PATTERN = "raw-logs-*"
NORMALIZED_INDEX = "normalized-events"
ALERT_INDEX = "security-alerts"
LOGGER = logging.getLogger(__name__)


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
    from cloud_soc.cli import main as cli_main
    return cli_main()
