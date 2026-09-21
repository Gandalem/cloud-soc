"""Complete snapshot reads. This is batch pagination, not a durable checkpoint."""

import logging
from typing import Any

from elasticsearch import Elasticsearch

LOGGER = logging.getLogger(__name__)


class IncompleteSearchError(RuntimeError):
    """A partial snapshot must never be used as a complete detection input."""


def fetch_all_hits(
    client: Elasticsearch, *, index: str, page_size: int = 1000,
) -> list[dict[str, Any]]:
    if type(page_size) is not int or not 1 <= page_size <= 10000:
        raise ValueError("page_size must be between 1 and 10000")

    opened = client.open_point_in_time(
        index=index, keep_alive="2m", allow_partial_search_results=False,
    )
    pit_id = opened["id"]
    failed = True
    try:
        if opened.get("_shards", {}).get("failed", 0):
            raise IncompleteSearchError("PIT opened with failed shards")
        hits: list[dict[str, Any]] = []
        cursor = None
        while True:
            request: dict[str, Any] = {
                "pit": {"id": pit_id, "keep_alive": "2m"},
                "size": page_size,
                "query": {"match_all": {}},
                # _shard_doc is unique and stable within this PIT.
                "sort": [{"_shard_doc": "asc"}],
                "track_total_hits": False,
                "allow_partial_search_results": False,
            }
            if cursor is not None:
                request["search_after"] = cursor
            response = client.search(**request)
            pit_id = response.get("pit_id", pit_id)
            if (response.get("timed_out") or response.get("terminated_early")
                    or response.get("_shards", {}).get("failed", 0)):
                raise IncompleteSearchError("Elasticsearch returned a partial search")
            page = response["hits"]["hits"]
            if not page:
                failed = False
                return hits
            next_cursor = page[-1].get("sort")
            if not next_cursor or next_cursor == cursor:
                raise IncompleteSearchError("Missing or non-advancing search_after cursor")
            hits.extend(page)
            cursor = next_cursor
    finally:
        try:
            client.close_point_in_time(id=pit_id)
        except Exception:
            if not failed:
                raise
            # Preserve the original read failure; the PIT also has a bounded TTL.
            LOGGER.warning("PIT cleanup failed after an unsuccessful read")
