"""Bounded receipt-time windows with replay-safe writes and a durable checkpoint."""

from datetime import datetime, timedelta, timezone
from contextlib import closing
import sqlite3
from elasticsearch import ConflictError
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import INDICES, SOURCE_FIELDS, document_reference
from cloud_soc.portal.security_detail import DETAIL_FIELDS
from cloud_soc.processing.contract import normalize, NORMALIZED, RECORDS, STATUS

READ_FIELDS = list(SOURCE_FIELDS + DETAIL_FIELDS) + ["message", "event.timezone", "event.created"]


def checked(response):
    if response.get("timed_out") or response.get("terminated_early") or response.get("_shards", {}).get("failed", 0):
        raise RuntimeError("partial_search")
    return response


def resolve(client, patterns):
    response = client.indices.resolve_index(name=",".join(patterns), expand_wildcards="open")
    if response.get("aliases") or response.get("data_streams"):
        raise RuntimeError("index_alias_not_allowed")
    names = [item["name"] for item in response.get("indices", [])]
    if any(document_reference(name, "check") is None for name in names):
        raise RuntimeError("unexpected_index")
    return names


def scan(client, start, end, *, page_size=200, max_pages=1000):
    names = resolve(client, INDICES)
    if not names:
        return
    caps = client.field_caps(index=names, fields=["event.ingested"], include_unmapped=True)["fields"].get("event.ingested", {})
    if not caps or set(caps) - {"date", "date_nanos"}:
        raise RuntimeError("receipt_mapping_missing")
    pit, after = None, None
    try:
        pit = checked(client.open_point_in_time(index=names, keep_alive="2m", allow_partial_search_results=False))["id"]
        for _ in range(max_pages):
            response = checked(client.search(pit={"id": pit, "keep_alive": "2m"}, size=page_size,
                sort=["_shard_doc"], search_after=after, source=READ_FIELDS, track_total_hits=False,
                allow_partial_search_results=False, timeout="10s",
                query={"range": {"event.ingested": {"gte": start, "lt": end}}}))
            pit = response.get("pit_id", pit)
            hits = response["hits"]["hits"]
            if not hits:
                return
            cursor = hits[-1].get("sort")
            if not cursor or cursor == after:
                raise RuntimeError("cursor_not_advancing")
            yield from hits
            after = cursor
        raise RuntimeError("window_page_limit")
    finally:
        if pit:
            client.close_point_in_time(id=pit)


def create(client, index, identifier, document):
    try:
        client.create(index=index, id=identifier, document=document)
    except ConflictError:
        pass


def run_once(client, state_path, initial_start, *, now=None, scanner=scan):
    now = now or datetime.now(timezone.utc)
    initial = parse_time(initial_start)
    if initial is None or initial > now:
        raise ValueError("A past aware initial start is required")
    client = client.options(request_timeout=15, max_retries=0)
    with closing(sqlite3.connect(state_path, timeout=0)) as db:
        db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), checkpoint TEXT, last_success TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), initial_start TEXT NOT NULL)")
        configured = db.execute("SELECT initial_start FROM config WHERE id=1").fetchone()
        if configured and configured[0] != iso(initial):
            raise ValueError("Initial start cannot change for an existing state file")
        db.execute("INSERT OR IGNORE INTO config VALUES (1,?)", (iso(initial),))
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT checkpoint,last_success FROM state WHERE id=1").fetchone()
        checkpoint = parse_time(row[0]) if row else initial
        if checkpoint is None or checkpoint > now:
            raise ValueError("Invalid checkpoint or clock regression")
        start = max(initial, checkpoint - timedelta(minutes=15))
        end = min(now - timedelta(seconds=30), checkpoint + timedelta(minutes=5))
        counts = {"normalized": 0, "unsupported": 0, "invalid": 0}
        status = {"@timestamp": iso(now), "state": "running", "detection": "disabled_pending_approval",
                  "checkpoint": iso(checkpoint), "last_success": row[1] if row else None,
                  "range": {"start": iso(start), "end": iso(end)}, "counts": counts, "error": None}
        try:
            client.index(index=STATUS, id="normalizer", document=status)
            if end > checkpoint:
                for hit in scanner(client, iso(start), iso(end)):
                    identifier, record, event = normalize(hit, iso(now))
                    if event:
                        create(client, NORMALIZED, identifier, event)
                    create(client, RECORDS, identifier, record)
                    counts[record["status"]] += 1
                checkpoint = end
            completed = end > (parse_time(row[0]) if row else initial)
            status.update(state="success" if completed else "waiting", checkpoint=iso(checkpoint),
                          last_success=iso(now) if completed else (row[1] if row else None))
            client.index(index=STATUS, id="normalizer", document=status)
            db.execute("INSERT OR REPLACE INTO state VALUES (1,?,?)", (iso(checkpoint), status["last_success"]))
            db.commit()
            return status
        except Exception:
            db.rollback()
            status.update(state="failed", error="processing_failed", checkpoint=row[0] if row else iso(initial),
                          last_success=row[1] if row else None)
            try:
                client.index(index=STATUS, id="normalizer", document=status)
            except Exception:
                pass
            raise RuntimeError("processing_failed; checkpoint retained") from None
