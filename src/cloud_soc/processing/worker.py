"""Bounded receipt-time windows with replay-safe writes and a durable checkpoint."""

from datetime import datetime, timedelta, timezone
from contextlib import closing
import sqlite3
import sys
import json
import re
from elasticsearch import ConflictError
from cloud_soc.portal.agent_status import iso, parse_time
from cloud_soc.portal.log_contract import INDICES, SOURCE_FIELDS, document_reference
from cloud_soc.portal.security_detail import DETAIL_FIELDS
from cloud_soc.processing.contract import normalize, NORMALIZED, RECORDS, STATUS
from cloud_soc.elastic.index_scope import index_batches
from cloud_soc.processing import continuation
from cloud_soc.web.scope import NORMALIZER_VERSION as SITE_VERSION, LEGACY_VERSION
from cloud_soc.portal.log_contract import field

READ_FIELDS = list(SOURCE_FIELDS + DETAIL_FIELDS) + ["message", "event.timezone", "event.created",
    "log.syslog.appname", "process.name", "journald.syslog.identifier", "journald.process.name", "journald.pid"]


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
    return list(dict.fromkeys(names))


def scan(client, start, end, *, page_size=200, max_pages=1000):
    names = resolve(client, INDICES)
    if not names:
        return
    batches = list(index_batches(names))
    for batch in batches:
        caps = client.field_caps(index=batch, fields=["event.ingested"], include_unmapped=True)["fields"].get("event.ingested", {})
        if not caps or set(caps) - {"date", "date_nanos"}:
            raise RuntimeError("receipt_mapping_missing")
    pages = 0
    for batch in batches:
        for hits in scan_batch(client, batch, start, end, page_size=page_size, max_pages=max_pages - pages):
            pages += 1
            yield from hits


def scan_batch(client, names, start, end, *, page_size, max_pages):
    pit, after = None, None
    try:
        opened = client.open_point_in_time(index=names, keep_alive="2m", allow_partial_search_results=False)
        pit = opened["id"]
        checked(opened)
        for _ in range(max_pages):
            response = client.search(pit={"id": pit, "keep_alive": "2m"}, size=page_size,
                sort=["_shard_doc"], search_after=after, source=READ_FIELDS, track_total_hits=False,
                allow_partial_search_results=False, timeout="10s",
                query={"range": {"event.ingested": {"gte": start, "lt": end}}})
            pit = response.get("pit_id", pit)
            checked(response)
            hits = response["hits"]["hits"]
            if not hits:
                return
            cursor = hits[-1].get("sort")
            if not cursor or cursor == after:
                raise RuntimeError("cursor_not_advancing")
            yield hits
            after = cursor
        raise RuntimeError("window_page_limit")
    finally:
        if pit:
            failing = sys.exc_info()[0] is not None
            try:
                client.close_point_in_time(id=pit)
            except Exception:
                if not failing:
                    raise


def create(client, index, identifier, document):
    try:
        client.create(index=index, id=identifier, document=document)
    except ConflictError:
        pass


def create_batch(client, documents):
    """Immutable creates; a partial failure must retain the window checkpoint."""
    if not documents:
        return
    operations = []
    for index, identifier, document in documents:
        operations.extend([{"create": {"_index": index, "_id": identifier}}, document])
    response = client.bulk(operations=operations)
    items = response.get("items")
    if not isinstance(items, list) or len(items) != len(documents):
        raise RuntimeError("partial_bulk_response")
    for item in items:
        result = item.get("create", {})
        status = result.get("status")
        if status == 201 and not result.get("error"):
            continue
        if status == 409 and result.get("error", {}).get("type") == "version_conflict_engine_exception":
            continue
        raise RuntimeError("normalization_bulk_failed")


def run_once(client, state_path, initial_start, *, now=None, scanner=None, max_pages=1000, ssh_v2_start=None, web_site_v2_start=None,
             window_minutes=5, status_id='normalizer', source_indices=None,
             normalized_index=NORMALIZED, records_index=RECORDS, status_index=STATUS,
             receipt_lag_seconds=30, overlap_seconds=900):
    now = now or datetime.now(timezone.utc)
    initial = parse_time(initial_start)
    if (initial is None or initial > now or type(max_pages) is not int or not 1 <= max_pages <= 10000
            or type(window_minutes) is not int or not 1 <= window_minutes <= 60
            or status_id not in ('normalizer', 'normalizer-priority')
            or type(receipt_lag_seconds) is not int or not 0 <= receipt_lag_seconds <= 300
            or type(overlap_seconds) is not int or not 60 <= overlap_seconds <= 86400):
        raise ValueError("A past aware initial start is required")
    ssh_start = parse_time(ssh_v2_start) if ssh_v2_start is not None else None
    if ssh_v2_start is not None and (ssh_start is None or not initial <= ssh_start <= now):
        raise ValueError("An aware SSH adapter start within the configured receipt range is required")
    web_start = parse_time(web_site_v2_start) if web_site_v2_start is not None else None
    if web_site_v2_start is not None and (web_start is None or not initial <= web_start <= now):
        raise ValueError('An aware site adapter start within the receipt range is required')
    if source_indices is not None:
        if (not isinstance(source_indices, (list, tuple)) or not source_indices
                or any(not isinstance(n, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,254}', n)
                       or document_reference(n, 'scope') is None for n in source_indices)):
            raise ValueError('Explicit source scope must contain concrete raw indices')
    for target in (normalized_index, records_index, status_index):
        if not isinstance(target, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_.-]{0,254}', target):
            raise ValueError('Concrete processing target required')
    scope = json.dumps([list(source_indices) if source_indices is not None else None,
                        normalized_index, records_index, status_index], separators=(',', ':'))
    client = client.options(request_timeout=15, max_retries=0)
    with closing(sqlite3.connect(state_path, timeout=0)) as db:
        db.execute('CREATE TABLE IF NOT EXISTS target_config (id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL)')
        saved_scope = db.execute('SELECT scope FROM target_config WHERE id=1').fetchone()
        if saved_scope and saved_scope[0] != scope:
            raise ValueError('Processing scope cannot change for an existing checkpoint')
        db.execute('INSERT OR IGNORE INTO target_config VALUES(1,?)', (scope,))
        db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), checkpoint TEXT, last_success TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), initial_start TEXT NOT NULL)")
        configured = db.execute("SELECT initial_start FROM config WHERE id=1").fetchone()
        db.execute('CREATE TABLE IF NOT EXISTS receipt_policy (id INTEGER PRIMARY KEY CHECK(id=1), lag INTEGER NOT NULL, overlap INTEGER NOT NULL)')
        policy = db.execute('SELECT lag,overlap FROM receipt_policy WHERE id=1').fetchone()
        if ((policy and tuple(policy) != (receipt_lag_seconds, overlap_seconds)) or
                (not policy and configured and (receipt_lag_seconds, overlap_seconds) != (30, 900))):
            raise ValueError('Receipt policy changes require separate explicit state')
        db.execute('INSERT OR IGNORE INTO receipt_policy VALUES(1,?,?)', (receipt_lag_seconds, overlap_seconds))
        if configured and configured[0] != iso(initial):
            raise ValueError("Initial start cannot change for an existing state file")
        db.execute("INSERT OR IGNORE INTO config VALUES (1,?)", (iso(initial),))
        db.execute("CREATE TABLE IF NOT EXISTS adapter_config (name TEXT PRIMARY KEY, start TEXT NOT NULL)")
        saved_web = db.execute("SELECT start FROM adapter_config WHERE name='web_access_site_v2'").fetchone()
        if saved_web and (web_start is None or saved_web[0] != iso(web_start)):
            raise ValueError('Site adapter start cannot change for an existing state file')
        if web_start is not None and not saved_web:
            if configured:
                raise ValueError('Site adapter adoption requires a new explicit state file; retain the old checkpoint')
            db.execute("INSERT INTO adapter_config VALUES ('web_access_site_v2',?)", (iso(web_start),))
        saved_ssh = db.execute("SELECT start FROM adapter_config WHERE name='linux_ssh_v2'").fetchone()
        if saved_ssh and (ssh_start is None or saved_ssh[0] != iso(ssh_start)):
            raise ValueError("SSH adapter start cannot change for an existing state file")
        if ssh_start is not None:
            db.execute("INSERT OR IGNORE INTO adapter_config VALUES ('linux_ssh_v2',?)", (iso(ssh_start),))
        db.commit()
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT checkpoint,last_success FROM state WHERE id=1").fetchone()
        checkpoint = parse_time(row[0]) if row else initial
        if checkpoint is None or checkpoint > now:
            raise ValueError("Invalid checkpoint or clock regression")
        start = max(initial, checkpoint - timedelta(seconds=overlap_seconds))
        end = min(now - timedelta(seconds=receipt_lag_seconds), checkpoint + timedelta(minutes=window_minutes))
        counts = {"normalized": 0, "unsupported": 0, "invalid": 0}
        status = {"@timestamp": iso(now), "state": "running", "detection": "separate_worker",
                  "initial_start": iso(initial),
                  "checkpoint": iso(checkpoint), "last_success": row[1] if row else None,
                  "range": {"start": iso(start), "end": iso(end)}, "counts": counts, "error": None}
        meta = None
        try:
            client.index(index=status_index, id=status_id, document=status)
            if end > checkpoint:
                def consume(hits, counters):
                    batch = []
                    for hit in hits:
                        received = parse_time(field(hit.get('_source'), 'event.ingested'))
                        web_version = SITE_VERSION if web_start is not None and received is not None and received >= web_start else LEGACY_VERSION
                        identifier, record, event = normalize(hit, iso(now), ssh_v2_start=ssh_start, web_version=web_version)
                        if event:
                            record['normalized']['index'] = normalized_index
                            batch.append((normalized_index, identifier, event))
                        batch.append((records_index, identifier, record))
                        counters[record["status"]] += 1
                        if len(batch) >= 200:
                            create_batch(client, batch)
                            batch.clear()
                    create_batch(client, batch)

                if scanner is not None:
                    consume(scanner(client, iso(start), iso(end)), counts)
                else:
                    meta = continuation.prepare(db, client, iso(checkpoint), iso(start), iso(end),
                        resolve=lambda c: resolve(c, source_indices if source_indices is not None else INDICES),
                        batches=index_batches, checked=checked)
                    status["range"] = {"start": meta["start"], "end": meta["end"]}
                    counts = meta["counts"]
                    complete = continuation.read(client, db, meta, budget=max_pages,
                        fields=READ_FIELDS, checked=checked, consume=consume)
                    status["counts"] = counts
                    if not complete:
                        status.update(state="running", error=None,
                            progress={"state": "catching_up", "processed": sum(counts.values()),
                                      "range_complete": False})
                        client.index(index=status_index, id=status_id, document=status)
                        continuation.remember(db, meta)
                        db.commit()
                        return status
                    end = parse_time(meta["end"])
                checkpoint = end
            completed = end > (parse_time(row[0]) if row else initial)
            status.update(state="success" if completed else "waiting", checkpoint=iso(checkpoint),
                          last_success=iso(now) if completed else (row[1] if row else None))
            client.index(index=status_index, id=status_id, document=status)
            db.execute("INSERT OR REPLACE INTO state VALUES (1,?,?)", (iso(checkpoint), status["last_success"]))
            if meta is not None:
                continuation.clear(db)
            db.commit()
            return status
        except Exception:
            db.rollback()
            if meta and meta.get("pit"):
                try:
                    client.close_point_in_time(id=meta["pit"])
                except Exception:
                    pass
            status.update(state="failed", error="processing_failed", checkpoint=row[0] if row else iso(initial),
                          last_success=row[1] if row else None)
            try:
                client.index(index=status_index, id=status_id, document=status)
            except Exception:
                pass
            raise RuntimeError("processing_failed; checkpoint retained") from None
