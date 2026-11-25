"""Resume bounded raw reads without persisting event bodies or advancing coverage early."""

import hashlib
import json

from elasticsearch import NotFoundError

from cloud_soc.processing.continuation_store import resolve_continuation_store
from cloud_soc.processing.contract import raw_identity

PAGE_SIZE = 200


def prepare(db, client, checkpoint, start, end, *, resolve, batches, checked):
    store = resolve_continuation_store(db)
    store.init()
    meta = store.load_progress()
    if meta is not None:
        if meta.get("version") != 1 or meta["checkpoint"] != checkpoint:
            raise RuntimeError("scan_scope_changed")
        return meta

    names = resolve(client)
    scopes = list(batches(names))
    # All mappings must pass before any create-only write.
    for scope in scopes:
        fields = client.field_caps(index=scope, fields=["event.ingested"], include_unmapped=True)
        caps = fields["fields"].get("event.ingested", {})
        if not caps or set(caps) - {"date", "date_nanos"}:
            raise RuntimeError("receipt_mapping_missing")

    return {
        "version": 1,
        "checkpoint": checkpoint,
        "start": start,
        "end": end,
        "batches": scopes,
        "batch": 0,
        "pit": None,
        "after": None,
        "counts": {"normalized": 0, "unsupported": 0, "invalid": 0},
    }


def seen_id(hit):
    reference = raw_identity(hit)
    return hashlib.sha256(json.dumps(reference, sort_keys=True).encode()).hexdigest()


def _close_pit_safely(client, pit_id):
    if not pit_id:
        return
    try:
        client.close_point_in_time(id=pit_id)
    except NotFoundError:
        pass


def read(client, db, meta, *, budget, fields, checked, consume):
    store = resolve_continuation_store(db)
    reopened = False

    for _ in range(budget):
        if meta["batch"] == len(meta["batches"]):
            return True

        scope = meta["batches"][meta["batch"]]
        scope_set = set(scope) if isinstance(scope, (list, tuple, set)) else {scope}

        if not meta["pit"]:
            opened = client.open_point_in_time(
                index=scope,
                keep_alive="10m",
                allow_partial_search_results=False,
            )
            meta["pit"] = opened["id"]
            checked(opened)
            meta["after"] = None

        try:
            result = client.search(
                pit={"id": meta["pit"], "keep_alive": "10m"},
                size=PAGE_SIZE,
                sort=["_shard_doc"],
                search_after=meta["after"],
                source=fields,
                track_total_hits=False,
                allow_partial_search_results=False,
                timeout="10s",
                query={"range": {"event.ingested": {"gte": meta["start"], "lt": meta["end"]}}},
            )
        except NotFoundError:
            if reopened:
                raise
            # Replay only this fixed receipt range; committed reference hashes
            # skip already delivered events without keeping their contents.
            meta["pit"], meta["after"], reopened = None, None, True
            continue

        meta["pit"] = result.get("pit_id", meta["pit"])
        checked(result)
        hits = result["hits"]["hits"]

        if not hits:
            _close_pit_safely(client, meta["pit"])
            meta["pit"], meta["after"] = None, None
            meta["batch"] += 1
            reopened = False
            continue

        after = hits[-1].get("sort")
        if (
            not isinstance(after, list)
            or not after
            or after == meta["after"]
            or len(hits) > PAGE_SIZE
            or any(hit.get("_index") not in scope_set for hit in hits)
        ):
            raise RuntimeError("cursor_not_advancing")

        hashed_hits = [(seen_id(hit), hit) for hit in hits]
        already_seen = store.filter_seen([hid for hid, _ in hashed_hits])
        unseen_pairs = [(hid, hit) for hid, hit in hashed_hits if hid not in already_seen]
        unseen_hits = [hit for _, hit in unseen_pairs]

        if unseen_hits:
            consume(unseen_hits, meta["counts"])
            store.mark_seen([hid for hid, _ in unseen_pairs])

        meta["after"] = after

    return meta["batch"] == len(meta["batches"])


def remember(db, meta):
    store = resolve_continuation_store(db)
    store.save_progress(meta)


def clear(db):
    store = resolve_continuation_store(db)
    store.clear()