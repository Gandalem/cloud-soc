"""Explicit compartment/Region polling with durable replay boundaries."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time

# Reuse only cloud-neutral error/time/ES primitives, never AWS clients or state.
from cloud_soc.aws.collector import CollectionError, ElasticsearchSink
from cloud_soc.aws.cloudtrail import iso, timestamp
from cloud_soc.oci.audit import project_event

WINDOW = timedelta(hours=1)
OVERLAP = timedelta(minutes=15)
LAG = timedelta(minutes=10)
HISTORY = timedelta(days=365)
MAX_PAGES = 1000


def valid_ocid(value, kind):
    return isinstance(value, str) and len(value) <= 255 and re.fullmatch(r"ocid1\." + kind + r"\.oc1\.\.[a-z0-9]{8,200}", value) is not None


def minute(value):
    return timestamp(value).replace(second=0, microsecond=0)


@dataclass(frozen=True)
class Settings:
    tenancy_id: str
    organization: str
    regions: tuple[str, ...]
    compartments: tuple[str, ...]
    lookback_hours: int = 24

    @classmethod
    def parse(cls, value):
        if not isinstance(value, dict) or set(value) - {"tenancy_id", "organization", "regions", "compartments", "lookback_hours"}:
            raise CollectionError("invalid_config")
        tenancy, org = value.get("tenancy_id"), value.get("organization")
        if not valid_ocid(tenancy, "tenancy"):
            raise CollectionError("invalid_tenancy")
        if not isinstance(org, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", org):
            raise CollectionError("invalid_organization")
        regions, compartments = value.get("regions"), value.get("compartments")
        if (not isinstance(regions, list) or not 1 <= len(regions) <= 20
                or any(not isinstance(r, str) or not re.fullmatch(r"[a-z]{2}-[a-z]{2,30}-[1-9][0-9]?", r) for r in regions)
                or len(set(regions)) != len(regions)):
            raise CollectionError("invalid_regions")
        if (not isinstance(compartments, list) or not 1 <= len(compartments) <= 50
                or any(c != tenancy and not valid_ocid(c, "compartment") for c in compartments)
                or len(set(compartments)) != len(compartments)):
            raise CollectionError("invalid_compartments")
        if len(regions) * len(compartments) > 100:
            raise CollectionError("too_many_scopes")
        hours = value.get("lookback_hours", 24)
        if type(hours) is not int or not 1 <= hours <= 364 * 24:
            raise CollectionError("invalid_lookback")
        return cls(tenancy, org, tuple(sorted(regions)), tuple(sorted(compartments)), hours)

    def fingerprint(self):
        return hashlib.sha256(json.dumps({"v": 1, **self.__dict__}, sort_keys=True).encode()).hexdigest()


class State:
    def __init__(self, path, settings, *, now):
        path = Path(path)
        if path.is_symlink():
            raise CollectionError("unsafe_state_path")
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
            os.close(fd)
        except FileExistsError:
            pass
        self.db = sqlite3.connect(path, isolation_level=None, timeout=0)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS oci_identity(id INTEGER PRIMARY KEY CHECK(id=1), fingerprint TEXT NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS oci_progress(region TEXT, compartment TEXT, floor TEXT NOT NULL, watermark TEXT NOT NULL, last_attempt TEXT, last_success TEXT, error TEXT, created INTEGER NOT NULL DEFAULT 0, duplicates INTEGER NOT NULL DEFAULT 0, PRIMARY KEY(region,compartment))")
            self.db.execute("BEGIN IMMEDIATE")
            previous = self.db.execute("SELECT fingerprint FROM oci_identity WHERE id=1").fetchone()
            if previous and previous[0] != settings.fingerprint():
                raise CollectionError("state_scope_mismatch")
            self.db.execute("INSERT OR IGNORE INTO oci_identity VALUES(1,?)", (settings.fingerprint(),))
            floor = iso(minute(now) - timedelta(hours=settings.lookback_hours))
            for region in settings.regions:
                for compartment in settings.compartments:
                    self.db.execute("INSERT OR IGNORE INTO oci_progress(region,compartment,floor,watermark) VALUES(?,?,?,?)", (region, compartment, floor, floor))
            self.db.execute("COMMIT")
        except Exception:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def status(self):
        keys = ("region", "compartment", "floor", "watermark", "last_attempt", "last_success", "error", "created", "duplicates")
        return [dict(zip(keys, row)) for row in self.db.execute("SELECT region,compartment,floor,watermark,last_attempt,last_success,error,created,duplicates FROM oci_progress ORDER BY region,compartment")]

    def fail(self, region, compartment, now, code):
        self.db.execute("UPDATE oci_progress SET last_attempt=?,error=? WHERE region=? AND compartment=?", (iso(now), code, region, compartment))


def poll_scope(settings, state, region, compartment, client, sink, *, now, sleep=time.sleep, max_pages=MAX_PAGES):
    now = minute(now)
    state.db.execute("BEGIN IMMEDIATE")
    try:
        floor, watermark = (timestamp(v) for v in state.db.execute("SELECT floor,watermark FROM oci_progress WHERE region=? AND compartment=?", (region, compartment)).fetchone())
        start, end = max(floor, watermark - OVERLAP), min(watermark + WINDOW, now - LAG)
        if start < now - HISTORY:
            raise CollectionError("history_gap_requires_review")
        if end < watermark or end <= floor:
            state.db.execute("COMMIT")
            return {"status": "waiting", "created": 0, "duplicates": 0}
        token, seen, created, duplicates = None, set(), 0, 0
        for _ in range(max_pages):
            sleep(0.55)
            try:
                events, next_token = client.page(compartment, start, end, token)
            except Exception as error:
                status = getattr(error, "status", None)
                code = {401: "oci_authentication_failed", 403: "oci_access_denied", 404: "oci_scope_unavailable", 429: "oci_throttled"}.get(status, "oci_lookup_failed") if type(status) is int else "oci_lookup_failed"
                raise CollectionError(code) from None
            if not isinstance(events, list) or len(events) > 10000:
                raise CollectionError("invalid_oci_page")
            for event in events:
                try:
                    index, identifier, document = project_event(event, tenancy=settings.tenancy_id, compartment=compartment, region=region, organization=settings.organization)
                except (ValueError, TypeError):
                    raise CollectionError("invalid_oci_event") from None
                # OCI queries processed time, not necessarily event_time; do not discard late events.
                if sink.create(index, identifier, document):
                    created += 1
                else:
                    duplicates += 1
            if next_token is None:
                state.db.execute("UPDATE oci_progress SET watermark=?,last_attempt=?,last_success=?,error=NULL,created=?,duplicates=? WHERE region=? AND compartment=?", (iso(end), iso(now), iso(now), created, duplicates, region, compartment))
                state.db.execute("COMMIT")
                return {"status": "ok", "watermark": iso(end), "created": created, "duplicates": duplicates}
            if not isinstance(next_token, str) or not next_token or len(next_token) > 8192 or next_token in seen:
                raise CollectionError("invalid_pagination")
            seen.add(next_token)
            token = next_token
        raise CollectionError("page_limit_reached")
    except BaseException:
        if state.db.in_transaction:
            state.db.execute("ROLLBACK")
        raise


def run_cycle(settings, state, clients, sink, *, now=None, sleep=time.sleep):
    now = timestamp(now or datetime.now(timezone.utc))
    results = []
    for region in settings.regions:
        for compartment in settings.compartments:
            try:
                result = poll_scope(settings, state, region, compartment, clients[region], sink, now=now, sleep=sleep)
            except Exception as error:
                code = str(error) if isinstance(error, CollectionError) else "collection_failed"
                try:
                    state.fail(region, compartment, now, code)
                except sqlite3.OperationalError:
                    pass
                result = {"status": "error", "code": code}
            results.append({"region": region, "compartment": compartment, **result})
    return results
