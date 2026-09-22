"""Bounded polling, replay-safe create-only delivery and durable watermarks."""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sqlite3
import time

from elasticsearch import ConflictError

from cloud_soc.aws.cloudtrail import iso, project_event, timestamp

RECEIPT_PIPELINE = "cloud-soc-received-at-v1"
WINDOW = timedelta(hours=1)
OVERLAP = timedelta(minutes=15)
LAG = timedelta(minutes=5)
HISTORY = timedelta(days=90)
MAX_PAGES = 1000


class CollectionError(RuntimeError):
    """Only fixed codes reach CLI output or the checkpoint database."""


@dataclass(frozen=True)
class Settings:
    account_id: str
    organization: str
    regions: tuple[str, ...]
    lookback_hours: int = 24

    @classmethod
    def parse(cls, value):
        if not isinstance(value, dict) or set(value) - {"account_id", "organization", "regions", "lookback_hours"}:
            raise CollectionError("invalid_config")
        account, org, regions = (value.get(key) for key in ("account_id", "organization", "regions"))
        if not isinstance(account, str) or not re.fullmatch(r"\d{12}", account):
            raise CollectionError("invalid_account")
        if not isinstance(org, str) or not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", org):
            raise CollectionError("invalid_organization")
        if not isinstance(regions, list) or not 1 <= len(regions) <= 20:
            raise CollectionError("invalid_regions")
        if any(not isinstance(region, str) or not re.fullmatch(r"(?:us|eu|ap|sa|ca|me|af|il|mx)-(?:[a-z]+-)?[a-z]+-\d", region) or region.startswith("us-gov-") for region in regions):
            raise CollectionError("invalid_regions")
        if len(set(regions)) != len(regions):
            raise CollectionError("duplicate_regions")
        hours = value.get("lookback_hours", 24)
        if type(hours) is not int or not 1 <= hours <= 89 * 24:
            raise CollectionError("invalid_lookback")
        return cls(account, org, tuple(sorted(regions)), hours)

    def fingerprint(self):
        return hashlib.sha256(json.dumps({"v": 1, "account": self.account_id, "org": self.organization,
                                         "regions": self.regions, "lookback": self.lookback_hours}, sort_keys=True).encode()).hexdigest()


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
        self.db = sqlite3.connect(path, timeout=0, isolation_level=None)
        try:
            self.db.execute("PRAGMA journal_mode=WAL")
            self.db.execute("PRAGMA synchronous=FULL")
            self.db.execute("CREATE TABLE IF NOT EXISTS identity (id INTEGER PRIMARY KEY CHECK(id=1), fingerprint TEXT NOT NULL)")
            self.db.execute("CREATE TABLE IF NOT EXISTS progress (region TEXT PRIMARY KEY, floor TEXT NOT NULL, watermark TEXT NOT NULL, last_attempt TEXT, last_success TEXT, error TEXT, created INTEGER NOT NULL DEFAULT 0, duplicates INTEGER NOT NULL DEFAULT 0)")
            self.db.execute("BEGIN IMMEDIATE")
            previous = self.db.execute("SELECT fingerprint FROM identity WHERE id=1").fetchone()
            if previous and previous[0] != settings.fingerprint():
                raise CollectionError("state_scope_mismatch")
            self.db.execute("INSERT OR IGNORE INTO identity VALUES (1, ?)", (settings.fingerprint(),))
            floor = iso(timestamp(now) - timedelta(hours=settings.lookback_hours))
            for region in settings.regions:
                self.db.execute("INSERT OR IGNORE INTO progress(region,floor,watermark) VALUES(?,?,?)", (region, floor, floor))
            self.db.execute("COMMIT")
        except Exception:
            self.db.close()
            raise

    def close(self):
        self.db.close()

    def status(self):
        keys = ("region", "floor", "watermark", "last_attempt", "last_success", "error", "created", "duplicates")
        return [dict(zip(keys, row)) for row in self.db.execute("SELECT region,floor,watermark,last_attempt,last_success,error,created,duplicates FROM progress ORDER BY region")]

    def fail(self, region, now, code):
        self.db.execute("UPDATE progress SET last_attempt=?, error=? WHERE region=?", (iso(now), code, region))


class ElasticsearchSink:
    def __init__(self, client):
        self.client = client.options(request_timeout=20, max_retries=0)

    def create(self, index, identifier, document):
        try:
            self.client.create(index=index, id=identifier, document=document, pipeline=RECEIPT_PIPELINE)
            return True
        except ConflictError:
            # Event identity and event-date index are deterministic across replay.
            return False
        except Exception:
            raise CollectionError("elasticsearch_write_failed") from None


def poll_region(settings, state, region, aws, sink, *, now, sleep=time.sleep, max_pages=MAX_PAGES):
    now = timestamp(now)
    state.db.execute("BEGIN IMMEDIATE")
    try:
        floor_text, watermark_text = state.db.execute("SELECT floor,watermark FROM progress WHERE region=?", (region,)).fetchone()
        floor, watermark = timestamp(floor_text), timestamp(watermark_text)
        start = max(floor, watermark - OVERLAP)
        end = min(watermark + WINDOW, now - LAG)
        if start < now - HISTORY:
            raise CollectionError("history_gap_requires_review")
        if end < watermark or end <= floor:
            state.db.execute("COMMIT")
            return {"region": region, "status": "waiting", "created": 0, "duplicates": 0}
        token, seen = None, set()
        created, duplicates = 0, 0
        for _ in range(max_pages):
            request = {"StartTime": start, "EndTime": end, "MaxResults": 50}
            if token is not None:
                request["NextToken"] = token
            # SDK retries also back off; one collector per account/Region is required.
            sleep(0.55)
            try:
                page = aws.lookup_events(**request)
            except Exception as error:
                response = getattr(error, "response", {})
                detail = response.get("Error", {}) if isinstance(response, dict) else {}
                code = detail.get("Code") if isinstance(detail, dict) else None
                reason = {"ThrottlingException": "aws_throttled", "AccessDeniedException": "aws_access_denied",
                          "InvalidNextTokenException": "aws_page_token_invalid", "ExpiredTokenException": "aws_credentials_expired"}.get(code, "aws_lookup_failed") if isinstance(code, str) else "aws_lookup_failed"
                raise CollectionError(reason) from None
            events = page.get("Events") if isinstance(page, dict) else None
            if not isinstance(events, list) or len(events) > 50:
                raise CollectionError("invalid_aws_page")
            for envelope in events:
                try:
                    index, identifier, document = project_event(envelope, account=settings.account_id, region=region, organization=settings.organization)
                    if not start <= timestamp(document["@timestamp"]) <= end:
                        raise ValueError()
                except (ValueError, TypeError):
                    raise CollectionError("invalid_aws_event") from None
                if sink.create(index, identifier, document):
                    created += 1
                else:
                    duplicates += 1
            token = page.get("NextToken")
            if token is None:
                state.db.execute("UPDATE progress SET watermark=?,last_attempt=?,last_success=?,error=NULL,created=?,duplicates=? WHERE region=?",
                                 (iso(end), iso(now), iso(now), created, duplicates, region))
                state.db.execute("COMMIT")
                return {"region": region, "status": "ok", "watermark": iso(end), "created": created, "duplicates": duplicates}
            if not isinstance(token, str) or not token or len(token) > 8192 or token in seen:
                raise CollectionError("invalid_pagination")
            seen.add(token)
        raise CollectionError("page_limit_reached")
    except BaseException:
        if state.db.in_transaction:
            state.db.execute("ROLLBACK")
        raise


def run_cycle(settings, state, sts, clients, sink, *, now=None, sleep=time.sleep):
    now = timestamp(now or datetime.now(timezone.utc))
    try:
        identity = sts.get_caller_identity()
        if identity.get("Account") != settings.account_id or not str(identity.get("Arn", "")).startswith("arn:aws:"):
            raise CollectionError("aws_account_mismatch")
    except Exception as error:
        code = "aws_account_mismatch" if isinstance(error, CollectionError) else "aws_identity_unavailable"
        for region in settings.regions:
            state.fail(region, now, code)
        raise CollectionError(code) from None
    results = []
    for region in settings.regions:
        try:
            result = poll_region(settings, state, region, clients[region], sink, now=now, sleep=sleep)
        except Exception as error:
            code = str(error) if isinstance(error, CollectionError) else "collection_failed"
            # A second worker must not write a misleading failure over the lock owner.
            try:
                state.fail(region, now, code)
            except sqlite3.OperationalError:
                pass
            result = {"region": region, "status": "error", "code": code}
        results.append(result)
    return results
