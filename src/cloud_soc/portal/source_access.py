"""Audited, allowlisted stored fields. Never a complete or unmasked raw source."""

from datetime import datetime, timezone
from contextlib import contextmanager
import hashlib
import json
import math
import os
from pathlib import Path
import sqlite3

from elasticsearch import NotFoundError
from cloud_soc.privacy import display
from cloud_soc.portal.log_access import POLICY_VERSION, PURPOSES
from cloud_soc.portal.log_contract import SOURCE_FIELDS, document_reference, field
from cloud_soc.portal.security_detail import DETAIL_FIELDS
from cloud_soc.portal.log_query import LogQueryError, bounded_json, unavailable

SOURCE_VIEW_FIELDS = tuple(dict.fromkeys(SOURCE_FIELDS + DETAIL_FIELDS))
AUDIT_COLUMNS = "seq at actor role purpose reference_sha256 outcome policy_version".split()


class SourceAudit:
    def __init__(self, path):
        self.path = Path(path)
        if self.path.is_symlink():
            raise ValueError("Unsafe log access audit path.")
        if not self.path.exists():
            fd = os.open(self.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
        if not self.path.is_file():
            raise ValueError("Unsafe log access audit path.")
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS source_access (
                seq INTEGER PRIMARY KEY, at TEXT NOT NULL, actor TEXT NOT NULL,
                role TEXT NOT NULL, purpose TEXT NOT NULL, reference_sha256 TEXT NOT NULL,
                outcome TEXT NOT NULL, policy_version TEXT NOT NULL)""")

    @contextmanager
    def connect(self):
        # No writable aliases, WAL link following, or unbounded lock wait.
        if self.path.is_symlink() or not self.path.is_file():
            raise sqlite3.OperationalError("Unsafe audit file")
        for suffix in ("-wal", "-shm", "-journal"):
            if Path(str(self.path) + suffix).is_symlink():
                raise sqlite3.OperationalError("Unsafe audit sidecar")
        db = sqlite3.connect(self.path, timeout=0.2)
        try:
            db.execute("PRAGMA synchronous=FULL")
            with db:
                yield db
        finally:
            db.close()

    def record(self, principal, reference, purpose, outcome):
        fingerprint = hashlib.sha256(json.dumps(reference, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        try:
            with self.connect() as db:
                row = db.execute("INSERT INTO source_access(at,actor,role,purpose,reference_sha256,outcome,policy_version) VALUES(?,?,?,?,?,?,?)",
                    (datetime.now(timezone.utc).isoformat(), principal.username, principal.role,
                     purpose if isinstance(purpose, str) and purpose in PURPOSES else "invalid", fingerprint, outcome, POLICY_VERSION))
                return str(row.lastrowid)
        except sqlite3.Error:
            raise LogQueryError("source_audit_unavailable", 503, "원문 접근 감사 기록을 저장하지 못했습니다. 조회를 허용하지 않습니다.") from None


def protected_fields(source):
    """Rebuild only literal known paths; never forward caller-defined field names."""
    if not isinstance(source, dict):
        raise unavailable()
    result, redacted, limited = {}, [], []
    budget = [0]
    def value(item, depth=0):
        budget[0] += 1
        if depth > 3 or budget[0] > 4096:
            raise LogQueryError("response_too_large", 413, "원문 필드가 표시 한도를 초과했습니다.")
        if isinstance(item, str):
            shown = display(item, 8192)
            return shown
        if item is None or type(item) is bool or (type(item) is int and -(2**63) <= item < 2**63):
            return item
        if type(item) is float and math.isfinite(item):
            return item
        if isinstance(item, list):
            if depth:
                return "[WITHHELD]"
            if len(item) > 64:
                raise LogQueryError("response_too_large", 413, "원문 배열이 표시 한도를 초과했습니다.")
            values = [value(v, depth+1) for v in item]
            if any(v in ("[REDACTED]", "[WITHHELD]") for v in values if isinstance(v, str)):
                return ["[REDACTED]"]
            return values
        return "[WITHHELD]"
    for path in SOURCE_VIEW_FIELDS:
        raw = field(source, path)
        if raw is None:
            continue
        clean = value(raw)
        if clean == "[REDACTED]" or (isinstance(clean, list) and "[REDACTED]" in clean):
            redacted.append(path)
        if clean == "[WITHHELD]" or (isinstance(clean, list) and "[WITHHELD]" in clean):
            limited.append(path)
        parts = path.split(".")
        parent = result
        for part in parts[:-1]:
            parent = parent.setdefault(part, {})
        parent[parts[-1]] = clean
    return {"source": result, "redacted_fields": redacted, "withheld_fields": limited,
            "withheld_by_policy": ["message", "event.original", "command_arguments", "credentials", "unknown_fields"],
            "complete_source": False}


class ProtectedSourceReader:
    def __init__(self, reader, audit):
        self.reader, self.audit = reader, audit

    def read(self, principal, data):
        reference, purpose = {}, "invalid"
        try:
            if not isinstance(data, dict) or set(data) != {"index", "id", "purpose"}:
                raise ValueError()
            reference = document_reference(data["index"], data["id"])
            purpose = data["purpose"]
            if not isinstance(purpose, str) or purpose not in PURPOSES:
                raise ValueError()
        except (ValueError, TypeError):
            self.audit.record(principal, reference, purpose, "invalid")
            raise LogQueryError("invalid_source_request", 400, "문서 참조와 정해진 조회 사유를 확인하세요.") from None
        if not principal.source_organizations:
            self.audit.record(principal, reference, purpose, "forbidden")
            raise LogQueryError("source_forbidden", 403, "보호된 원문 필드를 조회할 권한이 없습니다.")
        try:
            self.reader.require_client()
            if self.reader.indices(reference["index"]) != [reference["index"]]:
                raise NotFoundError("missing", {}, {})
            hit = self.reader.client.get(index=reference["index"], id=reference["id"], source_includes=list(SOURCE_VIEW_FIELDS))
            if hit.get("_index") != reference["index"] or hit.get("_id") != reference["id"]:
                raise unavailable()
            if not principal.can_read_source(field(hit.get("_source"), "organization.id")):
                self.audit.record(principal, reference, purpose, "not_found")
                raise LogQueryError("source_not_found", 404, "문서를 찾을 수 없습니다.")
            content = {"contract_version": 1, "policy_version": POLICY_VERSION, "reference": reference,
                       "raw_access": "protected_fields", "purpose": purpose, **protected_fields(hit.get("_source"))}
            bounded_json(content, 60000)
        except NotFoundError:
            self.audit.record(principal, reference, purpose, "not_found")
            raise LogQueryError("source_not_found", 404, "문서를 찾을 수 없습니다.") from None
        except LogQueryError as error:
            if error.code not in {"source_not_found", "source_audit_unavailable"}:
                self.audit.record(principal, reference, purpose, "unavailable")
            raise
        except Exception:
            self.audit.record(principal, reference, purpose, "unavailable")
            raise unavailable() from None
        # Serialize before recording success; neither ES nor browser cache is an audit.
        audit_id = self.audit.record(principal, reference, purpose, "granted")
        return bounded_json({**content, "audit_id": audit_id}, 65536)
