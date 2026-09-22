"""Single-admin case work, separate from immutable Elasticsearch evidence."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import sqlite3
import uuid

from cloud_soc.privacy import sensitive, REDACTED
from cloud_soc.portal.operations import identifier

STATUSES = ("new", "triage", "investigating", "escalated", "closed")
PRIORITIES = ("critical", "high", "medium", "low")
VERDICTS = ("unreviewed", "malicious", "benign", "false_positive", "inconclusive")
TRANSITIONS = {"new": {"triage", "investigating", "closed"}, "triage": {"investigating", "closed"},
               "investigating": {"triage", "escalated", "closed"}, "escalated": {"investigating", "closed"}, "closed": {"investigating"}}


class CaseError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code, self.status = code, status


def invalid():
    return CaseError("invalid_case_input", "입력 형식·길이·허용 항목을 확인하세요. 비밀정보는 저장하지 마세요.")


def clean(value, limit, *, empty=False):
    if (not isinstance(value, str) or len(value) > limit or (not empty and not value.strip()) or sensitive(value)
            or any(ord(c) < 32 and c not in "\n\t" for c in value)):
        raise invalid()
    return value.strip()


def case_id(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{32}", value):
        raise invalid()
    return value


def now():
    return datetime.now(timezone.utc).isoformat()


class CaseStore:
    def __init__(self, path, admin):
        self.path, self.admin = Path(path), admin
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.connect() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS cases (
                    id TEXT PRIMARY KEY, title TEXT NOT NULL, organization TEXT NOT NULL,
                    priority TEXT NOT NULL, status TEXT NOT NULL, owner TEXT, verdict TEXT NOT NULL,
                    version INTEGER NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS case_alerts (
                    alert_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
                    linked_at TEXT NOT NULL, snapshot TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS case_alerts_case ON case_alerts(case_id);
                CREATE TABLE IF NOT EXISTS case_history (
                    seq INTEGER PRIMARY KEY AUTOINCREMENT, case_id TEXT NOT NULL REFERENCES cases(id),
                    actor TEXT NOT NULL, at TEXT NOT NULL, version INTEGER NOT NULL, action TEXT NOT NULL,
                    changes TEXT NOT NULL, note TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS case_history_case ON case_history(case_id, seq);
                CREATE TABLE IF NOT EXISTS case_requests (
                    token TEXT PRIMARY KEY, actor TEXT NOT NULL, fingerprint TEXT NOT NULL, response TEXT NOT NULL);
                CREATE INDEX IF NOT EXISTS cases_queue ON cases(created_at DESC, id DESC);
            """)

    @contextmanager
    def connect(self):
        db = sqlite3.connect(self.path, timeout=5)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    def authorize(self, actor):
        if actor != self.admin:
            raise CaseError("case_forbidden", "사건 관리자 권한이 필요합니다.", 403)

    def mutation(self, actor, token, payload, action):
        self.authorize(actor)
        if not isinstance(token, str) or not re.fullmatch(r"[0-9a-fA-F-]{36}", token):
            raise invalid()
        fingerprint = hashlib.sha256(json.dumps(payload, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
        with self.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            previous = db.execute("SELECT * FROM case_requests WHERE token=?", (token,)).fetchone()
            if previous:
                if previous["actor"] != actor or previous["fingerprint"] != fingerprint:
                    raise CaseError("idempotency_conflict", "같은 요청 ID를 다른 작업에 사용할 수 없습니다.", 409)
                return json.loads(previous["response"])
            result = action(db)
            db.execute("INSERT INTO case_requests VALUES (?,?,?,?)", (token, actor, fingerprint, json.dumps(result)))
            return result

    def row(self, db, identifier):
        row = db.execute("SELECT * FROM cases WHERE id=?", (case_id(identifier),)).fetchone()
        if not row:
            raise CaseError("case_missing", "사건을 찾을 수 없습니다.", 404)
        return dict(row)

    def history(self, db, row, actor, action, changes, note=""):
        db.execute("INSERT INTO case_history(case_id,actor,at,version,action,changes,note) VALUES(?,?,?,?,?,?,?)",
                   (row["id"], actor, row["updated_at"], row["version"], action, json.dumps(changes, ensure_ascii=False), note))

    def validate_body(self, body, allowed, required):
        if not isinstance(body, dict) or set(body) - allowed or not required <= set(body):
            raise invalid()

    def create(self, body, actor, token, fetch_alert):
        self.validate_body(body, {"title", "alert_id", "priority"}, {"title", "alert_id", "priority"})
        title = clean(body["title"], 160)
        alert_id = identifier(body["alert_id"])
        if body["priority"] not in PRIORITIES:
            raise invalid()
        def action(db):
            if db.execute("SELECT 1 FROM case_alerts WHERE alert_id=?", (alert_id,)).fetchone():
                raise CaseError("alert_already_linked", "이미 사건에 연결된 경보입니다. 사건 목록에서 확인하세요.", 409)
            # Replays do not need ES availability; only the first mutation resolves it.
            alert = fetch_alert(alert_id)
            organization = clean(alert.get("organization"), 128)
            if organization == REDACTED:
                raise invalid()
            timestamp = now()
            row = {"id": uuid.uuid4().hex, "title": title, "organization": organization,
                   "priority": body["priority"], "status": "new", "owner": None, "verdict": "unreviewed",
                   "version": 1, "created_at": timestamp, "updated_at": timestamp}
            db.execute("INSERT INTO cases VALUES (:id,:title,:organization,:priority,:status,:owner,:verdict,:version,:created_at,:updated_at)", row)
            db.execute("INSERT INTO case_alerts VALUES (?,?,?,?)", (alert_id, row["id"], timestamp, json.dumps(alert, ensure_ascii=False)))
            self.history(db, row, actor, "created", {"alert_id": alert_id, "title": title, "priority": row["priority"]})
            return row
        return self.mutation(actor, token, {"action": "create", "body": body}, action)

    def update(self, identifier, body, actor, token, fetch_alert):
        case_id(identifier)
        self.validate_body(body, {"version", "status", "owner", "priority", "verdict", "note", "alert_id"}, {"version"})
        if type(body["version"]) is not int or body["version"] < 1 or len(body) < 2:
            raise invalid()
        note = clean(body.get("note", ""), 2000, empty=True)
        for key, allowed in (("status", STATUSES), ("priority", PRIORITIES), ("verdict", VERDICTS), ("owner", (None, self.admin))):
            if key in body and body[key] not in allowed:
                raise invalid()
        if "alert_id" in body:
            identifier_check = clean(body["alert_id"], 512)
        def action(db):
            before = self.row(db, identifier)
            if before["version"] != body["version"]:
                raise CaseError("case_version_conflict", "다른 수정이 먼저 저장되었습니다. 내용을 확인하고 다시 저장하세요.", 409)
            row = {**before, **{key: body[key] for key in ("status", "priority", "owner", "verdict") if key in body}}
            if row["status"] != before["status"] and row["status"] not in TRANSITIONS[before["status"]]:
                raise CaseError("invalid_transition", "허용하지 않는 상태 전이입니다.")
            if before["status"] == "closed":
                if row["status"] != "investigating" or not note:
                    raise CaseError("case_closed", "종결된 사건은 사유를 입력하고 조사 중으로 재개해야 합니다.", 409)
                row["verdict"] = "unreviewed"
            if row["status"] == "closed" and (row["verdict"] == "unreviewed" or not note):
                raise CaseError("closure_reason_required", "종결 시 판정과 사유 메모가 필요합니다.")
            if row["verdict"] != before["verdict"] and not note:
                raise CaseError("verdict_reason_required", "판정 변경 시 사유 메모가 필요합니다.")
            changes = {key: {"before": before[key], "after": row[key]} for key in ("status", "priority", "owner", "verdict") if before[key] != row[key]}
            if "alert_id" in body:
                if db.execute("SELECT 1 FROM case_alerts WHERE alert_id=?", (identifier_check,)).fetchone():
                    raise CaseError("alert_already_linked", "이미 사건에 연결된 경보입니다.", 409)
                if db.execute("SELECT count(*) FROM case_alerts WHERE case_id=?", (identifier,)).fetchone()[0] >= 100:
                    raise CaseError("case_alert_limit", "한 사건에는 최대 100개의 경보를 연결할 수 있습니다.")
                alert = fetch_alert(identifier_check)
                if alert.get("organization") != row["organization"]:
                    raise CaseError("organization_mismatch", "같은 조직의 경보만 연결할 수 있습니다.")
                db.execute("INSERT INTO case_alerts VALUES (?,?,?,?)", (identifier_check, identifier, now(), json.dumps(alert, ensure_ascii=False)))
                changes["alert_id"] = identifier_check
            if not changes and not note:
                raise CaseError("no_case_changes", "변경 내용이나 메모를 입력하세요.")
            row.update(version=row["version"] + 1, updated_at=now())
            db.execute("UPDATE cases SET status=:status,priority=:priority,owner=:owner,verdict=:verdict,version=:version,updated_at=:updated_at WHERE id=:id", row)
            self.history(db, row, actor, "updated", changes, note)
            return row
        return self.mutation(actor, token, {"action": "update", "id": identifier, "body": body}, action)

    def detail(self, identifier, actor, before=None):
        self.authorize(actor)
        if before is not None and (not isinstance(before, str) or not re.fullmatch(r"[1-9][0-9]{0,17}", before)):
            raise invalid()
        with self.connect() as db:
            db.execute("BEGIN")
            row = self.row(db, identifier)
            alerts = [{"id": entry["alert_id"], "linked_at": entry["linked_at"], "snapshot": json.loads(entry["snapshot"])}
                      for entry in db.execute("SELECT * FROM case_alerts WHERE case_id=? ORDER BY linked_at,alert_id", (identifier,))]
            rows = db.execute("SELECT * FROM case_history WHERE case_id=? AND seq<? ORDER BY seq DESC LIMIT 51",
                              (identifier, int(before) if before else 2**63-1)).fetchall()
            history = [{**dict(item), "changes": json.loads(item["changes"])} for item in rows[:50]]
            return {"case": row, "alerts": alerts, "history": history,
                    "history_next": str(rows[49]["seq"]) if len(rows) > 50 else None, "actor": actor}

    def lookup(self, alert_id, actor):
        self.authorize(actor)
        with self.connect() as db:
            row = db.execute("SELECT case_id FROM case_alerts WHERE alert_id=?", (identifier(alert_id),)).fetchone()
            return {"case_id": row[0] if row else None}

    def listing(self, pairs, actor):
        self.authorize(actor)
        pairs = list(pairs); args = dict(pairs)
        if len(args) != len(pairs) or set(args) - {"status", "owner", "priority", "sort", "page", "days"}:
            raise invalid()
        conditions, params = [], []
        for key, allowed in (("status", STATUSES + ("open",)), ("priority", PRIORITIES), ("owner", ("unassigned", "me"))):
            if key not in args: continue
            if args[key] not in allowed: raise invalid()
            if key == "owner" and args[key] == "unassigned": conditions.append("owner IS NULL")
            elif key == "status" and args[key] == "open": conditions.append("status <> 'closed'")
            else:
                conditions.append(key + "=?"); params.append(actor if key == "owner" else args[key])
        if "days" in args:
            if args["days"] not in ("1", "7", "30"): raise invalid()
            conditions.append("created_at>=?"); params.append((datetime.now(timezone.utc)-timedelta(days=int(args["days"]))).isoformat())
        page = args.get("page", "1")
        if not re.fullmatch(r"[1-9][0-9]{0,4}", page): raise invalid()
        orders = {"newest": "created_at DESC,id DESC", "oldest": "created_at,id", "priority": "CASE priority WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END,created_at,id"}
        if args.get("sort", "priority") not in orders: raise invalid()
        where = " WHERE " + " AND ".join(conditions) if conditions else ""
        with self.connect() as db:
            db.execute("BEGIN")
            counts = dict(db.execute("SELECT count(*) AS total,coalesce(sum(status<>'closed'),0) AS open,coalesce(sum(owner IS NULL),0) AS unassigned,coalesce(sum(status='investigating'),0) AS investigating FROM cases" + where, params).fetchone())
            rows = [dict(row) for row in db.execute("SELECT * FROM cases" + where + " ORDER BY " + orders[args.get("sort", "priority")] + " LIMIT 25 OFFSET ?", params + [(int(page)-1)*25])]
            return {"rows": rows, "counts": counts, "page": int(page), "has_next": int(page)*25 < counts["total"],
                    "actor": actor, "filters": args, "untriaged_alert_count": None}
