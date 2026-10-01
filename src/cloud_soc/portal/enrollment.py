"""Single-consumer enrollment. Secrets are delivered only over the TLS API.

The retry envelope is encrypted with a client-generated, high-entropy attempt
secret, which is never persisted by the server. A crashed issuer is not retried
automatically: its deterministic key names must first be revoked.
"""

import base64
from datetime import datetime, timezone
import hashlib
import json
import re
import secrets
import time
import uuid

from cryptography.fernet import Fernet


TOKEN_TTL = 15 * 60
SESSION_TTL = 30 * 60
PROOF_FIELD = "cloud_soc_enrollment"
SECRET = re.compile(r"[A-Za-z0-9_-]{43}\Z")


class EnrollmentError(Exception):
    def __init__(self, code, status, message):
        super().__init__(message)
        self.code, self.status = code, status


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def envelope(attempt):
    # The attempt is 256 random bits; the server stores only its one-way hash.
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(b"cloud-soc-enrollment-v1\0" + attempt.encode("ascii")).digest()))


class Enrollments:
    def __init__(self, store, issuer, monitor, *, clock=time.time):
        self.store, self.issuer, self.monitor, self.clock = store, issuer, monitor, clock
        with store.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS enrollments (
                id TEXT PRIMARY KEY, token_hash TEXT NOT NULL, package_id TEXT NOT NULL,
                package_sha256 TEXT NOT NULL, spec TEXT NOT NULL, target_label TEXT NOT NULL,
                days INTEGER NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL,
                deadline INTEGER, state TEXT NOT NULL, attempt_hash TEXT,
                sealed BLOB, nonce TEXT NOT NULL, key_ids TEXT NOT NULL DEFAULT '[]',
                agents TEXT, completed INTEGER)""")

    @staticmethod
    def public(row):
        spec = json.loads(row["spec"])
        return {"id": row["id"], "package_id": row["package_id"], "package_name": spec["name"],
                "organization": spec["organization"], "os": spec["os"], "network": spec["network"],
                "target_label": row["target_label"], "state": row["state"], "expires": row["expires"],
                "deadline": row["deadline"], "completed": row["completed"]}

    def mint(self, identifier, data):
        if (not isinstance(data, dict) or set(data) - {"days", "target_label"}
                or type(data.get("days")) is not int or data["days"] not in (1, 7, 30, 90)):
            raise ValueError("키 유효 기간은 1·7·30·90일 중 선택하세요.")
        label = data.get("target_label", "")
        if not isinstance(label, str) or len(label) > 100 or any(ord(c) < 32 or ord(c) == 127 for c in label):
            raise ValueError("대상 별칭은 줄바꿈 없이 100자 이내로 입력하세요.")
        package = self.store.get(identifier)
        if package.get("enrollment_protocol") != 1 or package["os"] != "windows" or not package["network"]:
            raise EnrollmentError("enrollment_package_required", 409, "단일 설치 토큰은 새로 생성한 Windows 로그+네트워크 패키지에서 먼저 지원합니다.")
        self.check_pipeline()
        sid = uuid.uuid4().hex
        token = sid + "." + secrets.token_urlsafe(32)
        now = int(self.clock())
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            # Completed metadata is retained. Expired unused tokens need no key cleanup.
            db.execute("UPDATE enrollments SET state='expired' WHERE state='unused' AND expires<=?", (now,))
            if db.execute("SELECT count(*) FROM enrollments WHERE state IN ('unused','issuing','issued','cleanup_pending')").fetchone()[0] >= 500:
                raise EnrollmentError("enrollment_limit", 409, "대기 중인 설치 토큰을 정리한 후 다시 발급하세요.")
            db.execute("INSERT INTO enrollments (id,token_hash,package_id,package_sha256,spec,target_label,days,created,expires,state,nonce) VALUES (?,?,?,?,?,?,?,?,?,'unused',?)",
                       (sid, digest(token), identifier, package["sha256"], json.dumps(package), label.strip(),
                        data["days"], now, now + TOKEN_TTL, secrets.token_hex(32)))
        return {"id": sid, "token": token, "expires": now + TOKEN_TTL,
                "warning": "15분 이내 설치기에 한 번 입력하세요. 토큰을 명령줄·패키지·파일에 저장하지 마세요."}

    def listing(self):
        with self.store.connect() as db:
            db.execute("UPDATE enrollments SET state='expired' WHERE state='unused' AND expires<=?", (int(self.clock()),))
            return [self.public(r) for r in db.execute("SELECT * FROM enrollments ORDER BY created DESC, id LIMIT 200")]

    def sweep(self):
        """Explicit maintenance: revoke abandoned keys, not completed installations."""
        now = int(self.clock())
        with self.store.connect() as db:
            db.execute("UPDATE enrollments SET state='expired',sealed=NULL WHERE state='unused' AND expires<=?", (now,))
            pending = [r["id"] for r in db.execute("SELECT id FROM enrollments WHERE state='cleanup_pending' OR (state IN ('issuing','issued') AND deadline<=?) ORDER BY created LIMIT 100", (now,))]
        failed = 0
        for sid in pending:
            try:
                self.cancel(sid)
            except EnrollmentError:
                failed += 1
        return {"examined": len(pending), "cleanup_pending": failed}

    def check_pipeline(self):
        from cloud_soc.portal.status_setup import PIPELINE, PIPELINE_ID
        try:
            if self.monitor is None:
                raise RuntimeError("Reader missing")
            configured = self.issuer.ingest.get_pipeline(id=PIPELINE_ID)
            if configured[PIPELINE_ID].get("processors") != PIPELINE["processors"]:
                raise RuntimeError("Pipeline differs")
        except Exception:
            raise EnrollmentError("enrollment_setup_required", 503, "설치 수신 검증용 중앙 파이프라인·조회 계정을 먼저 준비하세요.") from None

    @staticmethod
    def scopes(spec):
        return ["host", "network"] if spec["network"] else ["host"]

    @staticmethod
    def key_name(sid, scope):
        return f"cloud-soc-enrollment-{sid}-{scope}"

    def authenticate(self, db, token, attempt):
        if not isinstance(token, str) or not re.fullmatch(r"[a-f0-9]{32}\.[A-Za-z0-9_-]{43}", token):
            raise EnrollmentError("invalid_enrollment", 401, "설치 토큰을 확인하세요.")
        if not isinstance(attempt, str) or not SECRET.fullmatch(attempt):
            raise EnrollmentError("invalid_attempt", 400, "설치 재시도 식별자가 올바르지 않습니다.")
        row = db.execute("SELECT * FROM enrollments WHERE id=?", (token[:32],)).fetchone()
        if row is None or not secrets.compare_digest(row["token_hash"], digest(token)):
            raise EnrollmentError("invalid_enrollment", 401, "설치 토큰을 확인하세요.")
        if row["attempt_hash"] and not secrets.compare_digest(row["attempt_hash"], digest(attempt)):
            raise EnrollmentError("enrollment_consumed", 409, "다른 설치 시도에서 이미 사용한 토큰입니다.")
        return row

    def exchange(self, token, data):
        if not isinstance(data, dict) or set(data) != {"attempt", "package_id", "package_sha256"}:
            raise ValueError("설치 시도·패키지 ID·SHA-256만 전달하세요.")
        attempt = data["attempt"]
        now = int(self.clock())
        with self.store.connect() as db:
            existing = self.authenticate(db, token, attempt)
        if existing["state"] == "issued" and existing["deadline"] <= now:
            self.cancel(existing["id"])
            raise EnrollmentError("enrollment_expired", 410, "설치 수신 확인 시간이 만료되었습니다.")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self.authenticate(db, token, attempt)
            if data["package_id"] != row["package_id"] or data["package_sha256"] != row["package_sha256"]:
                raise EnrollmentError("package_mismatch", 409, "발급한 토큰의 패키지와 설치 파일이 다릅니다.")
            # A deleted or superseded package cannot enroll even if its old ZIP remains.
            if self.store.get(row["package_id"])["sha256"] != row["package_sha256"]:
                raise EnrollmentError("package_mismatch", 409, "패키지 정보를 다시 확인하세요.")
            if row["state"] == "issued" and row["deadline"] > now:
                return json.loads(envelope(attempt).decrypt(row["sealed"]))
            if row["state"] != "unused":
                raise EnrollmentError("enrollment_unavailable", 409, "설치 토큰을 재사용할 수 없습니다. 중단된 발급은 관리자가 취소 후 새 토큰을 발급하세요.")
            if row["expires"] <= now:
                raise EnrollmentError("enrollment_expired", 410, "설치 토큰이 만료되었습니다. 새로 발급하세요.")
            self.check_pipeline()
            db.execute("UPDATE enrollments SET state='issuing',attempt_hash=?,deadline=? WHERE id=?",
                       (digest(attempt), now + SESSION_TTL, row["id"]))
        # Persist the reservation BEFORE calling Elasticsearch. A crash never reissues.
        sid = row["id"]
        spec = json.loads(row["spec"])
        try:
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                current = db.execute("SELECT * FROM enrollments WHERE id=?", (sid,)).fetchone()
                if current["state"] != "issuing":
                    raise RuntimeError("Cancelled reservation")
                issued = []
                platform = "windows" if spec["os"] == "windows" else "linux"
                for scope in self.scopes(spec):
                    name = self.key_name(sid, scope)
                    previous = self.issuer.security.get_api_key(name=name, owner=True).get("api_keys")
                    if not isinstance(previous, list) or previous:
                        # A stale restored DB must not duplicate a remotely issued key.
                        raise RuntimeError("Existing remote enrollment key")
                    indices = [f"soc-host-raw-{platform}-*"] + ["soc-agent-health-*"] if scope == "host" else [f"soc-network-{platform}-*"]
                    role = {"cluster": ["monitor"] + (["read_pipeline"] if scope == "network" else []),
                            "indices": [{"names": indices, "privileges": ["auto_configure", "create_doc"]}]}
                    key = self.issuer.security.create_api_key(name=name, expiration=f"{row['days']}d",
                        role_descriptors={f"cloud_soc_{scope}": role}, metadata={"package_id": row["package_id"],
                        "organization": spec["organization"], "enrollment_id": sid, "scope": scope})
                    if not isinstance(key.get("id"), str) or not isinstance(key.get("api_key"), str) or not key["id"] or not key["api_key"]:
                        raise RuntimeError("Invalid key response")
                    issued.append({"id": key["id"], "key": key["id"] + ":" + key["api_key"], "scope": scope, "expiration": key.get("expiration")})
                reply = {"id": sid, "keys": issued, "probe": row["nonce"], "deadline": now + SESSION_TTL,
                         "endpoint": spec["endpoint"], "organization": spec["organization"], "receipt_verified": False}
                for key in issued:
                    db.execute("INSERT INTO issued_keys (id,package_id,created_at,scope,expiration,target_label,package_name,package_os,organization) VALUES (?,?,?,?,?,?,?,?,?)",
                        (key["id"], row["package_id"], datetime.now(timezone.utc).isoformat(), key["scope"], key["expiration"],
                         row["target_label"], spec["name"], spec["os"], spec["organization"]))
                db.execute("UPDATE enrollments SET state='issued',sealed=?,key_ids=? WHERE id=?",
                    (envelope(attempt).encrypt(json.dumps(reply).encode()), json.dumps([{k: v for k, v in key.items() if k != "key"} for key in issued]), sid))
            return reply
        except Exception:
            try:
                self.cancel(sid)
            except Exception:
                pass
            raise EnrollmentError("enrollment_issue_failed", 503, "설치 키 발급을 완료하지 못했습니다. 취소/폐기 상태를 확인하고 새 토큰을 발급하세요.") from None

    def cancel(self, sid):
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute("SELECT * FROM enrollments WHERE id=?", (sid,)).fetchone()
            if row is None:
                raise KeyError(sid)
            if row["state"] == "complete":
                raise EnrollmentError("enrollment_complete", 409, "수신 확인된 설치는 발급 키 관리에서 개별 폐기하세요.")
            if row["state"] in ("cancelled", "expired"):
                return self.public(row)
            failed = False
            if row["attempt_hash"]:
                for scope in self.scopes(json.loads(row["spec"])):
                    name = self.key_name(sid, scope)
                    try:
                        result = self.issuer.security.invalidate_api_key(name=name, owner=True)
                        if type(result.get("error_count")) is not int or result["error_count"] != 0:
                            raise RuntimeError("Invalid cleanup response")
                        keys = self.issuer.security.get_api_key(name=name, owner=True).get("api_keys")
                        if not isinstance(keys, list) or any(k.get("name") != name or k.get("invalidated") is not True for k in keys):
                            raise RuntimeError("Unverified cleanup")
                        for k in keys:
                            db.execute("UPDATE issued_keys SET revoked_at=COALESCE(revoked_at,?),server_state='revoked' WHERE id=?",
                                       (datetime.now(timezone.utc).isoformat(), k["id"]))
                    except Exception:
                        failed = True
            db.execute("UPDATE enrollments SET state=?,sealed=NULL WHERE id=?", ("cleanup_pending" if failed else "cancelled", sid))
        if failed:
            raise EnrollmentError("cleanup_pending", 503, "실패한 설치 키의 폐기를 확인하지 못했습니다. 취소를 다시 시도하세요.")
        return {**self.public(row), "state": "cancelled"}

    def session(self, token, attempt):
        with self.store.connect() as db:
            row = self.authenticate(db, token, attempt)
        if row["state"] not in ("issued", "complete"):
            raise EnrollmentError("enrollment_unavailable", 409, "설치 세션을 사용할 수 없습니다.")
        if row["deadline"] <= int(self.clock()):
            if row["state"] != "complete":
                self.cancel(row["id"])
            raise EnrollmentError("enrollment_expired", 410, "수신 확인 시간이 만료되었습니다.")
        return row

    def abort(self, token, data):
        if not isinstance(data, dict) or set(data) != {"attempt"}:
            raise ValueError("설치 재시도 식별자만 전달하세요.")
        with self.store.connect() as db:
            row = self.authenticate(db, token, data["attempt"])
        return self.cancel(row["id"])

    def receipt(self, token, data):
        if not isinstance(data, dict) or set(data) != {"attempt", "agents"}:
            raise ValueError("설치 시도와 수집기 ID만 전달하세요.")
        row = self.session(token, data["attempt"])
        spec = json.loads(row["spec"])
        agents = data["agents"]
        if (not isinstance(agents, dict) or set(agents) != set(self.scopes(spec))
                or any(not isinstance(v, str) or not re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", v) for v in agents.values())
                or len(set(agents.values())) != len(agents)):
            raise ValueError("패키지에 필요한 각 수집기의 고유 ID를 전달하세요.")
        with self.store.connect() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self.authenticate(db, token, data["attempt"])
            if current["state"] not in ("issued", "complete"):
                raise EnrollmentError("enrollment_unavailable", 409, "설치 세션을 사용할 수 없습니다.")
            if current["agents"] and json.loads(current["agents"]) != agents:
                raise EnrollmentError("agent_mismatch", 409, "최초 수신 확인에 등록한 수집기 ID와 다릅니다.")
            db.execute("UPDATE enrollments SET agents=? WHERE id=?", (json.dumps(agents, sort_keys=True), row["id"]))
        if row["state"] == "complete":
            return {"verified": True, "state": "complete", "id": row["id"]}
        if self.monitor is None:
            raise EnrollmentError("receipt_unavailable", 503, "중앙 수신 조회 계정이 준비되지 않았습니다.")
        self.check_pipeline()
        received = []
        platform = "windows" if spec["os"] == "windows" else "linux"
        try:
            for key in json.loads(row["key_ids"]):
                scope = key["scope"]
                terms = {"agent.id": agents[scope], "agent.type": "filebeat" if scope == "host" else "packetbeat",
                         "organization.id": spec["organization"], "labels.installation_probe": row["nonce"],
                         f"{PROOF_FIELD}.id": row["id"], f"{PROOF_FIELD}.key_id": key["id"],
                         f"{PROOF_FIELD}.scope": scope, f"{PROOF_FIELD}.package_id": row["package_id"]}
                if scope == "host":
                    terms["event.action"] = "installation_probe"
                else:
                    terms.update({"event.dataset": "flow", "network.transport": "tcp"})
                index = f"soc-host-raw-{platform}-*,soc-agent-health-*" if scope == "host" else f"soc-network-{platform}-*"
                result = self.monitor.search(index=index, size=1, track_total_hits=True,
                    allow_no_indices=True, ignore_unavailable=True,
                    query={"bool": {"filter": [{"term": {f: v}} for f, v in terms.items()] + [{"range": {"event.ingested": {
                        "gte": datetime.fromtimestamp(row["created"], timezone.utc).isoformat(),
                        "lte": datetime.fromtimestamp(row["deadline"], timezone.utc).isoformat()}}}]}},
                    source=False, allow_partial_search_results=False)
                if result.get("timed_out") is not False or result.get("_shards", {}).get("failed") != 0:
                    raise RuntimeError("Incomplete receipt search")
                total = result["hits"]["total"]
                if total["relation"] != "eq" or type(total["value"]) is not int or total["value"] < 0:
                    raise RuntimeError("Invalid receipt count")
                if total["value"] > 0:
                    from cloud_soc.portal.status_setup import PIPELINE_ID
                    hits = result["hits"]["hits"]
                    if len(hits) != 1 or not isinstance(hits[0].get("_index"), str):
                        raise RuntimeError("Missing proof index")
                    proof_index = hits[0]["_index"]
                    if not proof_index.startswith(tuple(pattern.rstrip("*") for pattern in index.split(","))):
                        raise RuntimeError("Unexpected proof index")
                    configured = self.monitor.indices.get_settings(index=proof_index, flat_settings=True)
                    if configured[proof_index]["settings"].get("index.final_pipeline") != PIPELINE_ID:
                        raise RuntimeError("Untrusted proof index")
                    received.append(scope)
        except Exception:
            raise EnrollmentError("receipt_unavailable", 503, "중앙 수신을 확인하지 못했습니다. 설치 성공으로 처리하지 마세요.") from None
        verified = set(received) == set(agents)
        if verified:
            with self.store.connect() as db:
                db.execute("BEGIN IMMEDIATE")
                current = self.authenticate(db, token, data["attempt"])
                if current["state"] != "issued" or current["deadline"] <= int(self.clock()):
                    raise EnrollmentError("enrollment_unavailable", 409, "수신 확인 도중 설치 세션이 종료되었습니다.")
                db.execute("UPDATE enrollments SET state='complete',completed=?,sealed=NULL WHERE id=?", (int(self.clock()), row["id"]))
        return {"id": row["id"], "verified": verified, "state": "complete" if verified else "awaiting_receipt", "received": received}
