"""Worker configuration immutability and durable checkpoint storage backends."""

from abc import ABC, abstractmethod
from contextlib import closing, contextmanager
import json
import sqlite3
from typing import Any, Iterator

from cloud_soc.processing.continuation_store import (
    ContinuationStateStore,
    RedisContinuationStore,
    SqliteContinuationStore,
)
from cloud_soc.storage_backend import get_redis_client, get_state_backend_type


class WorkerStateStore(ABC):
    """정규화 워커의 설정 불변성, 체크포인트, continuation 상태를 관리하는 추상 저장소"""

    @contextmanager
    @abstractmethod
    def session(self) -> Iterator[None]:
        """리소스 오픈 및 분산 환경의 경우 작업 단위 Lease(락)를 획득합니다."""
        yield

    @abstractmethod
    def ensure_immutable_config(
        self,
        *,
        scope: str,
        initial_iso: str,
        receipt_lag_seconds: int,
        overlap_seconds: int,
        web_start_iso: str | None,
        ssh_start_iso: str | None,
    ) -> None:
        pass

    @abstractmethod
    def load_checkpoint(self) -> tuple[str, str | None] | None:
        """(checkpoint_iso, last_success_iso) 반환. 최초 실행 시 None."""
        pass

    @abstractmethod
    def commit_checkpoint(
        self,
        checkpoint_iso: str,
        last_success_iso: str | None,
        *,
        clear_continuation: bool,
    ) -> None:
        pass

    @abstractmethod
    def commit_catching_up(self, meta: dict[str, Any]) -> None:
        pass

    @abstractmethod
    def rollback(self) -> None:
        pass

    @abstractmethod
    def continuation_store(self) -> ContinuationStateStore:
        pass


class SqliteWorkerStateStore(WorkerStateStore):
    """기존 로컬 state_path(SQLite) 및 모든 기존 단위 테스트와 100% 호환되는 구현체"""

    def __init__(self, state_path: Any) -> None:
        self.state_path = state_path
        self._db: sqlite3.Connection | None = None
        self._cont_store: SqliteContinuationStore | None = None

    @contextmanager
    def session(self) -> Iterator[None]:
        with closing(sqlite3.connect(self.state_path, timeout=0)) as db:
            self._db = db
            self._cont_store = SqliteContinuationStore(db)
            try:
                yield
            finally:
                self._db = None
                self._cont_store = None

    def _conn(self) -> sqlite3.Connection:
        if self._db is None:
            raise RuntimeError("WorkerStateStore session is not active")
        return self._db

    def ensure_immutable_config(
        self,
        *,
        scope: str,
        initial_iso: str,
        receipt_lag_seconds: int,
        overlap_seconds: int,
        web_start_iso: str | None,
        ssh_start_iso: str | None,
    ) -> None:
        db = self._conn()
        db.execute("CREATE TABLE IF NOT EXISTS target_config (id INTEGER PRIMARY KEY CHECK(id=1), scope TEXT NOT NULL)")
        saved_scope = db.execute("SELECT scope FROM target_config WHERE id=1").fetchone()
        if saved_scope and saved_scope[0] != scope:
            raise ValueError("Processing scope cannot change for an existing checkpoint")
        db.execute("INSERT OR IGNORE INTO target_config VALUES(1,?)", (scope,))

        db.execute("CREATE TABLE IF NOT EXISTS state (id INTEGER PRIMARY KEY CHECK(id=1), checkpoint TEXT, last_success TEXT)")
        db.execute("CREATE TABLE IF NOT EXISTS config (id INTEGER PRIMARY KEY CHECK(id=1), initial_start TEXT NOT NULL)")
        configured = db.execute("SELECT initial_start FROM config WHERE id=1").fetchone()

        db.execute(
            "CREATE TABLE IF NOT EXISTS receipt_policy (id INTEGER PRIMARY KEY CHECK(id=1), lag INTEGER NOT NULL, overlap INTEGER NOT NULL)"
        )
        policy = db.execute("SELECT lag,overlap FROM receipt_policy WHERE id=1").fetchone()
        if (policy and tuple(policy) != (receipt_lag_seconds, overlap_seconds)) or (
            not policy and configured and (receipt_lag_seconds, overlap_seconds) != (30, 900)
        ):
            raise ValueError("Receipt policy changes require separate explicit state")
        db.execute("INSERT OR IGNORE INTO receipt_policy VALUES(1,?,?)", (receipt_lag_seconds, overlap_seconds))

        if configured and configured[0] != initial_iso:
            raise ValueError("Initial start cannot change for an existing state file")
        db.execute("INSERT OR IGNORE INTO config VALUES (1,?)", (initial_iso,))

        db.execute("CREATE TABLE IF NOT EXISTS adapter_config (name TEXT PRIMARY KEY, start TEXT NOT NULL)")
        saved_web = db.execute("SELECT start FROM adapter_config WHERE name='web_access_site_v2'").fetchone()
        if saved_web and (web_start_iso is None or saved_web[0] != web_start_iso):
            raise ValueError("Site adapter start cannot change for an existing state file")
        if web_start_iso is not None and not saved_web:
            if configured:
                raise ValueError("Site adapter adoption requires a new explicit state file; retain the old checkpoint")
            db.execute("INSERT INTO adapter_config VALUES ('web_access_site_v2',?)", (web_start_iso,))

        saved_ssh = db.execute("SELECT start FROM adapter_config WHERE name='linux_ssh_v2'").fetchone()
        if saved_ssh and (ssh_start_iso is None or saved_ssh[0] != ssh_start_iso):
            raise ValueError("SSH adapter start cannot change for an existing state file")
        if ssh_start_iso is not None:
            db.execute("INSERT OR IGNORE INTO adapter_config VALUES ('linux_ssh_v2',?)", (ssh_start_iso,))

        db.commit()
        db.execute("BEGIN IMMEDIATE")

    def load_checkpoint(self) -> tuple[str, str | None] | None:
        row = self._conn().execute("SELECT checkpoint,last_success FROM state WHERE id=1").fetchone()
        return (row[0], row[1]) if row else None

    def commit_checkpoint(
        self,
        checkpoint_iso: str,
        last_success_iso: str | None,
        *,
        clear_continuation: bool,
    ) -> None:
        db = self._conn()
        db.execute("INSERT OR REPLACE INTO state VALUES (1,?,?)", (checkpoint_iso, last_success_iso))
        if clear_continuation:
            self.continuation_store().clear()
        db.commit()

    def commit_catching_up(self, meta: dict[str, Any]) -> None:
        self.continuation_store().save_progress(meta)
        self._conn().commit()

    def rollback(self) -> None:
        self._conn().rollback()

    def continuation_store(self) -> ContinuationStateStore:
        if self._cont_store is None:
            raise RuntimeError("WorkerStateStore session is not active")
        return self._cont_store


class RedisWorkerStateStore(WorkerStateStore):
    """K8s 무상태 워커용 Redis 저장소 (status_id별 격리 + 분산 Lease)"""

    def __init__(self, status_id: str, namespace: str = "cloud_soc:worker", lock_timeout: int = 120) -> None:
        self.redis = get_redis_client()
        self.status_id = status_id
        self.prefix = f"{namespace}:{status_id}"
        self.config_key = f"{self.prefix}:config"
        self.state_key = f"{self.prefix}:state"
        self.lock_key = f"{self.prefix}:lease"
        self.lock_timeout = lock_timeout
        self._cont_store = RedisContinuationStore(stream_id=status_id)

    @contextmanager
    def session(self) -> Iterator[None]:
        distributed_lock = self.redis.lock(self.lock_key, timeout=self.lock_timeout, blocking=False)
        if not distributed_lock.acquire(blocking=False):
            raise TimeoutError(f"Another worker holds processing lease: {self.lock_key}")
        try:
            yield
        finally:
            try:
                distributed_lock.release()
            except Exception:
                pass

    def ensure_immutable_config(
        self,
        *,
        scope: str,
        initial_iso: str,
        receipt_lag_seconds: int,
        overlap_seconds: int,
        web_start_iso: str | None,
        ssh_start_iso: str | None,
    ) -> None:
        raw = self.redis.get(self.config_key)
        cfg = json.loads(raw) if raw else {}

        if "scope" in cfg and cfg["scope"] != scope:
            raise ValueError("Processing scope cannot change for an existing checkpoint")
        cfg.setdefault("scope", scope)

        configured = "initial_start" in cfg
        saved_policy = cfg.get("receipt_policy")
        if (saved_policy and tuple(saved_policy) != (receipt_lag_seconds, overlap_seconds)) or (
            not saved_policy and configured and (receipt_lag_seconds, overlap_seconds) != (30, 900)
        ):
            raise ValueError("Receipt policy changes require separate explicit state")
        cfg.setdefault("receipt_policy", [receipt_lag_seconds, overlap_seconds])

        if configured and cfg["initial_start"] != initial_iso:
            raise ValueError("Initial start cannot change for an existing state file")
        cfg.setdefault("initial_start", initial_iso)

        adapters = cfg.setdefault("adapters", {})
        saved_web = adapters.get("web_access_site_v2")
        if saved_web and (web_start_iso is None or saved_web != web_start_iso):
            raise ValueError("Site adapter start cannot change for an existing state file")
        if web_start_iso is not None and not saved_web:
            if configured:
                raise ValueError("Site adapter adoption requires a new explicit state file; retain the old checkpoint")
            adapters["web_access_site_v2"] = web_start_iso

        saved_ssh = adapters.get("linux_ssh_v2")
        if saved_ssh and (ssh_start_iso is None or saved_ssh != ssh_start_iso):
            raise ValueError("SSH adapter start cannot change for an existing state file")
        if ssh_start_iso is not None:
            adapters.setdefault("linux_ssh_v2", ssh_start_iso)

        self.redis.set(self.config_key, json.dumps(cfg))

    def load_checkpoint(self) -> tuple[str, str | None] | None:
        raw = self.redis.get(self.state_key)
        if not raw:
            return None
        data = json.loads(raw)
        return (data["checkpoint"], data.get("last_success"))

    def commit_checkpoint(
        self,
        checkpoint_iso: str,
        last_success_iso: str | None,
        *,
        clear_continuation: bool,
    ) -> None:
        pipe = self.redis.pipeline()
        pipe.set(self.state_key, json.dumps({"checkpoint": checkpoint_iso, "last_success": last_success_iso}))
        if clear_continuation:
            pipe.delete(self._cont_store.progress_key, self._cont_store.seen_key)
        pipe.execute()

    def commit_catching_up(self, meta: dict[str, Any]) -> None:
        self._cont_store.save_progress(meta)

    def rollback(self) -> None:
        pass

    def continuation_store(self) -> ContinuationStateStore:
        return self._cont_store


def resolve_worker_state_store(state_path_or_store: Any, *, status_id: str) -> WorkerStateStore:
    if isinstance(state_path_or_store, WorkerStateStore):
        return state_path_or_store
    if state_path_or_store is None or get_state_backend_type() == "redis":
        return RedisWorkerStateStore(status_id=status_id)
    return SqliteWorkerStateStore(state_path_or_store)