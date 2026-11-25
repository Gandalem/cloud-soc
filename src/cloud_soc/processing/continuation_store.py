"""State store adapters for bounded PIT scan progress and seen-reference deduplication."""

from abc import ABC, abstractmethod
from contextlib import contextmanager
import json
from typing import Any, Iterator

from cloud_soc.storage_backend import get_redis_client, get_state_backend_type

_SQLITE_IN_CHUNK_SIZE = 500


class ContinuationStateStore(ABC):
    """PIT 스캔 진행 상태(progress) 및 처리 완료 해시(seen) 저장소 인터페이스"""

    @abstractmethod
    def init(self) -> None:
        pass

    @abstractmethod
    def load_progress(self) -> dict[str, Any] | None:
        pass

    @abstractmethod
    def save_progress(self, meta: dict[str, Any]) -> None:
        pass

    @abstractmethod
    def filter_seen(self, candidate_ids: list[str]) -> set[str]:
        """후보 해시 목록 중 이미 처리된 ID 집합을 일괄 반환합니다."""
        pass

    @abstractmethod
    def mark_seen(self, seen_ids: list[str]) -> None:
        """처리 완료된 해시 목록을 일괄 기록합니다."""
        pass

    @abstractmethod
    def clear(self) -> None:
        pass

    @contextmanager
    def lease(self) -> Iterator[None]:
        """다중 워커 환경에서 동일 스캔 커서 경합을 막는 분산 락"""
        yield


class SqliteContinuationStore(ContinuationStateStore):
    """기존 로컬 SQLite 연결(db)과 100% 호환되는 어댑터 (배치 조회/삽입 최적화 포함)"""

    def __init__(self, db: Any) -> None:
        self.db = db

    def init(self) -> None:
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS scan_progress (id INTEGER PRIMARY KEY CHECK(id=1), body TEXT NOT NULL)"
        )
        self.db.execute("CREATE TABLE IF NOT EXISTS scan_seen (id TEXT PRIMARY KEY)")

    def load_progress(self) -> dict[str, Any] | None:
        row = self.db.execute("SELECT body FROM scan_progress WHERE id=1").fetchone()
        return json.loads(row[0]) if row else None

    def save_progress(self, meta: dict[str, Any]) -> None:
        self.db.execute("INSERT OR REPLACE INTO scan_progress VALUES(1,?)", (json.dumps(meta),))

    def filter_seen(self, candidate_ids: list[str]) -> set[str]:
        if not candidate_ids:
            return set()
        found: set[str] = set()
        for start in range(0, len(candidate_ids), _SQLITE_IN_CHUNK_SIZE):
            chunk = candidate_ids[start : start + _SQLITE_IN_CHUNK_SIZE]
            placeholders = ",".join("?" for _ in chunk)
            rows = self.db.execute(
                f"SELECT id FROM scan_seen WHERE id IN ({placeholders})",
                chunk,
            ).fetchall()
            found.update(row[0] for row in rows)
        return found

    def mark_seen(self, seen_ids: list[str]) -> None:
        if not seen_ids:
            return
        self.db.executemany(
            "INSERT OR IGNORE INTO scan_seen VALUES(?)",
            [(item,) for item in seen_ids],
        )

    def clear(self) -> None:
        self.db.execute("DELETE FROM scan_progress")
        self.db.execute("DELETE FROM scan_seen")


class RedisContinuationStore(ContinuationStateStore):
    """K8s 무상태 워커용 Redis 기반 스캔 상태 저장소"""

    def __init__(
        self,
        stream_id: str = "default",
        namespace: str = "cloud_soc:proc_scan",
        ttl_seconds: int = 86400,
        lock_timeout: int = 60,
    ) -> None:
        self.redis = get_redis_client()
        self.progress_key = f"{namespace}:{stream_id}:progress"
        self.seen_key = f"{namespace}:{stream_id}:seen"
        self.lock_key = f"{namespace}:{stream_id}:lease"
        self.ttl_seconds = ttl_seconds
        self.lock_timeout = lock_timeout

    def init(self) -> None:
        pass

    def load_progress(self) -> dict[str, Any] | None:
        raw = self.redis.get(self.progress_key)
        return json.loads(raw) if raw else None

    def save_progress(self, meta: dict[str, Any]) -> None:
        pipe = self.redis.pipeline()
        pipe.set(self.progress_key, json.dumps(meta), ex=self.ttl_seconds)
        if self.redis.exists(self.seen_key):
            pipe.expire(self.seen_key, self.ttl_seconds)
        pipe.execute()

    def filter_seen(self, candidate_ids: list[str]) -> set[str]:
        if not candidate_ids:
            return set()
        # Redis 6.2+ SMISMEMBER로 배치 존재 여부를 왕복 1회에 조회
        flags = self.redis.smismember(self.seen_key, candidate_ids)
        return {cid for cid, exists in zip(candidate_ids, flags) if exists}

    def mark_seen(self, seen_ids: list[str]) -> None:
        if not seen_ids:
            return
        pipe = self.redis.pipeline()
        pipe.sadd(self.seen_key, *seen_ids)
        pipe.expire(self.seen_key, self.ttl_seconds)
        pipe.execute()

    def clear(self) -> None:
        self.redis.delete(self.progress_key, self.seen_key)

    @contextmanager
    def lease(self) -> Iterator[None]:
        distributed_lock = self.redis.lock(
            self.lock_key,
            timeout=self.lock_timeout,
            blocking_timeout=5.0,
        )
        if not distributed_lock.acquire(blocking=True):
            raise TimeoutError(f"Another worker holds continuation lease: {self.lock_key}")
        try:
            yield
        finally:
            try:
                distributed_lock.release()
            except Exception:
                pass


def resolve_continuation_store(
    db_or_store: Any,
    *,
    stream_id: str = "default",
) -> ContinuationStateStore:
    if isinstance(db_or_store, ContinuationStateStore):
        return db_or_store
    if db_or_store is not None:
        return SqliteContinuationStore(db_or_store)
    if get_state_backend_type() == "redis":
        return RedisContinuationStore(stream_id=stream_id)
    raise ValueError("A SQLite connection or ContinuationStateStore is required in local mode")