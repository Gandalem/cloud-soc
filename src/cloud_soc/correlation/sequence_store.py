from abc import ABC, abstractmethod
from contextlib import contextmanager
import json
from typing import Any, Iterator
from cloud_soc.storage_backend import get_redis_client, get_state_backend_type


class SequenceStateStore(ABC):
    """시퀀스 탐지 상태(failures, last_alert) 저장소 인터페이스"""

    @contextmanager
    @abstractmethod
    def lock(self, rule_id: str, group_key_json: str) -> Iterator[None]:
        """다중 워커 동시 수정 및 중복 경보 방지를 위한 키 단위 락"""
        yield

    @abstractmethod
    def load(self, rule_id: str, group_key_json: str) -> dict[str, Any]:
        pass

    @abstractmethod
    def save(self, rule_id: str, group_key_json: str, state: dict[str, Any], ttl_seconds: int) -> None:
        pass


class DictSequenceStateStore(SequenceStateStore):
    """기존 로컬 dict runtime과 100% 호환되는 인메모리 어댑터"""

    def __init__(self, runtime: dict[str, Any]) -> None:
        self._runtime = runtime

    @contextmanager
    def lock(self, rule_id: str, group_key_json: str) -> Iterator[None]:
        yield

    def load(self, rule_id: str, group_key_json: str) -> dict[str, Any]:
        return self._runtime.setdefault(group_key_json, {"failures": []})

    def save(self, rule_id: str, group_key_json: str, state: dict[str, Any], ttl_seconds: int) -> None:
        self._runtime[group_key_json] = state


class RedisSequenceStateStore(SequenceStateStore):
    """K8s 다중 워커(HPA) 환경용 Redis 기반 분산 시퀀스 상태 저장소"""

    def __init__(self, namespace: str = "cloud_soc:seq_state", lock_timeout: int = 10) -> None:
        self.redis = get_redis_client()
        self.namespace = namespace
        self.lock_timeout = lock_timeout

    def _state_key(self, rule_id: str, group_key_json: str) -> str:
        return f"{self.namespace}:{rule_id}:{group_key_json}"

    def _lock_key(self, rule_id: str, group_key_json: str) -> str:
        return f"{self.namespace}:lock:{rule_id}:{group_key_json}"

    @contextmanager
    def lock(self, rule_id: str, group_key_json: str) -> Iterator[None]:
        distributed_lock = self.redis.lock(
            self._lock_key(rule_id, group_key_json),
            timeout=self.lock_timeout,
            blocking_timeout=5.0,
        )
        acquired = distributed_lock.acquire(blocking=True)
        if not acquired:
            raise TimeoutError(f"Failed to acquire sequence lock: {rule_id}:{group_key_json}")
        try:
            yield
        finally:
            try:
                distributed_lock.release()
            except Exception:
                pass

    def load(self, rule_id: str, group_key_json: str) -> dict[str, Any]:
        raw = self.redis.get(self._state_key(rule_id, group_key_json))
        if not raw:
            return {"failures": []}
        return json.loads(raw)

    def save(self, rule_id: str, group_key_json: str, state: dict[str, Any], ttl_seconds: int) -> None:
        key = self._state_key(rule_id, group_key_json)
        # failures가 비었고 last_alert도 없으면 즉시 키 삭제
        if not state.get("failures") and not state.get("last_alert"):
            self.redis.delete(key)
            return
        self.redis.set(key, json.dumps(state), ex=max(int(ttl_seconds), 60))


def resolve_sequence_store(runtime: dict[str, Any] | SequenceStateStore | None) -> SequenceStateStore:
    if isinstance(runtime, SequenceStateStore):
        return runtime
    if isinstance(runtime, dict):
        return DictSequenceStateStore(runtime)
    if get_state_backend_type() == "redis":
        return RedisSequenceStateStore()
    return DictSequenceStateStore({})