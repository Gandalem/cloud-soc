"""Runtime storage backend selector and shared client factories."""

from functools import lru_cache
import os
from typing import Any


def get_state_backend_type() -> str:
    """K8s 운영 환경에서는 'redis', 로컬 개발 및 기본 테스트에서는 'local'을 반환합니다."""
    return os.getenv("CLOUD_SOC_STATE_BACKEND", "local").strip().lower()


@lru_cache(maxsize=1)
def get_redis_client() -> Any:
    """단일 Redis 커넥션 풀을 생성·재사용합니다. (local 모드 의존성 충돌 방지를 위해 지연 임포트)"""
    import redis

    redis_url = os.getenv("REDIS_URL", "redis://cloud-soc-redis:6379/0")
    return redis.Redis.from_url(
        redis_url,
        decode_responses=True,
        socket_timeout=5.0,
        retry_on_timeout=True,
    )


@lru_cache(maxsize=1)
def get_es_client() -> Any:
    """단일 Elasticsearch 클라이언트를 생성·재사용합니다."""
    from elasticsearch import Elasticsearch

    es_hosts = [
        host.strip()
        for host in os.getenv("ELASTICSEARCH_HOSTS", "http://cloud-soc-es:9200").split(",")
        if host.strip()
    ]
    return Elasticsearch(
        es_hosts,
        basic_auth=(
            os.getenv("ELASTIC_USER", "elastic"),
            os.getenv("ELASTIC_PASSWORD", ""),
        ),
    )