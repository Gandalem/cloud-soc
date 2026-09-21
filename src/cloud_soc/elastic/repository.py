from typing import Any

from elasticsearch import ConflictError, Elasticsearch

from cloud_soc.elastic.pagination import fetch_all_hits


PROVENANCE_MAPPING = {"type": "object", "enabled": False}


class ProvenanceMappingError(RuntimeError):
    """An existing index requires explicit, non-destructive schema preparation."""


def ensure_provenance_mapping(
    client: Elasticsearch, index_name: str, *, apply: bool = False,
) -> None:
    """Inspect existing mappings; additions require an explicit setup command."""
    mappings = client.indices.get_mapping(index=index_name)
    missing = []
    for concrete_index, definition in mappings.items():
        field = (definition.get("mappings", {}).get("properties", {})
                 .get("cloud_soc", {}).get("properties", {}).get("provenance"))
        if field is None:
            missing.append(concrete_index)
        elif field.get("enabled") is not False:
            raise ProvenanceMappingError(f"{concrete_index}: incompatible cloud_soc.provenance mapping")
    if missing and not apply:
        raise ProvenanceMappingError(
            "Missing provenance mapping. Review docs/pipeline_reliability.md, then run "
            "python -m cloud_soc.main --prepare-lineage-mappings"
        )
    for concrete_index in missing:
        client.indices.put_mapping(index=concrete_index, properties={
            "cloud_soc": {"properties": {"provenance": PROVENANCE_MAPPING}},
        })


def save_immutable_document(
    client: Elasticsearch, *, index_name: str, document: dict[str, Any],
    document_id: str, refresh: bool | str,
) -> dict[str, Any]:
    """Retries keep the original evidence instead of overwriting old documents."""
    try:
        return client.create(
            index=index_name, id=document_id, document=document, refresh=refresh,
        )
    except ConflictError:
        return {"result": "existing", "_index": index_name, "_id": document_id}


# ============================================================
# normalized-events 인덱스 Mapping
#
# Elasticsearch가 필드 타입을 임의로 추측하지 않고
# 우리가 원하는 보안 로그 구조대로 저장하도록 지정한다.
# ============================================================

NORMALIZED_EVENTS_MAPPING = {
    "properties": {
        "@timestamp": {
            "type": "date",
        },

        "ecs": {
            "properties": {
                "version": {
                    "type": "keyword",
                },
            },
        },

        "event": {
            "properties": {
                "kind": {
                    "type": "keyword",
                },
                "category": {
                    "type": "keyword",
                },
                "type": {
                    "type": "keyword",
                },
                "action": {
                    "type": "keyword",
                },
                "outcome": {
                    "type": "keyword",
                },
                "module": {
                    "type": "keyword",
                },
                "dataset": {
                    "type": "keyword",
                },
                "timezone": {
                    "type": "keyword",
                },
                "reason": {
                    "type": "keyword",
                },

                # 원본 로그는 _source에는 보존하지만
                # 검색용 필드로는 사용하지 않는다.
                "original": {
                    "type": "keyword",
                    "index": False,
                    "doc_values": False,
                },
            },
        },

        "host": {
            "properties": {
                "name": {
                    "type": "keyword",
                },
            },
        },

        "process": {
            "properties": {
                "name": {
                    "type": "keyword",
                },
                "pid": {
                    "type": "long",
                },
            },
        },

        "service": {
            "properties": {
                "name": {
                    "type": "keyword",
                },
                "type": {
                    "type": "keyword",
                },
            },
        },

        "source": {
            "properties": {
                # 중요:
                # 공격자 IP를 문자열이 아닌
                # Elasticsearch IP 타입으로 저장한다.
                "ip": {
                    "type": "ip",
                },
                "port": {
                    "type": "integer",
                },
            },
        },

        "user": {
            "properties": {
                "name": {
                    "type": "keyword",
                },
            },
        },

        "network": {
            "properties": {
                "transport": {
                    "type": "keyword",
                },
                "protocol": {
                    "type": "keyword",
                },
            },
        },

        "organization": {
            "properties": {
                "id": {
                    "type": "keyword",
                },
            },
        },

        # 사람이 원본 내용을 검색할 때 사용하는 필드
        "message": {
            "type": "text",
        },

        "related": {
            "properties": {
                "ip": {
                    "type": "ip",
                },
            },
        },

        # Cloud SOC 프로젝트 전용 필드
        "cloud_soc": {
            "properties": {
                "provenance": PROVENANCE_MAPPING,
                "authentication_method": {
                    "type": "keyword",
                },
            },
        },
    },
}


def ensure_normalized_index(
    client: Elasticsearch,
    index_name: str = "normalized-events",
) -> bool:
    """
    normalized-events 인덱스가 없으면 생성한다.

    반환:
        True  -> 새로 생성함
        False -> 이미 존재함
    """

    # Elasticsearch에 같은 이름의 인덱스가 있는지 확인한다.
    exists_response = client.indices.exists(
        index=index_name,
    )

    if exists_response:
        return False

    # 인덱스가 없다면 ECS에 맞는 Mapping과 함께 생성한다.
    client.indices.create(
        index=index_name,
        mappings=NORMALIZED_EVENTS_MAPPING,
    )

    return True


def save_document(
    client: Elasticsearch,
    index_name: str,
    document: dict[str, Any],
    document_id: str | None = None,
    refresh: bool | str = "wait_for",
) -> dict[str, Any]:
    """
    Elasticsearch에 문서 1건을 저장한다.

    document_id를 지정하면 같은 ID의 문서를 다시 저장할 때
    새 문서를 만들지 않고 기존 문서를 갱신한다.
    """

    if document_id is None:
        return client.index(
            index=index_name,
            document=document,
            refresh=refresh,
        )

    return client.index(
        index=index_name,
        id=document_id,
        document=document,
        refresh=refresh,
    )


def save_normalized_event(
    client: Elasticsearch,
    event: dict[str, Any],
    index_name: str = "normalized-events",
    document_id: str | None = None,
    refresh: bool | str = "wait_for",
    *,
    index_prepared: bool = False,
) -> dict[str, Any]:
    """
    ECS 정규화 이벤트를 저장한다.

    document_id:
    raw-logs 문서에서 만들어진 고정 ID를 사용해
    같은 로그가 중복 저장되는 것을 방지한다.
    """

    if not index_prepared:
        ensure_normalized_index(client=client, index_name=index_name)
        ensure_provenance_mapping(client, index_name)

    if document_id is not None:
        return save_immutable_document(
            client, index_name=index_name, document=event,
            document_id=document_id, refresh=refresh,
        )

    return save_document(
        client=client,
        index_name=index_name,
        document=event,
        document_id=document_id,
        refresh=refresh,
    )


def get_document(
    client: Elasticsearch,
    index_name: str,
    document_id: str,
) -> dict[str, Any]:
    """
    Elasticsearch에서 ID를 이용해 문서 1건을 조회한다.
    """

    response = client.get(
        index=index_name,
        id=document_id,
    )

    return response

# ============================================================
# security-alerts Mapping
# ============================================================

SECURITY_ALERTS_MAPPING = {
    "properties": {
        "@timestamp": {
            "type": "date",
        },

        "event": {
            "properties": {
                "kind": {
                    "type": "keyword",
                },
                "category": {
                    "type": "keyword",
                },
            },
        },

        "rule": {
            "properties": {
                "id": {
                    "type": "keyword",
                },
                "name": {
                    "type": "keyword",
                },
            },
        },

        "source": {
            "properties": {
                "ip": {
                    "type": "ip",
                },
            },
        },

        "organization": {
            "properties": {
                "id": {
                    "type": "keyword",
                },
            },
        },

        "cloud_soc": {
            "properties": {
                "provenance": PROVENANCE_MAPPING,
                "alert_title": {
                    "type": "keyword",
                },
                "severity": {
                    "type": "keyword",
                },
                "event_count": {
                    "type": "integer",
                },
                "threshold": {
                    "type": "integer",
                },
                "time_window_seconds": {
                    "type": "integer",
                },
                "window_start": {
                    "type": "date",
                },
                "window_end": {
                    "type": "date",
                },
            },
        },

        "message": {
            "type": "text",
        },

        "tags": {
            "type": "keyword",
        },

        "mitre": {
            "properties": {
                "tactic": {
                    "type": "keyword",
                },

                "technique": {
                    "properties": {
                        "id": {
                            "type": "keyword",
                        },
                        "name": {
                            "type": "keyword",
                        },
                    },
                },
            },
        },
    },
}

def ensure_security_alerts_index(
    client: Elasticsearch,
    index_name: str = "security-alerts",
) -> bool:
    """
    security-alerts 인덱스가 없으면 생성한다.
    """

    exists_response = client.indices.exists(
        index=index_name,
    )

    if exists_response:
        return False

    client.indices.create(
        index=index_name,
        mappings=SECURITY_ALERTS_MAPPING,
    )

    return True


def save_security_alert(
    client: Elasticsearch,
    alert: dict[str, Any],
    index_name: str = "security-alerts",
    document_id: str | None = None,
    refresh: bool | str = "wait_for",
    *,
    index_prepared: bool = False,
) -> dict[str, Any]:
    """
    Detection Engine에서 발생한 Alert를 저장한다.
    """

    if not index_prepared:
        ensure_security_alerts_index(client=client, index_name=index_name)
        ensure_provenance_mapping(client, index_name)

    if document_id is not None:
        return save_immutable_document(
            client, index_name=index_name, document=alert,
            document_id=document_id, refresh=refresh,
        )

    return save_document(
        client=client,
        index_name=index_name,
        document=alert,
        document_id=document_id,
        refresh=refresh,
    )


def fetch_raw_events(
    client: Elasticsearch,
    index_pattern: str = "raw-logs-*",
    page_size: int = 1000,
) -> list[dict[str, Any]]:
    """Read every raw hit in one PIT snapshot, including hits beyond 10,000."""

    # 아직 Filebeat 로그가 하나도 없다면 빈 목록 반환
    if not client.indices.exists(
        index=index_pattern,
    ):
        return []

    return fetch_all_hits(client, index=index_pattern, page_size=page_size)
