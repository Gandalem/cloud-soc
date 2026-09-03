from typing import Any

from elasticsearch import Elasticsearch


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
) -> dict[str, Any]:
    """
    Elasticsearch에 일반 문서 1건을 저장한다.

    기존 테스트 및 다른 종류의 문서에서도
    사용할 수 있도록 범용 함수로 유지한다.
    """

    response = client.index(
        index=index_name,
        document=document,

        # TEST:
        # 저장 직후 Kibana/검색에서 확인할 수 있도록 기다린다.
        #
        # TODO:
        # 실제 대량 로그 처리 단계에서는
        # 매번 refresh하면 성능이 떨어질 수 있으므로 제거 또는 변경한다.
        refresh="wait_for",
    )

    return response


def save_normalized_event(
    client: Elasticsearch,
    event: dict[str, Any],
    index_name: str = "normalized-events",
) -> dict[str, Any]:
    """
    ECS로 정규화된 이벤트를 normalized-events에 저장한다.
    """

    # 혹시 인덱스가 만들어지지 않은 상태라면
    # 먼저 인덱스를 생성한다.
    ensure_normalized_index(
        client=client,
        index_name=index_name,
    )

    response = save_document(
        client=client,
        index_name=index_name,
        document=event,
    )

    return response


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