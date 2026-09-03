from typing import Any

from elasticsearch import Elasticsearch


def save_document(
    client: Elasticsearch,
    index_name: str,
    document: dict[str, Any],
) -> dict[str, Any]:
    """
    Elasticsearch에 문서 1건을 저장한다.
    """

    # CONFIG:
    # index_name은 나중에 config/app.yml에서 읽도록 변경할 예정이다.
    # 현재는 함수 호출 시 직접 전달한다.

    response = client.index(
        index=index_name,
        document=document,

        # TEST:
        # 저장 직후 바로 검색해서 확인할 수 있도록 기다린다.
        # 실제 대량 로그 처리 단계에서는 성능 때문에 재검토해야 한다.
        refresh="wait_for",
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