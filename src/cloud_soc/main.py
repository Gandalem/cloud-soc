from datetime import datetime, timezone

from cloud_soc.elastic.client import create_elasticsearch_client
from cloud_soc.elastic.repository import get_document, save_document


def main() -> None:
    """
    Cloud SOC 프로그램 시작점.

    현재 단계에서는 Elasticsearch 저장/조회 테스트만 수행한다.

    TODO:
    추후에는 아래 흐름으로 변경할 예정이다.

    raw-logs
        ↓
    Parser
        ↓
    Normalizer
        ↓
    Detection Engine
        ↓
    security-alerts
    """

    client = create_elasticsearch_client()

    # TEST:
    # 현재 Elasticsearch 연결 및 저장 기능 검증용 인덱스다.
    # 실제 로그 수집 단계에서는 raw-logs-* 구조로 변경할 예정이다.
    test_index = "cloud-soc-test"

    # TEST:
    # 실제 SSH 로그가 아니라 Elasticsearch 저장 확인용 가짜 이벤트다.
    test_document = {
        "@timestamp": datetime.now(timezone.utc).isoformat(),

        "event": {
            "category": "authentication",
            "action": "connection_test",
            "outcome": "success",
        },

        "source": {
            "ip": "127.0.0.1",
        },

        "user": {
            "name": "cloud-soc-test",
        },

        "message": "Cloud SOC Elasticsearch 저장 테스트",

        "tags": [
            "cloud-soc",
            "test",
        ],
    }

    try:
        # Elasticsearch에 테스트 문서 저장
        save_response = save_document(
            client=client,
            index_name=test_index,
            document=test_document,
        )

        document_id = save_response["_id"]

        print("테스트 데이터 저장 성공")
        print(f"인덱스: {save_response['_index']}")
        print(f"문서 ID: {document_id}")
        print(f"결과: {save_response['result']}")

        # 방금 저장한 문서를 다시 Elasticsearch에서 가져온다.
        saved_document = get_document(
            client=client,
            index_name=test_index,
            document_id=document_id,
        )

        print()
        print("저장된 데이터 확인")
        print(saved_document["_source"])

    except Exception as error:
        print("Elasticsearch 데이터 저장/조회 실패")
        print(f"오류 내용: {error}")

    finally:
        client.close()


if __name__ == "__main__":
    main()