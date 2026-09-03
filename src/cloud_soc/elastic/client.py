import os
from pathlib import Path

from dotenv import load_dotenv
from elasticsearch import Elasticsearch


# 프로젝트 최상위 폴더 위치를 찾는다.
# client.py -> elastic -> cloud_soc -> src -> Cloud-SOC
PROJECT_ROOT = Path(__file__).resolve().parents[3]

# 프로젝트 최상위의 .env 파일을 불러온다.
load_dotenv(PROJECT_ROOT / ".env")


def create_elasticsearch_client() -> Elasticsearch:
    """
    Elasticsearch와 통신하기 위한 클라이언트를 생성한다.
    """

    # CONFIG:
    # 실제 Elasticsearch 주소는 .env에서 관리한다.
    # 값이 없으면 개발환경 기본값인 localhost:9200을 사용한다.
    elasticsearch_url = os.getenv(
        "ELASTICSEARCH_URL",
        "http://localhost:9200",
    )

    # SECURITY:
    # 계정 정보는 Python 코드에 직접 작성하지 않는다.
    # 추후 Elasticsearch 보안 기능을 활성화하면 .env에서 읽어 사용한다.
    username = os.getenv("ELASTICSEARCH_USERNAME", "")
    password = os.getenv("ELASTICSEARCH_PASSWORD", "")

    # username과 password 중 하나만 입력된 경우
    # 잘못된 설정이므로 오류를 발생시킨다.
    if bool(username) != bool(password):
        raise ValueError(
            "ELASTICSEARCH_USERNAME과 "
            "ELASTICSEARCH_PASSWORD는 함께 설정해야 합니다."
        )

    # Elasticsearch 연결 옵션
    options = {
        "request_timeout": 10,
    }

    # SECURITY:
    # 현재 개발 단계에서는 Elasticsearch 인증을 꺼두었기 때문에
    # username/password가 비어 있어도 정상이다.
    #
    # TODO:
    # 최종 프로젝트에서는 Elasticsearch 보안 기능을 활성화하고
    # Basic Auth 또는 API Key 방식으로 변경할 예정이다.
    if username and password:
        options["basic_auth"] = (username, password)

    client = Elasticsearch(
        elasticsearch_url,
        **options,
    )

    return client


def check_elasticsearch_connection(client: Elasticsearch) -> bool:
    """
    Elasticsearch 서버와 정상적으로 통신 가능한지 확인한다.
    """

    try:
        # TEST:
        # Elasticsearch 서버 정보를 요청해서
        # 정상적인 응답이 오는지 확인한다.
        info = client.info()

        print("Elasticsearch 연결 성공")
        print(f"클러스터 이름: {info['cluster_name']}")
        print(f"Elasticsearch 버전: {info['version']['number']}")

        return True

    except Exception as error:
        print("Elasticsearch 연결 실패")
        print(f"오류 내용: {error}")

        return False


if __name__ == "__main__":
    # 이 파일을 직접 실행했을 때만 연결 테스트를 수행한다.
    es_client = create_elasticsearch_client()

    try:
        success = check_elasticsearch_connection(es_client)
        raise SystemExit(0 if success else 1)
    
    finally:
        # 사용이 끝난 연결을 정리한다.
        es_client.close()