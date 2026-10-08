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

    def secret(name):
        inline, filename = os.getenv(name, ""), os.getenv(name + "_FILE", "")
        if inline and filename:
            raise ValueError("Choose one credential source")
        if filename:
            path = Path(filename)
            if os.name != "nt" and path.stat().st_mode & 0o077:
                raise ValueError("Credential file must be private (chmod 600)")
            inline = path.read_text(encoding="utf-8").strip()
            if not inline:
                raise ValueError("Empty credential file")
        return inline

    elasticsearch_url = os.getenv("ELASTICSEARCH_URL", "http://localhost:9200")
    from urllib.parse import urlsplit
    parsed = urlsplit(elasticsearch_url)
    if (parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username
            or parsed.password or parsed.query or parsed.fragment or parsed.path not in ("", "/")):
        raise ValueError("Elasticsearch URL must be a plain origin")
    username = os.getenv("ELASTICSEARCH_USERNAME", "")
    password = secret("ELASTICSEARCH_PASSWORD")
    api_key = secret("ELASTICSEARCH_API_KEY")
    if bool(username) != bool(password) or api_key and (username or password):
        raise ValueError("Use one complete authentication method")
    if parsed.scheme == "http" and (parsed.hostname not in ("localhost", "127.0.0.1", "::1") or api_key or username):
        raise ValueError("HTTP is permitted only for unauthenticated loopback development")
    options = {"request_timeout": 10, "max_retries": 0}
    ca = os.getenv("ELASTICSEARCH_CA_FILE")
    if ca:
        options["ca_certs"] = ca
    if api_key:
        options["api_key"] = api_key
    elif username:
        options["basic_auth"] = (username, password)
    client = Elasticsearch(elasticsearch_url, **options)

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
        print(f"오류 유형: {type(error).__name__}")

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
