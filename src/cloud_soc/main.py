from pathlib import Path

from cloud_soc.elastic.client import create_elasticsearch_client
from cloud_soc.elastic.repository import (
    ensure_normalized_index,
    save_normalized_event,
)
from cloud_soc.normalizers.ecs import normalize_linux_auth_event
from cloud_soc.parsers.linux_auth import parse_linux_auth_line


# ============================================================
# 프로젝트 최상위 폴더
#
# main.py
# ↓
# cloud_soc
# ↓
# src
# ↓
# cloud-soc
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[2]


# ============================================================
# CONFIG
# ============================================================

# TEST:
# 현재는 OCI에서 가져온 샘플 auth.log를 사용한다.
#
# TODO:
# 추후 실제 운영에서는 sample_logs 파일을 직접 읽지 않고
# Elasticsearch의 raw-logs 인덱스에서 Filebeat 로그를 읽는다.
AUTH_SAMPLE_FILE = (
    PROJECT_ROOT
    / "sample_logs"
    / "linux"
    / "auth.log"
)


# CONFIG:
# 현재 MVP에서 사용할 정규화 이벤트 인덱스.
#
# TODO:
# AWS 배포 단계에서는
# - Data Stream
# - 날짜 기반 Index
# - ILM
# 등을 검토한다.
NORMALIZED_INDEX = "normalized-events"


def main() -> None:
    """
    Cloud SOC 메인 프로그램.

    현재 처리 흐름:

    sample auth.log
           ↓
    Linux SSH Parser
           ↓
    ECS Normalizer
           ↓
    normalized-events
           ↓
    Elasticsearch

    TODO:
    최종 구조:

    raw-logs
       ↓
    Parser
       ↓
    ECS Normalizer
       ↓
    normalized-events
       ↓
    Detection Engine
       ↓
    security-alerts
    """

    client = create_elasticsearch_client()

    try:
        # ----------------------------------------------------
        # 1. normalized-events 인덱스 준비
        # ----------------------------------------------------

        created = ensure_normalized_index(
            client=client,
            index_name=NORMALIZED_INDEX,
        )

        if created:
            print(
                f"인덱스 생성 완료: {NORMALIZED_INDEX}"
            )
        else:
            print(
                f"기존 인덱스 사용: {NORMALIZED_INDEX}"
            )

        # ----------------------------------------------------
        # 2. 테스트용 auth.log 파일 존재 확인
        # ----------------------------------------------------

        if not AUTH_SAMPLE_FILE.exists():
            print(
                "auth.log 샘플 파일을 찾을 수 없습니다."
            )
            print(
                f"경로: {AUTH_SAMPLE_FILE}"
            )
            return

        # ----------------------------------------------------
        # 3. auth.log를 한 줄씩 읽는다.
        # ----------------------------------------------------

        processed_count = 0
        skipped_count = 0

        with AUTH_SAMPLE_FILE.open(
            "r",
            encoding="utf-8",
            errors="replace",
        ) as log_file:

            for line in log_file:

                # --------------------------------------------
                # Parser
                # --------------------------------------------

                parsed_event = parse_linux_auth_line(
                    line
                )

                # 현재 Parser에서 지원하지 않는 로그라면
                # 다음 줄로 넘어간다.
                if parsed_event is None:
                    skipped_count += 1
                    continue

                # --------------------------------------------
                # ECS Normalizer
                # --------------------------------------------

                normalized_event = (
                    normalize_linux_auth_event(
                        parsed_event,

                        # CONFIG:
                        # 현재 OCI 개발 환경 식별자.
                        #
                        # TODO:
                        # 추후 config 파일에서 읽도록 변경한다.
                        organization_id="oci-dev",
                    )
                )

                # --------------------------------------------
                # Elasticsearch 저장
                # --------------------------------------------

                response = save_normalized_event(
                    client=client,
                    index_name=NORMALIZED_INDEX,
                    event=normalized_event,
                )

                processed_count += 1

                print()
                print("정규화 이벤트 저장 성공")
                print(
                    f"문서 ID: {response['_id']}"
                )

                print(
                    "사용자:",
                    normalized_event["user"]["name"],
                )

                print(
                    "Source IP:",
                    normalized_event["source"]["ip"],
                )

                print(
                    "결과:",
                    normalized_event["event"]["outcome"],
                )

        # ----------------------------------------------------
        # 4. 결과 출력
        # ----------------------------------------------------

        print()
        print("=" * 60)
        print("처리 완료")
        print(
            f"정규화 및 저장 성공: {processed_count}"
        )
        print(
            f"지원하지 않아 건너뜀: {skipped_count}"
        )

    except Exception as error:
        print()
        print("Cloud SOC 처리 중 오류 발생")
        print(f"오류 내용: {error}")

    finally:
        client.close()


if __name__ == "__main__":
    main()