import argparse
import hashlib
import json
import time
from typing import Any

from elasticsearch import Elasticsearch

from cloud_soc.detection.engine import (
    run_detection_from_elasticsearch,
)
from cloud_soc.elastic.client import (
    create_elasticsearch_client,
)
from cloud_soc.elastic.repository import (
    ensure_normalized_index,
    ensure_security_alerts_index,
    fetch_raw_events,
    save_normalized_event,
    save_security_alert,
)
from cloud_soc.normalizers.ecs import (
    normalize_linux_auth_event,
)
from cloud_soc.parsers.linux_auth import (
    parse_linux_auth_line,
)


# ============================================================
# CONFIG
# ============================================================

RAW_INDEX_PATTERN = "raw-logs-*"

NORMALIZED_INDEX = "normalized-events"

ALERT_INDEX = "security-alerts"

DEFAULT_ORGANIZATION_ID = "oci-dev"


def make_stable_id(*values: str) -> str:
    """
    같은 데이터를 처리했을 때 항상 같은 Elasticsearch ID를 만든다.

    이것이 필요한 이유:

    프로그램 실행 1회
        → 로그 저장

    프로그램 실행 2회
        → 같은 로그를 또 저장

    같은 상황에서 문서가 계속 복제되는 것을 방지한다.

    TODO:
    추후 checkpoint 시스템을 추가하면
    처리 효율도 함께 개선한다.
    """

    joined = "|".join(values)

    return hashlib.sha256(
        joined.encode("utf-8")
    ).hexdigest()


def build_security_alert(
    detection: dict[str, Any],
) -> dict[str, Any]:
    """
    Detection Engine 결과를 security-alerts에
    저장할 문서 형태로 변환한다.
    """

    alert_config = detection.get(
        "alert",
        {},
    )

    group = detection.get(
        "group",
        {},
    )

    source_ip = group.get(
        "source.ip"
    )

    document: dict[str, Any] = {
        # 탐지를 발생시킨 마지막 이벤트 시간
        "@timestamp": detection["window_end"],

        "event": {
            "kind": "alert",

            "category": [
                alert_config.get(
                    "category",
                    "authentication",
                )
            ],
        },

        "rule": {
            "id": detection["rule_id"],
            "name": detection["rule_name"],
        },

        "organization": {
            # CONFIG:
            # 현재는 OCI 서버 한 대이므로 고정값.
            #
            # TODO:
            # 다중 회사 지원 시 이벤트의 organization.id를
            # Detection 결과까지 전달하도록 변경한다.
            "id": DEFAULT_ORGANIZATION_ID,
        },

        "cloud_soc": {
            "alert_title": alert_config.get(
                "title",
                detection["rule_name"],
            ),

            "severity": detection["severity"],

            "event_count": detection["event_count"],

            "threshold": detection["threshold"],

            "time_window_seconds": (
                detection["time_window_seconds"]
            ),

            "window_start": detection["window_start"],

            "window_end": detection["window_end"],
        },

        "message": alert_config.get(
            "message",
            detection["rule_name"],
        ),

        "tags": alert_config.get(
            "tags",
            [],
        ),

        "mitre": detection.get(
            "mitre",
            {},
        ),
    }

    if source_ip:
        document["source"] = {
            "ip": source_ip,
        }

    return document


def process_raw_logs(
    client: Elasticsearch,
) -> tuple[int, int]:
    """
    raw-logs
        ↓
    Parser
        ↓
    ECS Normalizer
        ↓
    normalized-events
    """

    raw_events = fetch_raw_events(
        client=client,
        index_pattern=RAW_INDEX_PATTERN,
    )

    processed_count = 0
    skipped_count = 0

    for raw_event in raw_events:

        source = raw_event["_source"]

        # ----------------------------------------------------
        # Filebeat에서 지정한 로그 종류 확인
        # ----------------------------------------------------

        labels = source.get(
            "labels",
            {},
        )

        if not isinstance(labels, dict):
            skipped_count += 1
            continue

        if labels.get("log_source") != "linux_auth":
            skipped_count += 1
            continue

        # ----------------------------------------------------
        # 원본 auth.log 문자열
        # ----------------------------------------------------

        message = source.get(
            "message"
        )

        if not isinstance(message, str):
            skipped_count += 1
            continue

        # ----------------------------------------------------
        # Parser
        # ----------------------------------------------------

        parsed_event = parse_linux_auth_line(
            message
        )

        if parsed_event is None:
            skipped_count += 1
            continue

        # ----------------------------------------------------
        # organization.id
        # ----------------------------------------------------

        organization = source.get(
            "organization",
            {},
        )

        if isinstance(organization, dict):
            organization_id = organization.get(
                "id",
                DEFAULT_ORGANIZATION_ID,
            )
        else:
            organization_id = (
                DEFAULT_ORGANIZATION_ID
            )

        # ----------------------------------------------------
        # ECS Normalizer
        # ----------------------------------------------------

        normalized_event = (
            normalize_linux_auth_event(
                parsed_event,
                organization_id=organization_id,
            )
        )

        # ----------------------------------------------------
        # 중복 저장 방지 ID
        #
        # raw index + raw document ID를 이용하므로
        # 같은 raw 로그를 다시 읽어도 같은 ID가 만들어진다.
        # ----------------------------------------------------

        normalized_id = make_stable_id(
            raw_event["_index"],
            raw_event["_id"],
        )

        save_normalized_event(
            client=client,
            index_name=NORMALIZED_INDEX,
            event=normalized_event,
            document_id=normalized_id,

            # 여러 문서를 저장한 뒤 한 번만 refresh한다.
            refresh=False,
        )

        processed_count += 1

    if processed_count > 0:
        client.indices.refresh(
            index=NORMALIZED_INDEX,
        )

    return (
        processed_count,
        skipped_count,
    )


def process_detections(
    client: Elasticsearch,
) -> int:
    """
    normalized-events
        ↓
    Detection Engine
        ↓
    security-alerts
    """

    detections = (
        run_detection_from_elasticsearch(
            client=client,
            index_name=NORMALIZED_INDEX,
        )
    )

    for detection in detections:

        alert_document = build_security_alert(
            detection
        )

        # 같은 Detection 결과를 다시 처리해도
        # 같은 Alert ID가 만들어진다.
        alert_id = make_stable_id(
            "alert",
            detection["rule_id"],

            json.dumps(
                detection["group"],
                ensure_ascii=False,
                sort_keys=True,
            ),

            detection["window_start"],
            detection["window_end"],
        )

        response = save_security_alert(
            client=client,
            index_name=ALERT_INDEX,
            alert=alert_document,
            document_id=alert_id,
            refresh=False,
        )

        print()
        print("🚨 Security Alert")
        print(
            "Rule:",
            detection["rule_id"],
            detection["rule_name"],
        )
        print(
            "Severity:",
            detection["severity"],
        )
        print(
            "Group:",
            detection["group"],
        )
        print(
            "Event Count:",
            detection["event_count"],
        )
        print(
            "Elasticsearch:",
            response["result"],
        )

    if detections:
        client.indices.refresh(
            index=ALERT_INDEX,
        )

    return len(detections)


def run_pipeline_once(
    client: Elasticsearch,
) -> None:
    """
    Cloud SOC 1차 MVP 전체 파이프라인을 한 번 실행한다.
    """

    ensure_normalized_index(
        client=client,
        index_name=NORMALIZED_INDEX,
    )

    ensure_security_alerts_index(
        client=client,
        index_name=ALERT_INDEX,
    )

    normalized_count, skipped_count = (
        process_raw_logs(
            client
        )
    )

    detection_count = process_detections(
        client
    )

    print()
    print("=" * 60)
    print("Cloud SOC MVP 처리 완료")
    print("=" * 60)

    print(
        f"정규화 처리: {normalized_count}"
    )

    print(
        f"지원하지 않는 로그: {skipped_count}"
    )

    print(
        f"탐지 결과: {detection_count}"
    )


def main() -> None:
    """
    기본:
        파이프라인 1회 실행

    --watch:
        일정 간격으로 계속 실행

    TEST:
    MVP 데모에서는 --watch 모드를 사용한다.

    TODO:
    운영 단계에서는 Polling 대신
    checkpoint / queue / streaming 구조를 검토한다.
    """

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--watch",
        action="store_true",
        help="Cloud SOC 파이프라인을 반복 실행",
    )

    parser.add_argument(
        "--interval",
        type=int,
        default=5,
        help="반복 실행 간격(초)",
    )

    args = parser.parse_args()

    client = create_elasticsearch_client()

    try:

        if not args.watch:
            run_pipeline_once(
                client
            )
            return

        print(
            "Cloud SOC 실시간 MVP 시작"
        )

        print(
            f"처리 간격: {args.interval}초"
        )

        print(
            "종료: Ctrl + C"
        )

        while True:

            run_pipeline_once(
                client
            )

            time.sleep(
                max(
                    args.interval,
                    1,
                )
            )

    except KeyboardInterrupt:
        print()
        print(
            "Cloud SOC 종료"
        )

    except Exception as error:
        print()
        print(
            "Cloud SOC 처리 중 오류 발생"
        )
        print(
            f"오류 내용: {error}"
        )

    finally:
        client.close()


if __name__ == "__main__":
    main()