from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from typing import Any

from elasticsearch import Elasticsearch

from cloud_soc.detection.rule_loader import load_rules


def get_field_value(
    document: dict[str, Any],
    field_path: str,
) -> Any:
    """
    ECS의 점(.) 형식 필드 경로를 따라가서 값을 가져온다.

    예:

        source.ip

    document:
        {
            "source": {
                "ip": "203.0.113.10"
            }
        }

    결과:
        203.0.113.10
    """

    current: Any = document

    for part in field_path.split("."):
        if not isinstance(current, dict):
            return None

        if part not in current:
            return None

        current = current[part]

    return current


def condition_matches(
    event: dict[str, Any],
    condition: dict[str, Any],
) -> bool:
    """
    이벤트 하나가 Rule Condition 하나를 만족하는지 확인한다.
    """

    field = condition["field"]
    operator = condition["operator"]
    expected = condition["value"]

    actual = get_field_value(
        event,
        field,
    )

    # --------------------------------------------------------
    # equals
    # --------------------------------------------------------

    if operator == "equals":
        return actual == expected

    # --------------------------------------------------------
    # not_equals
    # --------------------------------------------------------

    if operator == "not_equals":
        return actual != expected

    # --------------------------------------------------------
    # contains
    #
    # ECS event.category처럼 배열인 경우:
    #
    # ["authentication"]
    #
    # 안에 authentication이 있는지 검사한다.
    # --------------------------------------------------------

    if operator == "contains":

        if isinstance(actual, (list, tuple, set)):
            return expected in actual

        if isinstance(actual, str):
            return str(expected) in actual

        return False

    # --------------------------------------------------------
    # in
    #
    # 예:
    #
    # value:
    #   - failure
    #   - unknown
    # --------------------------------------------------------

    if operator == "in":

        if not isinstance(
            expected,
            (list, tuple, set),
        ):
            return False

        return actual in expected

    # --------------------------------------------------------
    # greater_than
    # --------------------------------------------------------

    if operator == "greater_than":
        try:
            return actual > expected

        except TypeError:
            return False

    return False


def event_matches_rule(
    event: dict[str, Any],
    rule: dict[str, Any],
) -> bool:
    """
    이벤트가 Rule의 모든 conditions를 만족하는지 확인한다.

    모든 조건이 AND 관계다.
    """

    conditions = rule.get(
        "conditions",
        [],
    )

    return all(
        condition_matches(
            event,
            condition,
        )
        for condition in conditions
    )


def parse_event_timestamp(
    event: dict[str, Any],
) -> datetime:
    """
    ECS @timestamp를 Python datetime으로 변환한다.

    예:
        2026-09-03T01:45:46+00:00
    """

    value = event.get("@timestamp")

    if not isinstance(value, str):
        raise ValueError(
            "@timestamp가 없거나 문자열이 아닙니다."
        )

    # Python fromisoformat은 일부 환경에서
    # Z 표기를 바로 처리하지 못할 수 있으므로 +00:00으로 변환.
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"

    parsed = datetime.fromisoformat(value)

    # timezone 정보가 없는 데이터가 들어온 경우
    # UTC로 간주한다.
    #
    # SECURITY / 데이터 무결성:
    # 운영환경에서는 timezone 없는 이벤트 자체를
    # 별도로 기록하는 것도 고려한다.
    if parsed.tzinfo is None:
        parsed = parsed.replace(
            tzinfo=timezone.utc
        )

    return parsed


def build_group_key(
    event: dict[str, Any],
    group_by: list[str],
) -> tuple[Any, ...] | None:
    """
    Rule의 group_by 필드를 이용해 그룹 Key를 만든다.

    예:

        group_by:
            - source.ip

    결과:

        ("203.0.113.10",)
    """

    values: list[Any] = []

    for field in group_by:

        value = get_field_value(
            event,
            field,
        )

        # 그룹 기준 값이 없는 이벤트는
        # Threshold 계산에서 제외한다.
        if value is None:
            return None

        values.append(value)

    return tuple(values)


def detect_rule(
    events: list[dict[str, Any]],
    rule: dict[str, Any],
) -> list[dict[str, Any]]:
    """
    특정 Rule 하나를 이벤트 목록에 적용한다.

    처리:

        조건 필터링
             ↓
        group_by
             ↓
        시간 순 정렬
             ↓
        Sliding Window
             ↓
        Threshold 검사
    """

    threshold_count = rule["threshold"]["count"]

    window_seconds = (
        rule["time_window"]["seconds"]
    )

    cooldown_seconds = (
        rule
        .get("cooldown", {})
        .get("seconds", 0)
    )

    group_by = rule["group_by"]

    # --------------------------------------------------------
    # 1. Rule 조건과 일치하는 이벤트를 그룹별로 저장
    # --------------------------------------------------------

    grouped_events: dict[
        tuple[Any, ...],
        list[tuple[datetime, dict[str, Any]]],
    ] = defaultdict(list)

    for event in events:

        if not event_matches_rule(
            event,
            rule,
        ):
            continue

        group_key = build_group_key(
            event,
            group_by,
        )

        if group_key is None:
            continue

        try:
            timestamp = parse_event_timestamp(
                event
            )

        except (ValueError, TypeError):
            # TODO:
            # 운영 단계에서는 잘못된 이벤트를
            # 별도 dead-letter/error 로그로 저장한다.
            continue

        grouped_events[group_key].append(
            (
                timestamp,
                event,
            )
        )

    detections: list[dict[str, Any]] = []

    # --------------------------------------------------------
    # 2. 각 source.ip 그룹별 Threshold 검사
    # --------------------------------------------------------

    for group_key, group_events in grouped_events.items():

        # 반드시 시간순으로 처리한다.
        group_events.sort(
            key=lambda item: item[0]
        )

        # Sliding Window
        window: deque[
            tuple[
                datetime,
                dict[str, Any],
            ]
        ] = deque()

        last_alert_time: datetime | None = None

        for timestamp, event in group_events:

            # 현재 이벤트보다 Time Window 이상 오래된
            # 이벤트를 Window에서 제거한다.
            while window:

                oldest_timestamp = window[0][0]

                if (
                    timestamp
                    - oldest_timestamp
                    <= timedelta(
                        seconds=window_seconds
                    )
                ):
                    break

                window.popleft()

            # 현재 이벤트 추가
            window.append(
                (
                    timestamp,
                    event,
                )
            )

            # 아직 Threshold에 도달하지 않았다.
            if len(window) < threshold_count:
                continue

            # ------------------------------------------------
            # Cooldown
            # ------------------------------------------------

            if last_alert_time is not None:

                elapsed = (
                    timestamp
                    - last_alert_time
                )

                if elapsed < timedelta(
                    seconds=cooldown_seconds
                ):
                    continue

            # ------------------------------------------------
            # DETECTED
            # ------------------------------------------------

            group_values = {
                field: value
                for field, value
                in zip(
                    group_by,
                    group_key,
                )
            }

            detection = {
                "rule_id": rule["id"],
                "rule_name": rule["name"],
                "severity": rule.get(
                    "severity",
                    "medium",
                ),

                "group": group_values,

                "event_count": len(window),

                "threshold": threshold_count,

                "time_window_seconds": (
                    window_seconds
                ),

                "window_start": (
                    window[0][0].isoformat()
                ),

                "window_end": (
                    timestamp.isoformat()
                ),

                # Alert 저장 단계에서 사용할 정보
                "alert": rule.get(
                    "alert",
                    {},
                ),

                # MITRE ATT&CK 정보
                "mitre": rule.get(
                    "mitre",
                    {},
                ),
            }

            detections.append(detection)

            last_alert_time = timestamp

    return detections


def detect_events(
    events: list[dict[str, Any]],
    rules: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """
    여러 Rule을 모든 정규화 이벤트에 적용한다.
    """

    detections: list[dict[str, Any]] = []

    for rule in rules:

        if not rule.get(
            "enabled",
            True,
        ):
            continue

        rule_detections = detect_rule(
            events,
            rule,
        )

        detections.extend(
            rule_detections
        )

    return detections


def fetch_normalized_events(
    client: Elasticsearch,
    *,
    index_name: str = "normalized-events",
    max_events: int = 10000,
) -> list[dict[str, Any]]:
    """
    Elasticsearch normalized-events에서
    정규화 이벤트를 가져온다.

    TEST / MVP:
    현재는 최대 10,000건을 메모리에 가져온다.

    TODO:
    실제 운영 단계에서는:
    - search_after
    - checkpoint
    - Elasticsearch aggregation
    - streaming 처리
    등을 이용하도록 변경한다.
    """

    response = client.search(
        index=index_name,
        size=max_events,

        query={
            "match_all": {},
        },

        sort=[
            {
                "@timestamp": {
                    "order": "asc",
                }
            }
        ],
    )

    events: list[dict[str, Any]] = []

    for hit in response["hits"]["hits"]:

        source = hit["_source"]

        # Elasticsearch 문서 ID도 나중에
        # Alert 증거 추적에 사용할 수 있도록 보존한다.
        source["_cloud_soc_meta"] = {
            "document_id": hit["_id"],
        }

        events.append(source)

    return events


def run_detection_from_elasticsearch(
    client: Elasticsearch,
    *,
    index_name: str = "normalized-events",
) -> list[dict[str, Any]]:
    """
    normalized-events를 가져와서
    활성화된 Detection Rule을 실행한다.
    """

    rules = load_rules()

    events = fetch_normalized_events(
        client,
        index_name=index_name,
    )

    return detect_events(
        events,
        rules,
    )


# ============================================================
# TEST
#
# 실제 공격 없이 Detection Engine 자체가
# Threshold / Time Window를 제대로 계산하는지 확인한다.
#
# 동일 IP에서 20초 간격으로 10번 실패 이벤트 생성.
#
# 총 시간:
# 0초 ~ 180초
#
# 5분(300초) 안에 10회이므로 AUTH-001이 탐지되어야 한다.
#
# TODO:
# 추후 tests/test_detection_engine.py로 이동한다.
# ============================================================

if __name__ == "__main__":

    rules = load_rules()

    base_time = datetime(
        2026,
        9,
        3,
        1,
        0,
        0,
        tzinfo=timezone.utc,
    )

    test_events: list[dict[str, Any]] = []

    for number in range(10):

        event_time = (
            base_time
            + timedelta(
                seconds=number * 20
            )
        )

        test_events.append(
            {
                "@timestamp": (
                    event_time.isoformat()
                ),

                "event": {
                    "category": [
                        "authentication"
                    ],
                    "outcome": "failure",
                },

                "network": {
                    "protocol": "ssh",
                },

                "source": {
                    "ip": "203.0.113.10",
                },

                "user": {
                    "name": "test-user",
                },
            }
        )

    results = detect_events(
        test_events,
        rules,
    )

    print("=" * 60)
    print("Detection Engine 테스트")
    print("=" * 60)

    if not results:
        print("탐지 결과 없음")
        print("TEST 실패")

    else:

        for result in results:
            print()
            print("🚨 탐지 성공")
            print(
                "Rule:",
                result["rule_id"],
                result["rule_name"],
            )

            print(
                "Severity:",
                result["severity"],
            )

            print(
                "Group:",
                result["group"],
            )

            print(
                "Event Count:",
                result["event_count"],
            )

            print(
                "Window:",
                result["window_start"],
                "~",
                result["window_end"],
            )