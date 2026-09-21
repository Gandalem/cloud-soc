from datetime import datetime, timedelta, timezone, tzinfo
from typing import Any


# ============================================================
# ECS 버전
# ============================================================

# 현재 프로젝트가 기준으로 삼는 Elastic Common Schema 버전.
#
# TODO:
# Elastic Stack을 업그레이드할 경우 ECS 버전도 함께 검토한다.
ECS_VERSION = "9.5.0"


def parse_syslog_timestamp(
    timestamp_raw: str,
    *,
    reference_time: datetime | None = None,
    source_timezone: tzinfo = timezone.utc,
) -> datetime:
    """
    auth.log의 Syslog 시간을 ISO 8601 datetime으로 변환한다.

    예:
        Sep  3 01:45:46

    ↓

        2026-09-03T01:45:46+00:00

    기본 Syslog 시간에는 연도와 timezone 정보가 없기 때문에
    reference_time의 연도를 이용해서 보완한다.
    """

    if reference_time is None or reference_time.utcoffset() is None:
        raise ValueError("A stable, timezone-aware reference_time is required")
    local_reference = reference_time.astimezone(source_timezone)
    # English syslog months must not depend on the Windows process locale.
    months = "Jan Feb Mar Apr May Jun Jul Aug Sep Oct Nov Dec".split()
    month, day, clock = timestamp_raw.split()
    month_number = months.index(month) + 1
    hour, minute, second = (int(part) for part in clock.split(":"))
    candidates = []
    for year in (local_reference.year - 1, local_reference.year, local_reference.year + 1):
        try:
            candidate = datetime(
                year, month_number, int(day), hour, minute, second, tzinfo=source_timezone,
            )
        except ValueError:
            continue
        if candidate <= local_reference + timedelta(days=1):
            candidates.append(candidate)
    if not candidates:
        raise ValueError("Invalid syslog date near the raw reference year")
    return max(candidates)


def normalize_linux_auth_event(
    parsed_event: dict[str, Any],
    *,
    reference_time: datetime | None = None,
    source_timezone: tzinfo = timezone.utc,
    organization_id: str = "oci-dev",
) -> dict[str, Any]:
    """
    linux_auth.py Parser 결과를 ECS 형식으로 변환한다.

    Parser:
        source_ip

    ECS:
        source.ip

    Parser:
        username

    ECS:
        user.name
    """

    # --------------------------------------------------------
    # 필수 값 확인
    # --------------------------------------------------------

    required_fields = [
        "timestamp_raw",
        "host",
        "process_id",
        "event_type",
        "action",
        "outcome",
        "username",
        "source_ip",
        "source_port",
        "message",
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in parsed_event
    ]

    if missing_fields:
        raise ValueError(
            "ECS 변환에 필요한 Parser 필드가 없습니다: "
            + ", ".join(missing_fields)
        )

    if not isinstance(organization_id, str) or not organization_id.strip():
        raise ValueError("organization.id must be a non-empty string")
    port = parsed_event["source_port"]
    if type(port) is not int or not 0 <= port <= 65535:
        raise ValueError("source.port must be between 0 and 65535")

    # --------------------------------------------------------
    # timestamp 변환
    # --------------------------------------------------------

    event_time = parse_syslog_timestamp(
        parsed_event["timestamp_raw"],
        reference_time=reference_time,
        source_timezone=source_timezone,
    )

    # --------------------------------------------------------
    # ECS 이벤트 생성
    # --------------------------------------------------------

    ecs_event: dict[str, Any] = {
        # ECS에서 @timestamp는 이벤트가 실제 발생한 시간이다.
        "@timestamp": event_time.astimezone(timezone.utc).isoformat(),

        # ECS 버전
        "ecs": {
            "version": ECS_VERSION,
        },

        # 이벤트 분류 정보
        "event": {
            "kind": "event",

            # SSH 로그인/인증 관련 이벤트
            "category": [
                "authentication",
            ],

            # 인증 결과를 나타내는 단일 로그이므로 info 사용
            "type": [
                "info",
            ],

            "action": parsed_event["action"],
            "outcome": parsed_event["outcome"],

            # 어떤 종류의 데이터인지 식별
            "module": "linux",
            "dataset": "linux.auth",

            # Syslog 원본에 timezone 정보가 없기 때문에 표시한다.
            "timezone": _timezone_to_string(source_timezone),

            # 원본 로그 보존
            "original": parsed_event["message"],
        },

        # 이벤트가 발생한 서버
        "host": {
            "name": parsed_event["host"],
        },

        # 로그를 만든 프로세스
        "process": {
            "name": "sshd",
            "pid": parsed_event["process_id"],
        },

        # SSH 서비스 정보
        "service": {
            "name": "sshd",
            "type": "ssh",
        },

        # 접속을 시도한 원격 시스템
        "source": {
            "ip": parsed_event["source_ip"],
            "port": parsed_event["source_port"],
        },

        # 로그인 대상 사용자
        "user": {
            "name": parsed_event["username"],
        },

        # 네트워크 프로토콜
        "network": {
            "transport": "tcp",
            "protocol": "ssh",
        },

        # 회사/환경 구분
        "organization": {
            # CONFIG:
            # 현재 개발 환경에서는 oci-dev 사용.
            #
            # TODO:
            # 추후 회사별 config.yml에서 읽도록 변경한다.
            "id": organization_id,
        },

        # Kibana에서 사람이 보기 위한 메시지
        "message": parsed_event["message"],

        # IP 검색/상관분석을 쉽게 하기 위한 ECS related 필드
        "related": {
            "ip": [
                parsed_event["source_ip"],
            ],
        },
    }

    # --------------------------------------------------------
    # 실패 이유
    # --------------------------------------------------------

    reason = parsed_event.get("reason")

    if reason:
        ecs_event["event"]["reason"] = reason

    # --------------------------------------------------------
    # 인증 방식
    # --------------------------------------------------------

    auth_method = parsed_event.get("auth_method")

    if auth_method:
        # ECS에 우리가 원하는 auth_method 전용 필드가 없기 때문에
        # 프로젝트 고유 namespace에 저장한다.
        #
        # 예:
        # publickey
        # password
        ecs_event["cloud_soc"] = {
            "authentication_method": auth_method,
        }

        # TODO:
        # 추후 ECS 또는 Elastic Security와 더 잘 호환되는
        # 인증 방식 필드가 확정되면 Mapping을 재검토한다.

    return ecs_event


def _timezone_to_string(value: tzinfo) -> str:
    """
    timezone 객체를 ECS event.timezone 문자열로 변환한다.

    예:
        UTC -> +00:00
    """

    offset = value.utcoffset(None)

    if offset is None:
        return "unknown"

    total_minutes = int(offset.total_seconds() // 60)

    sign = "+" if total_minutes >= 0 else "-"
    total_minutes = abs(total_minutes)

    hours, minutes = divmod(total_minutes, 60)

    return f"{sign}{hours:02d}:{minutes:02d}"


# ============================================================
# TEST
#
# 현재는 파일을 직접 실행해서 Normalizer를 확인한다.
#
# TODO:
# 추후 tests/test_ecs_normalizer.py로 이동한다.
# ============================================================

if __name__ == "__main__":
    sample_parser_result = {
        "timestamp_raw": "Sep  3 01:50:00",
        "host": "instance-20260306-1048",
        "process_id": 292528,

        "event_type": "authentication",
        "action": "ssh_login",
        "outcome": "failure",

        "username": "ubuntu",

        "source_ip": "203.0.113.10",
        "source_port": 50000,

        "auth_method": "password",
        "reason": "invalid_password",

        "message": (
            "Sep  3 01:50:00 instance-20260306-1048 "
            "sshd[292528]: Failed password for ubuntu "
            "from 203.0.113.10 port 50000 ssh2"
        ),
    }

    normalized = normalize_linux_auth_event(
        sample_parser_result,

        # TEST:
        # 테스트 결과가 실행 날짜에 따라 바뀌지 않도록
        # 연도를 2026년으로 고정한다.
        reference_time=datetime(
            2026,
            9,
            3,
            2,
            0,
            0,
            tzinfo=timezone.utc,
        ),

        # CONFIG:
        # 현재 OCI Ubuntu 서버가 UTC 시간 기준이므로 UTC 사용.
        #
        # TODO:
        # 서버 timezone을 자동 확인하거나 config에서 읽도록 변경한다.
        source_timezone=timezone.utc,

        organization_id="oci-dev",
    )

    from pprint import pprint

    pprint(normalized)
