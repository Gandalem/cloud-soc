import re
from ipaddress import ip_address
from typing import Any


# ============================================================
# Ubuntu /var/log/auth.log 기본 형식
#
# 예:
# Sep  3 01:45:19 instance-20260306-1048 sshd[292528]:
# Invalid user arik from 203.0.113.10 port 7218
#
# 여기서는 로그 앞부분에서
# - 시간
# - 서버 이름
# - sshd PID
# - 실제 메시지
# 를 분리한다.
# ============================================================

SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
    r"\s+"
    r"(?P<host>\S+)"
    r"\s+"
    r"sshd\[(?P<pid>\d+)\]:"
    r"\s+"
    r"(?P<message>.+)$"
)


# ============================================================
# SSH 로그인 성공
#
# 예:
# Accepted publickey for ubuntu from 198.51.100.20 port 19432 ssh2
#
# 또는:
# Accepted password for ubuntu from 198.51.100.20 port 19432 ssh2
# ============================================================

ACCEPTED_PATTERN = re.compile(
    r"^Accepted "
    r"(?P<method>password|publickey) "
    r"for "
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip>\S+) "
    r"port "
    r"(?P<port>\d+)"
)


# ============================================================
# SSH 비밀번호 로그인 실패
#
# 정상 사용자:
# Failed password for ubuntu from 203.0.113.10 port 12345 ssh2
#
# 존재하지 않는 사용자:
# Failed password for invalid user admin from 203.0.113.10 port 12345 ssh2
# ============================================================

FAILED_PASSWORD_PATTERN = re.compile(
    r"^Failed password for "
    r"(?:(?P<invalid_user>invalid user) )?"
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip>\S+) "
    r"port "
    r"(?P<port>\d+)"
)


# ============================================================
# 존재하지 않는 사용자 로그인 시도
#
# 예:
# Invalid user arik from 203.0.113.10 port 7218
# ============================================================

INVALID_USER_PATTERN = re.compile(
    r"^Invalid user "
    r"(?P<username>\S+) "
    r"from "
    r"(?P<ip>\S+) "
    r"port "
    r"(?P<port>\d+)"
)


def is_valid_ip(value: str) -> bool:
    """
    문자열이 정상적인 IPv4 또는 IPv6 주소인지 확인한다.
    """

    try:
        ip_address(value)
        return True

    except ValueError:
        return False


def parse_linux_auth_line(line: str) -> dict[str, Any] | None:
    """
    Ubuntu /var/log/auth.log 한 줄을 분석한다.

    현재 지원:
    - SSH publickey 로그인 성공
    - SSH password 로그인 성공
    - SSH password 로그인 실패
    - 존재하지 않는 사용자 로그인 시도

    지원하지 않는 로그는 None을 반환한다.

    TODO:
    추후 아래 이벤트도 지원할 예정이다.
    - SSH 연결 종료
    - root 로그인 시도
    - PAM 인증 실패
    - sudo 이벤트
    - SSH key fingerprint 분석
    """

    # 문자열 앞뒤의 불필요한 공백/개행 제거
    line = line.strip()

    # 빈 줄이면 분석할 필요가 없다.
    if not line:
        return None

    # --------------------------------------------------------
    # 1. auth.log 공통 구조 분석
    # --------------------------------------------------------

    syslog_match = SYSLOG_PATTERN.match(line)

    # sshd 로그 형식이 아니면 무시한다.
    if not syslog_match:
        return None

    timestamp_raw = syslog_match.group("timestamp")
    host = syslog_match.group("host")
    pid = int(syslog_match.group("pid"))
    message = syslog_match.group("message")

    # --------------------------------------------------------
    # 2. SSH 로그인 성공 확인
    # --------------------------------------------------------

    match = ACCEPTED_PATTERN.match(message)

    if match:
        source_ip = match.group("ip")

        if not is_valid_ip(source_ip):
            return None

        return {
            # 아직 ECS 형식으로 변환하지 않는다.
            # 다음 단계인 ecs.py에서 ECS로 변환한다.

            "timestamp_raw": timestamp_raw,
            "host": host,
            "process_id": pid,

            "event_type": "authentication",
            "action": "ssh_login",
            "outcome": "success",

            "username": match.group("username"),

            "source_ip": source_ip,
            "source_port": int(match.group("port")),

            "auth_method": match.group("method"),

            "reason": None,

            # 원본 로그를 반드시 남겨둔다.
            "message": line,
        }

    # --------------------------------------------------------
    # 3. SSH 비밀번호 로그인 실패 확인
    # --------------------------------------------------------

    match = FAILED_PASSWORD_PATTERN.match(message)

    if match:
        source_ip = match.group("ip")

        if not is_valid_ip(source_ip):
            return None

        invalid_user = match.group("invalid_user") is not None

        return {
            "timestamp_raw": timestamp_raw,
            "host": host,
            "process_id": pid,

            "event_type": "authentication",
            "action": "ssh_login",
            "outcome": "failure",

            "username": match.group("username"),

            "source_ip": source_ip,
            "source_port": int(match.group("port")),

            "auth_method": "password",

            "reason": (
                "invalid_user"
                if invalid_user
                else "invalid_password"
            ),

            "message": line,
        }

    # --------------------------------------------------------
    # 4. 존재하지 않는 사용자 로그인 시도
    # --------------------------------------------------------

    match = INVALID_USER_PATTERN.match(message)

    if match:
        source_ip = match.group("ip")

        if not is_valid_ip(source_ip):
            return None

        return {
            "timestamp_raw": timestamp_raw,
            "host": host,
            "process_id": pid,

            "event_type": "authentication",

            # 중요:
            # Failed password와 구분하기 위해 별도 action 사용
            "action": "ssh_invalid_user",

            "outcome": "failure",

            "username": match.group("username"),

            "source_ip": source_ip,
            "source_port": int(match.group("port")),

            "auth_method": None,

            "reason": "invalid_user",

            "message": line,
        }

    # --------------------------------------------------------
    # 현재 Parser에서 처리하지 않는 sshd 로그
    # --------------------------------------------------------

    return None


# ============================================================
# TEST:
# linux_auth.py 파일을 직접 실행했을 때만 동작한다.
#
# TODO:
# 추후 tests/test_linux_auth_parser.py로 테스트를 이동할 예정이다.
# ============================================================

if __name__ == "__main__":
    test_logs = [
        (
            "Sep  3 01:45:46 server01 sshd[1001]: "
            "Accepted publickey for ubuntu from "
            "198.51.100.20 port 19432 ssh2"
        ),
        (
            "Sep  3 01:50:00 server01 sshd[1002]: "
            "Failed password for ubuntu from "
            "203.0.113.10 port 50000 ssh2"
        ),
        (
            "Sep  3 01:51:00 server01 sshd[1003]: "
            "Failed password for invalid user admin from "
            "203.0.113.11 port 50001 ssh2"
        ),
        (
            "Sep  3 01:52:00 server01 sshd[1004]: "
            "Invalid user arik from "
            "203.0.113.12 port 50002"
        ),
    ]

    for log in test_logs:
        result = parse_linux_auth_line(log)

        print("=" * 60)
        print("원본 로그:")
        print(log)

        print()
        print("Parser 결과:")
        print(result)