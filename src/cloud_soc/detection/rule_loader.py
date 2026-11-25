"""YAML detection rule loader, ReDoS guard, ConfigMap hot-reloader, and CI validator."""

import argparse
import hashlib
import logging
from pathlib import Path
import re
import signal
import sys
import threading
import time
from typing import Any

import yaml

logger = logging.getLogger(__name__)


# ============================================================
# 프로젝트 경로
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parents[3]

DEFAULT_RULE_FILE = (
    PROJECT_ROOT
    / "rules"
    / "authentication.yml"
)


# ============================================================
# Detection Engine에서 지원하는 조건 연산자
# ============================================================

SUPPORTED_OPERATORS = {
    "exists",
    "equals",
    "not_equals",
    "contains",
    "in",
    "greater_than",
}

# ReDoS(중첩 수량자·과도한 백트래킹) 정적 탐지 패턴
_NESTED_QUANTIFIER_RE = re.compile(
    r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\s*\d+\s*,)"
)
_OVERLAPPING_WILD_QUANTIFIER_RE = re.compile(
    r"\((?:[^()\\]|\\.)*(?:\.\*|\.\+)(?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\s*\d+\s*,)"
)
_REDOS_PROBES = (
    "a" * 32 + "!",
    "0" * 32 + "!",
    "/" * 32 + "!",
    " " * 32 + "!",
)


def validate_regex_safety(
    pattern: str,
    *,
    max_length: int = 512,
    max_ms: float = 25.0,
) -> None:
    """정규식 문법 오류 및 ReDoS(치명적 백트래킹) 위험을 사전 검증합니다."""
    if not isinstance(pattern, str) or not pattern:
        raise ValueError("정규식 패턴은 비어 있지 않은 문자열이어야 합니다.")
    if len(pattern) > max_length:
        raise ValueError(f"정규식 길이가 허용 상한({max_length}자)을 초과했습니다.")

    if _NESTED_QUANTIFIER_RE.search(pattern) or _OVERLAPPING_WILD_QUANTIFIER_RE.search(pattern):
        raise ValueError(f"ReDoS 위험(중첩 수량자)이 감지된 정규식입니다: {pattern}")

    try:
        compiled = re.compile(pattern)
    except re.error as exc:
        raise ValueError(f"잘못된 정규표현식 문법입니다: {exc}") from None

    for probe in _REDOS_PROBES:
        started = time.perf_counter()
        compiled.search(probe)
        elapsed_ms = (time.perf_counter() - started) * 1000.0
        if elapsed_ms > max_ms:
            raise ValueError(
                f"ReDoS 위험(매칭 지연 {elapsed_ms:.1f}ms > {max_ms:.1f}ms)이 감지된 정규식입니다: {pattern}"
            )


def _iter_explicit_regex_patterns(obj: Any):
    """룰 내부에 명시된 정규식 패턴(regex: 접두사 또는 regex/regexes 키)을 추출합니다."""
    if isinstance(obj, dict):
        for key, value in obj.items():
            if key == "regex" and isinstance(value, str):
                yield value
            elif key == "regexes" and isinstance(value, list):
                for item in value:
                    if isinstance(item, str):
                        yield item
            else:
                yield from _iter_explicit_regex_patterns(value)
    elif isinstance(obj, list):
        for item in obj:
            yield from _iter_explicit_regex_patterns(item)
    elif isinstance(obj, str) and obj.startswith("regex:"):
        yield obj.removeprefix("regex:")


def load_rules(
    rule_path: str | Path | None = None,
    *,
    enabled_only: bool = True,
) -> list[dict[str, Any]]:
    """
    YAML 탐지 규칙 파일을 읽어서 Python List로 반환한다.

    기본 파일:
        rules/authentication.yml

    enabled_only=True이면
    enabled: false 규칙은 제외한다.
    """

    if rule_path is None:
        path = DEFAULT_RULE_FILE
    else:
        path = Path(rule_path)

    # --------------------------------------------------------
    # 파일 존재 확인
    # --------------------------------------------------------

    if not path.exists():
        raise FileNotFoundError(
            f"탐지 규칙 파일을 찾을 수 없습니다: {path}"
        )

    # --------------------------------------------------------
    # YAML 읽기
    # --------------------------------------------------------

    with path.open(
        "r",
        encoding="utf-8",
    ) as file:
        data = yaml.safe_load(file)

    if not isinstance(data, dict):
        raise ValueError(
            "탐지 규칙 YAML 최상위 구조는 객체여야 합니다."
        )

    rules = data.get("rules")

    if not isinstance(rules, list):
        raise ValueError(
            "탐지 규칙 파일에 rules 목록이 없습니다."
        )

    # --------------------------------------------------------
    # 각 Rule 검증
    # --------------------------------------------------------

    validated_rules: list[dict[str, Any]] = []
    rule_ids: set[str] = set()

    for rule in rules:
        validate_rule(rule)

        rule_id = rule["id"]

        # 같은 Rule ID가 두 번 존재하는 것을 방지한다.
        if rule_id in rule_ids:
            raise ValueError(
                f"중복된 탐지 규칙 ID입니다: {rule_id}"
            )

        rule_ids.add(rule_id)

        if enabled_only and not rule.get("enabled", True):
            continue

        validated_rules.append(rule)

    return validated_rules


def validate_rule(
    rule: dict[str, Any],
) -> None:
    """
    탐지 규칙에 필수 값이 있는지 검사한다.

    TEST:
    잘못 작성된 YAML을 Detection Engine이
    조용히 무시하지 않고 즉시 알려주기 위한 검사다.
    """

    if not isinstance(rule, dict):
        raise ValueError(
            "각 탐지 규칙은 객체 형식이어야 합니다."
        )

    kind = rule.get("type", "threshold")
    if kind not in ("single", "threshold", "sequence", "ordered", "diversity", "cardinality"):
        raise ValueError("Unsupported rule type")
    if kind in ("ordered", "diversity") and any(
        not isinstance(rule.get(key), dict) for key in ("threshold", "time_window")
    ):
        raise ValueError("Behavior bounds must be objects")
    if kind in ("ordered", "diversity") and not isinstance(rule.get("cooldown", {}), dict):
        raise ValueError("Behavior cooldown must be an object")
    if kind == "single":
        rule.setdefault("group_by", ["organization.id", "cloud.account.id"])
        rule.setdefault("threshold", {"count": 1})
        rule.setdefault("time_window", {"seconds": 1})
        rule.setdefault("cooldown", {"seconds": 0})
        if rule["threshold"] != {"count": 1} or rule["cooldown"] != {"seconds": 0}:
            raise ValueError("Single event rules cannot aggregate or suppress independent events")
    if "success_window" in rule:
        success = rule["success_window"]
        if (
            kind != "sequence"
            or not isinstance(success, dict)
            or set(success) != {"seconds"}
            or type(success["seconds"]) is not int
            or not 1 <= success["seconds"] <= 86400
        ):
            raise ValueError("success_window requires bounded sequence seconds")
    if kind == "sequence" and "success_window" not in rule and rule.get("cooldown", {"seconds": 0}) != {"seconds": 0}:
        raise ValueError("Failure-success sequences reset on successful authentication; cooldown must be zero")

    required_fields = [
        "id",
        "name",
        "conditions",
        "group_by",
        "threshold",
        "time_window",
    ]

    missing_fields = [
        field
        for field in required_fields
        if field not in rule
    ]

    if missing_fields:
        raise ValueError(
            "탐지 규칙에 필수 항목이 없습니다: "
            + ", ".join(missing_fields)
        )

    # --------------------------------------------------------
    # conditions 확인
    # --------------------------------------------------------

    conditions = rule["conditions"]

    if not isinstance(conditions, list) or not conditions:
        raise ValueError(
            f"{rule['id']}: conditions가 비어 있습니다."
        )

    for condition in conditions:
        if not isinstance(condition, dict):
            raise ValueError(
                f"{rule['id']}: 잘못된 condition 형식입니다."
            )

        for field in [
            "field",
            "operator",
            "value",
        ]:
            if field not in condition:
                raise ValueError(
                    f"{rule['id']}: "
                    f"condition에 {field}가 없습니다."
                )

        operator = condition["operator"]

        if operator not in SUPPORTED_OPERATORS:
            raise ValueError(
                f"{rule['id']}: "
                f"지원하지 않는 operator입니다: {operator}"
            )
        if operator == "exists" and type(condition["value"]) is not bool:
            raise ValueError("exists requires a boolean value")

    # --------------------------------------------------------
    # group_by 확인
    # --------------------------------------------------------

    group_by = rule["group_by"]

    if not isinstance(group_by, list) or not group_by:
        raise ValueError(
            f"{rule['id']}: group_by가 비어 있습니다."
        )

    # --------------------------------------------------------
    # Threshold 확인
    # --------------------------------------------------------

    threshold_count = (
        rule
        .get("threshold", {})
        .get("count")
    )

    if (
        type(threshold_count) is not int
        or threshold_count <= 0
    ):
        raise ValueError(
            f"{rule['id']}: "
            "threshold.count는 1 이상의 정수여야 합니다."
        )

    # --------------------------------------------------------
    # Time Window 확인
    # --------------------------------------------------------

    window_seconds = (
        rule
        .get("time_window", {})
        .get("seconds")
    )

    if (
        type(window_seconds) is not int
        or window_seconds <= 0
    ):
        raise ValueError(
            f"{rule['id']}: "
            "time_window.seconds는 "
            "1 이상의 정수여야 합니다."
        )

    cooldown = rule.get("cooldown", {"seconds": 0})
    if (
        not isinstance(cooldown, dict)
        or type(cooldown.get("seconds")) is not int
        or not 0 <= cooldown["seconds"] <= 86400
        or any(not isinstance(field, str) or not field.strip() for field in group_by)
        or type(rule.get("enabled", True)) is not bool
        or rule.get("severity", "medium") not in ("low", "medium", "high", "critical")
    ):
        raise ValueError("Invalid cooldown, scope, enabled flag or severity")

    # 명시된 정규식 패턴이 있다면 문법 및 ReDoS 안전성 검증
    for raw_regex in _iter_explicit_regex_patterns(rule):
        validate_regex_safety(raw_regex)

    if "waf_sqli" in rule or rule.get("id") == "WEB-WAF-01":
        from cloud_soc.detection.waf import validate_waf_rule
        validate_waf_rule(rule)
    if kind == "cardinality":
        from cloud_soc.detection.patterns import validate_pattern
        validate_pattern(rule)
    if kind in ("ordered", "diversity"):
        from cloud_soc.detection.behavior import validate_behavior

        def validate_conditions(conditions):
            if not isinstance(conditions, list) or not conditions:
                raise ValueError("Behavior stages require conditions")
            for condition in conditions:
                if (
                    not isinstance(condition, dict)
                    or not {"field", "operator", "value"} <= condition.keys()
                    or not isinstance(condition["field"], str)
                    or condition["operator"] not in SUPPORTED_OPERATORS
                    or condition["operator"] == "exists" and type(condition["value"]) is not bool
                ):
                    raise ValueError("Invalid behavior condition")

        validate_conditions(rule["conditions"])
        validate_behavior(rule, validate_conditions)


# ============================================================
# 디렉토리 일괄 로드 및 CI 검증
# ============================================================

def _discover_rule_files(rules_dir: str | Path) -> list[Path]:
    directory = Path(rules_dir)
    if not directory.is_dir():
        raise FileNotFoundError(f"탐지 규칙 디렉토리를 찾을 수 없습니다: {directory}")
    return sorted(
        path
        for path in directory.iterdir()
        if path.is_file() and path.suffix.lower() in (".yml", ".yaml")
    )


def load_rules_directory(
    rules_dir: str | Path,
    *,
    enabled_only: bool = True,
) -> list[dict[str, Any]]:
    """디렉토리 내 모든 YAML 룰 파일을 로드하고 파일 간 중복 ID를 차단합니다."""
    files = _discover_rule_files(rules_dir)
    if not files:
        raise FileNotFoundError(f"디렉토리 '{rules_dir}'에 YAML 탐지 규칙 파일이 없습니다.")

    combined: list[dict[str, Any]] = []
    seen_ids: set[str] = set()

    for file_path in files:
        # 비활성 룰까지 포함해 ID 중복을 먼저 검사한 뒤 enabled_only 필터 적용
        file_rules = load_rules(file_path, enabled_only=False)
        for rule in file_rules:
            rule_id = rule["id"]
            if rule_id in seen_ids:
                raise ValueError(f"[{file_path.name}] 파일 간 중복된 탐지 규칙 ID입니다: {rule_id}")
            seen_ids.add(rule_id)
            if enabled_only and not rule.get("enabled", True):
                continue
            combined.append(rule)

    return combined


def validate_rules_directory(rules_dir: str | Path) -> tuple[bool, list[str]]:
    """CI 파이프라인용: 디렉토리 내 모든 YAML 룰의 스키마, 중복 ID, ReDoS 안전성을 검증합니다."""
    errors: list[str] = []
    try:
        files = _discover_rule_files(rules_dir)
    except FileNotFoundError as exc:
        return False, [str(exc)]

    if not files:
        return False, [f"디렉토리 '{rules_dir}'에 .yml/.yaml 룰 파일이 존재하지 않습니다."]

    seen_ids: dict[str, str] = {}
    for file_path in files:
        try:
            file_rules = load_rules(file_path, enabled_only=False)
        except Exception as exc:
            errors.append(f"[{file_path.name}] {exc}")
            continue

        for rule in file_rules:
            rule_id = rule["id"]
            if rule_id in seen_ids:
                errors.append(
                    f"[{file_path.name}] 중복된 탐지 규칙 ID '{rule_id}' (기존 정의: {seen_ids[rule_id]})"
                )
            else:
                seen_ids[rule_id] = file_path.name

    return len(errors) == 0, errors


# ============================================================
# Kubernetes ConfigMap 무중단 핫리로드 (Atomic Swap + Fail-Safe)
# ============================================================

class RuleReloader:
    """ConfigMap 마운트 경로의 변경을 감지해 파드 재시작 없이 룰셋을 원자적으로 교체합니다."""

    def __init__(
        self,
        rules_dir: str | Path,
        *,
        enabled_only: bool = True,
        register_sighup: bool = False,
    ) -> None:
        self.rules_dir = Path(rules_dir)
        self.enabled_only = enabled_only
        self._lock = threading.RLock()
        self._rules: list[dict[str, Any]] = []
        self._fingerprint: str = ""
        self._force_reload = threading.Event()

        # 초기 로드는 실패 시 즉시 예외를 올려 Readiness Probe가 비정상 파드를 차단하게 함
        self._fingerprint = self._compute_fingerprint()
        self._rules = load_rules_directory(self.rules_dir, enabled_only=self.enabled_only)

        if register_sighup and hasattr(signal, "SIGHUP") and threading.current_thread() is threading.main_thread():
            signal.signal(signal.SIGHUP, self._handle_sighup)

    def _handle_sighup(self, _signum: int, _frame: Any) -> None:
        logger.info("SIGHUP 수신: 다음 검사 주기에 탐지 규칙 강제 핫리로드를 수행합니다.")
        self._force_reload.set()

    def _compute_fingerprint(self) -> str:
        """심볼릭 링크(K8s ConfigMap ..data) 교체까지 정확히 감지하기 위해 내용 SHA-256을 계산합니다."""
        digest = hashlib.sha256()
        for file_path in _discover_rule_files(self.rules_dir):
            digest.update(file_path.name.encode("utf-8"))
            digest.update(b"\0")
            digest.update(file_path.read_bytes())
            digest.update(b"\0")
        return digest.hexdigest()

    @property
    def rules(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._rules)

    @property
    def fingerprint(self) -> str:
        with self._lock:
            return self._fingerprint

    def reload_if_changed(self) -> bool:
        """
        변경이 감지되면 새 룰셋을 로드·검증한 뒤 원자적으로 교체합니다.
        새 룰셋에 오류가 있으면 기존 정상 룰셋을 유지(Fail-Safe)하고 False를 반환합니다.
        """
        forced = self._force_reload.is_set()
        try:
            current_fp = self._compute_fingerprint()
        except Exception as exc:
            logger.error("탐지 규칙 디렉토리 스캔 실패(기존 룰셋 유지): %s", exc)
            return False

        if not forced and current_fp == self._fingerprint:
            return False

        try:
            new_rules = load_rules_directory(self.rules_dir, enabled_only=self.enabled_only)
        except Exception as exc:
            # Fail-Safe: 잘못된 ConfigMap 반영 시에도 기존 정상 룰셋을 보존
            logger.error("탐지 규칙 핫리로드 검증 실패 — 기존 룰셋(%d개)을 유지합니다: %s", len(self._rules), exc)
            self._force_reload.clear()
            return False

        with self._lock:
            self._rules = new_rules
            self._fingerprint = current_fp
            self._force_reload.clear()

        logger.info("탐지 규칙 핫리로드 완료: %d개 활성화 (fp=%s)", len(new_rules), current_fp[:12])
        return True


# ============================================================
# CLI 진입점 (CI 검증 및 기본 로드 확인)
# ============================================================

def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Cloud-SOC YAML 탐지 규칙 로더 및 무결성 검증기")
    parser.add_argument(
        "--validate-dir",
        help="지정 디렉토리 내 모든 YAML 탐지 규칙을 검증합니다 (CI 게이트용).",
    )
    args = parser.parse_args(argv)

    if args.validate_dir:
        is_valid, error_list = validate_rules_directory(args.validate_dir)
        if not is_valid:
            print("탐지 규칙 검증 실패:", file=sys.stderr)
            for err in error_list:
                print(f"  - {err}", file=sys.stderr)
            return 1
        rules = load_rules_directory(args.validate_dir, enabled_only=False)
        print(f"'{args.validate_dir}' 디렉토리 내 탐지 규칙 {len(rules)}개 검증 통과")
        return 0

    loaded_rules = load_rules()
    print(f"탐지 규칙 {len(loaded_rules)}개 로드 완료")
    for loaded_rule in loaded_rules:
        print()
        print("Rule ID:", loaded_rule["id"])
        print("이름:", loaded_rule["name"])
        print("Threshold:", loaded_rule["threshold"]["count"])
        print("Time Window:", loaded_rule["time_window"]["seconds"], "초")
        print("Group By:", loaded_rule["group_by"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())