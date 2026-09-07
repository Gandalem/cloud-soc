from pathlib import Path
from typing import Any

import yaml


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
    "equals",
    "not_equals",
    "contains",
    "in",
    "greater_than",
}


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

    TODO:
    추후 JSON Schema 또는 별도 Rule Schema를
    도입하는 것도 검토한다.
    """

    if not isinstance(rule, dict):
        raise ValueError(
            "각 탐지 규칙은 객체 형식이어야 합니다."
        )

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
        not isinstance(threshold_count, int)
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
        not isinstance(window_seconds, int)
        or window_seconds <= 0
    ):
        raise ValueError(
            f"{rule['id']}: "
            "time_window.seconds는 "
            "1 이상의 정수여야 합니다."
        )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":
    loaded_rules = load_rules()

    print(
        f"탐지 규칙 {len(loaded_rules)}개 로드 완료"
    )

    for loaded_rule in loaded_rules:
        print()
        print("Rule ID:", loaded_rule["id"])
        print("이름:", loaded_rule["name"])
        print(
            "Threshold:",
            loaded_rule["threshold"]["count"],
        )
        print(
            "Time Window:",
            loaded_rule["time_window"]["seconds"],
            "초",
        )
        print(
            "Group By:",
            loaded_rule["group_by"],
        )