"""Deterministic triage score, not a probability of compromise. No external IO."""
RISK_VERSION = "triage-v1"
BASE = {"low": 20, "medium": 45, "high": 65, "critical": 85}


def calculate_risk(detection):
    severity = detection.get("severity", "medium")
    if severity not in BASE:
        raise ValueError("Unsupported risk severity")
    count, threshold = detection["event_count"], detection["threshold"]
    if type(count) is not int or type(threshold) is not int or count < 1 or threshold < 1:
        raise ValueError("Invalid risk event counts")
    factors = [{"name": "rule_severity", "points": BASE[severity]}]
    if detection.get("rule_snapshot", {}).get("type", "threshold") == "threshold" and count >= threshold * 2:
        factors.append({"name": "frequency_above_twice_threshold", "points": 10})
    if detection.get("rule_snapshot", {}).get("type") == "sequence":
        factors.append({"name": "failure_then_success", "points": 15})
    score = min(100, sum(factor["points"] for factor in factors))
    band = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 30 else "low"
    return {"risk_score": score, "risk_level": band, "risk_version": RISK_VERSION, "risk_factors": factors}
