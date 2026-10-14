"""Code-owned detector registry. Rule files never import/execute arbitrary code."""
from typing import Protocol


class Detector(Protocol):
    def detect(self, events, rule, runtime): ...


class ThresholdDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.engine import _detect_threshold
        return _detect_threshold(events, rule, runtime=runtime)


class SingleDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.engine import _detect_threshold, observation_identity, parse_event_timestamp, event_fingerprint
        seen, result = set(), []
        for event in sorted(events, key=lambda e: (parse_event_timestamp(e), event_fingerprint(e))):
            identifier = observation_identity(event)
            if identifier not in seen:
                seen.add(identifier)
                result.extend(_detect_threshold([event], rule))
        return result


class SequenceDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.sequence import detect_sequence
        return detect_sequence(events, rule, runtime if runtime is not None else {})


class BehaviorDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.behavior import detect_behavior
        return detect_behavior(events, rule, runtime)


class PatternDetector:
    def detect(self, events, rule, runtime):
        from cloud_soc.detection.patterns import detect_pattern
        return detect_pattern(events, rule, runtime)


DETECTORS: dict[str, Detector] = {
    "threshold": ThresholdDetector(), "single": SingleDetector(), "sequence": SequenceDetector(),
    "ordered": BehaviorDetector(), "diversity": BehaviorDetector(),
    "cardinality": PatternDetector(),
}


def detect(events, rule, *, runtime=None):
    kind = rule.get("type", "threshold")
    if kind not in DETECTORS:
        raise ValueError("Unsupported detector type")
    return DETECTORS[kind].detect(events, rule, runtime)
